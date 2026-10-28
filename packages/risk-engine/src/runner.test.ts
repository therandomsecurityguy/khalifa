import type { Issue, RiskRule, GraphVertex } from './types';

const mockRecordMany = jest.fn();
const mockIncrement = jest.fn();
const mockIntegrationEmit = jest.fn();

jest.mock('./posture-trend-store', () => ({
  PostureTrendStore: jest.fn().mockImplementation(() => ({
    record: jest.fn().mockResolvedValue(undefined),
    recordMany: mockRecordMany,
    increment: mockIncrement,
    getSeries: jest.fn().mockResolvedValue([]),
  })),
}));

jest.mock('@khalifa/integrations', () => ({
  IssueIntegrationsOrchestrator: jest.fn().mockImplementation(() => ({
    emit: mockIntegrationEmit,
    healthCheck: jest.fn().mockResolvedValue({}),
    configuredSinks: [],
  })),
}));

import Gremlin from 'gremlin';
import { RiskRuleRunner } from './runner';

describe('RiskRuleRunner stale-issue fix', () => {
  beforeEach(() => {
    mockRecordMany.mockReset().mockResolvedValue(undefined);
    mockIncrement.mockReset().mockResolvedValue(undefined);
    mockIntegrationEmit.mockReset().mockResolvedValue([]);
  });
  const rule: RiskRule = {
    id: 'RULE-001',
    name: 'Test Rule',
    description: 'test',
    severityHint: 'critical',
    riskFactors: [],
    gremlinQueryTemplate: 'g.V()',
    ownerTeam: 'cloud-security',
    enabled: true,
    autoTicketConfig: { enabled: false },
  };

  const existingIssue: Issue = {
    id: 'RULE-001-abc',
    ruleId: 'RULE-001',
    resourcesInvolved: [{ resourceId: 'arn:aws:s3:::bucket', resourceType: 'S3Bucket' }],
    pathSummary: [{ from: 'a', to: 'b', edgeType: 'CONTAINS' }],
    riskScore: 50,
    severity: 'medium',
    status: 'open',
    createdAt: '2024-01-01T00:00:00Z',
    updatedAt: '2024-01-01T00:00:00Z',
    owningTeam: 'cloud-security',
    remediationHint: 'old hint',
    metadata: { scoringFactors: {}, ruleName: 'old' },
  };

  const newPath: GraphVertex[] = [
    {
      id: 'arn:aws:s3:::bucket',
      label: 'S3Bucket',
      properties: { is_internet_exposed: true, data_classification: 'restricted', env: 'prod' },
    },
  ];

  test('refreshExistingIssue re-derives riskScore and updates fields', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    store.updateIssue = jest.fn().mockResolvedValue(true);

    await (runner as any).refreshExistingIssue(existingIssue, rule, {
      vertices: newPath,
      edges: [],
    });

    expect(store.updateIssue).toHaveBeenCalledTimes(1);
    const updated = store.updateIssue.mock.calls[0][0] as Issue;
    expect(updated.id).toBe('RULE-001-abc');
    expect(updated.createdAt).toBe('2024-01-01T00:00:00Z');
    expect(updated.owningTeam).toBe('cloud-security');
    expect(updated.status).toBe('open');
    expect(updated.updatedAt).not.toBe('2024-01-01T00:00:00Z');
    expect(updated.riskScore).not.toBe(50);
    expect(updated.severity).not.toBe('medium');
    expect(updated.metadata.lastRefreshedAt).toBeDefined();
    // Hints are re-derived, so an improved hint reaches issues opened before it.
    expect(updated.remediationHint).not.toBe('old hint');
  });

  test('caps severity at the rule maxSeverity, keeping the score', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    store.updateIssue = jest.fn().mockResolvedValue(true);
    const path = { vertices: newPath, edges: [] };

    await (runner as any).refreshExistingIssue(existingIssue, rule, path);
    await (runner as any).refreshExistingIssue(
      existingIssue,
      { ...rule, maxSeverity: 'low' },
      path
    );
    const created = (runner as any).createIssueFromMatch(
      { ...rule, maxSeverity: 'low' },
      path,
      [],
      ['arn:aws:s3:::bucket'],
      1
    ) as Issue;

    const [uncapped, capped] = store.updateIssue.mock.calls.map(([issue]: [Issue]) => issue);
    expect(uncapped.severity).not.toBe('low');
    expect(capped.severity).toBe('low');
    expect(capped.riskScore).toBe(uncapped.riskScore);
    expect(created.severity).toBe('low');
  });

  test('emitToIntegrations skips when autoTicketConfig disabled', async () => {
    const disabledRule: RiskRule = { ...rule, autoTicketConfig: { enabled: false } };
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    store.updateExternalRefs = jest.fn().mockResolvedValue(undefined);

    await (runner as any).emitToIntegrations(existingIssue, disabledRule);

    expect(store.updateExternalRefs).not.toHaveBeenCalled();
  });

  test('emitToIntegrations skips suppressed issues', async () => {
    const suppressedIssue: Issue = { ...existingIssue, status: 'suppressed' };
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    store.updateExternalRefs = jest.fn().mockResolvedValue(undefined);

    await (runner as any).emitToIntegrations(suppressedIssue, rule);

    expect(store.updateExternalRefs).not.toHaveBeenCalled();
  });

  test('runRule waits out a Neptune memory-limit storm and then continues', async () => {
    const waits: number[] = [];
    const runner = new RiskRuleRunner('localhost:8182', undefined, undefined, async (ms) => {
      waits.push(ms);
    });
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    const storm = {
      message:
        'Server error: {"code":"MemoryLimitExceededException","message":"Query cannot be completed due to memory limitations."} (500)',
      statusCode: 500,
    };
    neptune.executeQuery = jest
      .fn()
      .mockRejectedValueOnce(storm)
      .mockRejectedValueOnce(storm)
      .mockResolvedValueOnce([]);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({ issuesCreated: 0, errors: undefined })
    );
    expect(waits).toEqual([5_000, 15_000]);
    expect(neptune.executeQuery).toHaveBeenCalledTimes(3);
    warn.mockRestore();
  });

  test('runRule gives up on a non-retryable Neptune error without waiting', async () => {
    const waits: number[] = [];
    const runner = new RiskRuleRunner('localhost:8182', undefined, undefined, async (ms) => {
      waits.push(ms);
    });
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest
      .fn()
      .mockRejectedValue(
        new Error('Server error: {"code":"InternalFailureException","message":"bad step"} (500)')
      );

    const result = await runner.runRule(rule);
    expect(result.errors).toHaveLength(1);
    expect(waits).toEqual([]);
    expect(neptune.executeQuery).toHaveBeenCalledTimes(1);
  });

  test('runRule marks customer threat-intel matches and scores them', async () => {
    const { Path } = Gremlin.structure;
    const { t } = Gremlin.process;
    const element = (id: string, label: string, props: Record<string, unknown[]> = {}) =>
      new Map<unknown, unknown>([[t.id, id], [t.label, label], ...Object.entries(props)]);
    const path = new Path(
      ['anomaly', 'account'],
      [
        element('anomaly-1', 'CloudTrailAnomaly', {
          arn: ['anomaly-1'],
          anomaly_type: ['SECRET_READ_NEW_SOURCE_IP'],
          source_ip: ['203.0.113.7'],
        }),
      ]
    );
    const threatStore = {
      find: jest
        .fn()
        .mockResolvedValue([{ type: 'ip', value: '203.0.113.7', source: 's3://lists/ips.txt' }]),
    };
    const runner = new RiskRuleRunner(
      'localhost:8182',
      undefined,
      undefined,
      undefined,
      threatStore as never
    );
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest.fn().mockResolvedValue([path]);
    store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(null);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);
    let created: Issue | undefined;
    store.createIssue = jest.fn().mockImplementation(async (issue: Issue) => {
      created = issue;
      return true;
    });

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({ issuesCreated: 1, errors: undefined })
    );

    expect(threatStore.find).toHaveBeenCalledWith([{ type: 'ip', value: '203.0.113.7' }]);
    expect(created?.metadata.threatIntelMatches).toEqual([
      { type: 'ip', value: '203.0.113.7', source: 's3://lists/ips.txt' },
    ]);
    expect(created?.metadata.scoringFactors).toMatchObject({ threatIntelContribution: 10 });
  });

  test('runRule threads KEV and EPSS matches into exploitability', async () => {
    const { Path } = Gremlin.structure;
    const { t } = Gremlin.process;
    const element = (id: string, label: string, props: Record<string, unknown[]> = {}) =>
      new Map<unknown, unknown>([[t.id, id], [t.label, label], ...Object.entries(props)]);
    const path = new Path(
      ['i', 'cve'],
      [
        element('i-1', 'Ec2Instance'),
        element('cve-1', 'Vulnerability', { cve_id: ['CVE-2024-1234'] }),
      ]
    );
    const threatStore = {
      find: jest.fn().mockResolvedValue([
        { type: 'cve', value: 'CVE-2024-1234', source: 'kev.txt' },
        { type: 'epss', value: 'CVE-2024-1234', source: 'epss.csv', score: 0.9 },
      ]),
    };
    const runner = new RiskRuleRunner(
      'localhost:8182',
      undefined,
      undefined,
      undefined,
      threatStore as never
    );
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest.fn().mockResolvedValue([path]);
    store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(null);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);
    let created: Issue | undefined;
    store.createIssue = jest.fn().mockImplementation(async (issue: Issue) => {
      created = issue;
      return true;
    });

    await runner.runRule(rule);

    // EPSS 0.9 + 0.2 for known-exploited membership, clamped at 1.
    expect(created?.metadata.likelihoodFactors).toMatchObject({ exploitability: 1 });
    expect(created?.metadata.threatIntelMatches).toEqual([
      { type: 'cve', value: 'CVE-2024-1234', source: 'kev.txt' },
      { type: 'epss', value: 'CVE-2024-1234', source: 'epss.csv', score: 0.9 },
    ]);
  });

  test("runRule records the rule's ATT&CK techniques on the issue", async () => {
    const { Path } = Gremlin.structure;
    const { t } = Gremlin.process;
    const element = (id: string, label: string) =>
      new Map<unknown, unknown>([
        [t.id, id],
        [t.label, label],
      ]);
    const path = new Path(['ec2'], [element('ec2-1', 'Ec2Instance')]);
    const runner = new RiskRuleRunner('localhost:8182', undefined, undefined, undefined, {
      find: jest.fn().mockResolvedValue([]),
    } as never);
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest.fn().mockResolvedValue([path]);
    store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(null);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);
    let created: Issue | undefined;
    store.createIssue = jest.fn().mockImplementation(async (issue: Issue) => {
      created = issue;
      return true;
    });

    await runner.runRule(rule);

    expect(created?.metadata.attackTechniques).toEqual([
      expect.objectContaining({ id: 'T1190' }),
      expect.objectContaining({ id: 'T1078.004' }),
      expect.objectContaining({ id: 'T1530' }),
    ]);
  });

  test('runRule keeps running when the threat-intel store is unreadable', async () => {
    const { Path } = Gremlin.structure;
    const { t } = Gremlin.process;
    const element = (id: string, label: string) =>
      new Map<unknown, unknown>([
        [t.id, id],
        [t.label, label],
      ]);
    const path = new Path(['anomaly'], [element('anomaly-1', 'CloudTrailAnomaly')]);
    const threatStore = {
      find: jest.fn().mockRejectedValue(new Error('ResourceNotFoundException')),
    };
    const runner = new RiskRuleRunner(
      'localhost:8182',
      undefined,
      undefined,
      undefined,
      threatStore as never
    );
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest.fn().mockResolvedValue([path]);
    store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(null);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);
    let created: Issue | undefined;
    store.createIssue = jest.fn().mockImplementation(async (issue: Issue) => {
      created = issue;
      return true;
    });
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({ issuesCreated: 1, errors: undefined })
    );

    warn.mockRestore();
    expect(created?.metadata.threatIntelMatches).toBeUndefined();
    expect(created?.metadata.scoringFactors).toMatchObject({ threatIntelContribution: 0 });
  });
  test('runRule reads driver Path elements (Maps keyed by T enums, list values, edges between vertices)', async () => {
    const { Path } = Gremlin.structure;
    const { t } = Gremlin.process;
    const findingArn = 'arn:aws:securityhub:us-west-2:401311973745:finding/f9c2';
    const instanceArn = 'arn:aws:ec2:us-west-2:401311973745:instance/i-0599';
    const element = (id: string, label: string, props: Record<string, unknown[]> = {}) =>
      new Map<unknown, unknown>([[t.id, id], [t.label, label], ...Object.entries(props)]);
    const path = new Path(
      ['finding', 'target'],
      [
        element(findingArn, 'SecurityHubFinding', { arn: [findingArn], name: ['Exposed'] }),
        element('edge-1', 'DETECTS_ON'),
        element(instanceArn, 'Ec2Instance', {
          arn: [instanceArn],
          env: ['prod'],
          is_internet_exposed: [true],
        }),
      ]
    );
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest.fn().mockResolvedValue([path]);
    store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(null);
    store.createIssue = jest.fn().mockResolvedValue(true);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({ issuesCreated: 1, errors: undefined })
    );
    const issue = store.createIssue.mock.calls[0][0] as Issue;
    expect(issue.resourcesInvolved).toEqual([
      { resourceId: findingArn, resourceType: 'SecurityHubFinding', resourceName: 'Exposed' },
      { resourceId: instanceArn, resourceType: 'Ec2Instance', resourceName: undefined },
    ]);
    expect(issue.pathSummary).toEqual([
      { from: findingArn, to: instanceArn, edgeType: 'DETECTS_ON' },
    ]);
    expect(issue.metadata.environment).toBe('prod');
  });

  test('runRule reports a path whose vertex has no id as malformed instead of skipping it', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest
      .fn()
      .mockResolvedValue([{ objects: [{ label: 'EksCluster', arn: 'arn:aws:eks:::x' }] }]);

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({
        issuesCreated: 0,
        errors: ['Neptune returned a malformed risk-rule path'],
      })
    );
  });

  test('runRule reopens and refreshes a resolved issue that becomes active again', async () => {
    const resolvedIssue: Issue = { ...existingIssue, status: 'resolved' };
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest.fn().mockResolvedValue([
      {
        objects: [
          {
            id: 'neptune-generated-id',
            label: 'S3Bucket',
            arn: 'arn:aws:s3:::bucket',
            name: 'bucket',
          },
        ],
      },
    ]);
    store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(resolvedIssue);
    store.reopenIssue = jest.fn().mockResolvedValue(true);
    store.updateIssue = jest.fn().mockResolvedValue(true);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({ issuesCreated: 0, issuesResolved: 0, errors: undefined })
    );
    expect(store.getIssueByRuleAndResources).toHaveBeenCalledWith('RULE-001', [
      'arn:aws:s3:::bucket',
    ]);
    expect(store.reopenIssue).toHaveBeenCalledWith(resolvedIssue, {
      by: 'khalifa',
      reason: 'Matched again by RULE-001',
    });
    expect(store.updateIssue).toHaveBeenCalledWith(expect.objectContaining({ status: 'open' }));
  });

  test('runRule resolves inactive open and suppressed issues with a reason', async () => {
    const suppressedIssue: Issue = { ...existingIssue, id: 'RULE-001-def', status: 'suppressed' };
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest.fn().mockResolvedValue([]);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([existingIssue, suppressedIssue]);
    store.resolveIssue = jest.fn().mockResolvedValue(true);

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({ issuesCreated: 0, issuesResolved: 2, errors: undefined })
    );
    const change = { by: 'khalifa', reason: 'No longer matched by RULE-001' };
    expect(store.resolveIssue).toHaveBeenCalledWith(existingIssue, change);
    expect(store.resolveIssue).toHaveBeenCalledWith(suppressedIssue, change);
  });

  describe('a suppressed issue that still matches', () => {
    const DAY = 24 * 60 * 60 * 1000;
    const matchingPath = [
      {
        objects: [
          {
            id: 'v',
            label: 'S3Bucket',
            arn: 'arn:aws:s3:::bucket',
            env: 'prod',
            is_internet_exposed: true,
            data_classification: 'restricted',
          },
        ],
      },
    ];

    async function runWith(suppression: Issue['suppression']) {
      const runner = new RiskRuleRunner('localhost:8182');
      const store = (runner as any).issueStore;
      (runner as any).neptuneClient.executeQuery = jest.fn().mockResolvedValue(matchingPath);
      store.getIssueByRuleAndResources = jest
        .fn()
        .mockResolvedValue({ ...existingIssue, status: 'suppressed', suppression });
      store.updateIssue = jest.fn().mockResolvedValue(true);
      store.reopenIssue = jest.fn().mockResolvedValue(true);
      store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);
      await runner.runRule(rule);
      return store.reopenIssue as jest.Mock;
    }

    const active = (overrides: Partial<NonNullable<Issue['suppression']>> = {}) => ({
      by: 'analyst@example.com',
      at: new Date(Date.now() - DAY).toISOString(),
      reason: 'accepted',
      until: new Date(Date.now() + 30 * DAY).toISOString(),
      severity: 'critical' as const,
      ...overrides,
    });

    test('stays suppressed before its expiry', async () => {
      expect(await runWith(active())).not.toHaveBeenCalled();
    });

    test('reopens once its expiry passes', async () => {
      const reopen = await runWith(active({ until: new Date(Date.now() - 1).toISOString() }));
      expect(reopen).toHaveBeenCalledWith(expect.objectContaining({ status: 'suppressed' }), {
        by: 'khalifa',
        reason: 'Suppression by analyst@example.com expired',
      });
    });

    test('reopens early when its severity rises above what was accepted', async () => {
      const reopen = await runWith(active({ severity: 'low' }));
      expect(reopen).toHaveBeenCalledWith(expect.anything(), {
        by: 'khalifa',
        reason: expect.stringMatching(/^Severity rose from low to (medium|high|critical)/),
      });
    });

    test('reopens a legacy suppression with no recorded reason or expiry', async () => {
      const reopen = await runWith(undefined);
      expect(reopen).toHaveBeenCalledWith(expect.anything(), {
        by: 'khalifa',
        reason: 'Suppression had no recorded reason or expiry',
      });
    });
  });

  test('does not resolve issues when Neptune returns a malformed path', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest.fn().mockResolvedValue([{}]);
    store.resolveIssue = jest.fn();

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({ errors: ['Neptune returned a malformed risk-rule path'] })
    );
    expect(store.resolveIssue).not.toHaveBeenCalled();
  });

  test('snapshotTrends records rule series and the open total split by severity', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    store.getOpenIssuesByRule = jest.fn().mockImplementation(async (ruleId: string) => {
      if (ruleId === 'RULE-007') return [{ id: 'pub', severity: 'low' }];
      if (ruleId === 'RULE-006')
        return [
          { id: 'trust', severity: 'low' },
          { id: 'trust-2', severity: 'low' },
        ];
      if (ruleId === 'RULE-015') return [];
      return [{ id: 'other', severity: 'critical', riskScore: 90 }];
    });
    store.listIssues = jest.fn().mockResolvedValue({ items: [], totalCount: 0 });
    (runner as any).neptuneClient = { executeQuery: jest.fn().mockResolvedValue([]) };

    await (runner as any).snapshotTrends([
      { ruleId: 'RULE-001', executionTime: 1, matches: [], issuesCreated: 0, issuesResolved: 0 },
      { ruleId: 'RULE-006', executionTime: 1, matches: [], issuesCreated: 0, issuesResolved: 0 },
      { ruleId: 'RULE-007', executionTime: 1, matches: [], issuesCreated: 0, issuesResolved: 0 },
      { ruleId: 'RULE-015', executionTime: 1, matches: [], issuesCreated: 0, issuesResolved: 0 },
    ]);

    expect(mockRecordMany).toHaveBeenCalledWith([
      {
        metric: 'openIssuesBySeverity',
        value: 4,
        accountIds: [],
        sample: { bySeverity: { critical: 1, high: 0, medium: 0, low: 3 } },
      },
      { metric: 'publicBuckets', value: 1, accountIds: [] },
      { metric: 'crossAccountTrusts', value: 2, accountIds: [] },
      { metric: 'usersWithoutMfa', value: 0, accountIds: [] },
      { metric: 'openRiskScore', value: 90, accountIds: [] },
    ]);
  });

  test('snapshotTrends adds the run’s created and resolved totals to the day', async () => {
    const runner = trendRunner();

    await (runner as any).snapshotTrends([
      { ruleId: 'RULE-001', executionTime: 1, matches: [], issuesCreated: 3, issuesResolved: 1 },
      { ruleId: 'RULE-006', executionTime: 1, matches: [], issuesCreated: 2, issuesResolved: 4 },
    ]);

    expect(mockIncrement).toHaveBeenCalledTimes(2);
    expect(mockIncrement).toHaveBeenCalledWith('issuesCreated', 5);
    expect(mockIncrement).toHaveBeenCalledWith('issuesResolved', 5);
  });

  test('snapshotTrends increments by zero on a quiet run so the day still has a row', async () => {
    const runner = trendRunner();

    await (runner as any).snapshotTrends([
      { ruleId: 'RULE-001', executionTime: 1, matches: [], issuesCreated: 0, issuesResolved: 0 },
    ]);

    expect(mockIncrement).toHaveBeenCalledWith('issuesCreated', 0);
    expect(mockIncrement).toHaveBeenCalledWith('issuesResolved', 0);
  });

  // A runner whose two optional trend sources resolve empty, so the snapshot
  // tests never reach DynamoDB or Neptune.
  function trendRunner(): RiskRuleRunner {
    const runner = new RiskRuleRunner('localhost:8182');
    (runner as any).issueStore.getOpenIssuesByRule = jest.fn().mockResolvedValue([]);
    (runner as any).issueStore.listIssues = jest
      .fn()
      .mockResolvedValue({ items: [], totalCount: 0 });
    (runner as any).neptuneClient = { executeQuery: jest.fn().mockResolvedValue([]) };
    return runner;
  }

  test('snapshotTrends records MTTR and the admin-principal count when readable', async () => {
    const runner = trendRunner();
    const now = Date.now();
    (runner as any).issueStore.listIssues = jest.fn().mockResolvedValue({
      items: [
        {
          createdAt: new Date(now - 10 * 3_600_000).toISOString(),
          resolvedAt: new Date(now).toISOString(),
        },
        {
          createdAt: new Date(now - 30 * 3_600_000).toISOString(),
          resolvedAt: new Date(now).toISOString(),
        },
        { createdAt: '2026-01-01T00:00:00.000Z', resolvedAt: '2026-01-01T01:00:00.000Z' },
      ],
      totalCount: 3,
    });
    (runner as any).neptuneClient = { executeQuery: jest.fn().mockResolvedValue([3]) };

    await (runner as any).snapshotTrends([
      { ruleId: 'RULE-001', executionTime: 1, matches: [], issuesCreated: 0, issuesResolved: 0 },
    ]);

    const points = mockRecordMany.mock.calls[0][0];
    expect(points).toContainEqual({ metric: 'mttrHours', value: 20, accountIds: [] });
    expect(points).toContainEqual({ metric: 'adminPrincipals', value: 3, accountIds: [] });
  });

  test('snapshotTrends propagates persistence failures', async () => {
    const runner = trendRunner();
    mockRecordMany.mockRejectedValue(new Error('trend write failed'));

    await expect(
      (runner as any).snapshotTrends([
        {
          ruleId: rule.id,
          executionTime: 1,
          matches: [],
          issuesCreated: 0,
          issuesResolved: 0,
        },
      ])
    ).rejects.toThrow('trend write failed');
  });

  test('emitToIntegrations propagates external-reference persistence failures', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    store.updateExternalRefs = jest.fn().mockRejectedValue(new Error('reference write failed'));
    mockIntegrationEmit.mockResolvedValue([
      { system: 'linear', id: 'ENG-1', url: 'https://example.com/ENG-1' },
    ]);

    await expect(
      (runner as any).emitToIntegrations(existingIssue, {
        ...rule,
        autoTicketConfig: { enabled: true },
      })
    ).rejects.toThrow('reference write failed');
  });
});

describe('RiskRuleRunner identity blast radius', () => {
  const build = (vertices: GraphVertex[]) =>
    (new RiskRuleRunner('localhost:8182') as any).buildRiskInput(vertices);

  test('an admin IAM role in the path yields an admin identity factor', () => {
    const input = build([{ id: 'r1', label: 'IamRole', properties: { is_admin_role: true } }]);
    expect(input.identityBlastRadius).toEqual({ type: 'admin', scope: 1 });
  });

  test('the CIEM is_admin property also yields an admin factor', () => {
    const input = build([{ id: 'r1', label: 'IamRole', properties: { is_admin: true } }]);
    expect(input.identityBlastRadius).toEqual({ type: 'admin', scope: 1 });
  });

  test('cross-account trust yields a cross-account factor', () => {
    const input = build([
      { id: 'r1', label: 'IamRole', properties: { has_cross_account_trust: true } },
    ]);
    expect(input.identityBlastRadius).toEqual({ type: 'cross-account', scope: 1 });
  });

  test('a later cross-account vertex does not downgrade admin', () => {
    const input = build([
      { id: 'r1', label: 'IamRole', properties: { is_admin_role: true } },
      { id: 'r2', label: 'IamRole', properties: { has_cross_account_trust: true } },
    ]);
    expect(input.identityBlastRadius).toEqual({ type: 'admin', scope: 1 });
  });

  test('no identity properties leaves the factor absent, not zeroed', () => {
    const input = build([
      { id: 'i1', label: 'Ec2Instance', properties: { is_internet_exposed: true } },
    ]);
    expect(input.identityBlastRadius).toBeUndefined();
  });
});

describe('RiskRuleRunner one issue per problem', () => {
  const host = (n: string) => `arn:aws:ec2:us-west-2:111122223333:instance/i-${n}`;
  const finding = (n: string) => `arn:aws:securityhub:us-west-2:111122223333:finding/${n}`;
  const vertex = (id: string, label: string, props: Record<string, unknown> = {}) => ({
    id,
    label,
    properties: { arn: id, ...props },
  });
  const match = (findingId: string, hostId: string) => [
    vertex(finding(findingId), 'SecurityHubFinding'),
    { id: `e-${findingId}`, label: 'DETECTS_ON', properties: {} },
    vertex(host(hostId), 'Ec2Instance', { is_internet_exposed: true }),
  ];
  const rule: RiskRule = {
    id: 'RULE-018',
    name: 'Finding on exposed resource',
    description: 'test',
    severityHint: 'critical',
    riskFactors: [],
    gremlinQueryTemplate: 'g.V()',
    ownerTeam: 'detection-response',
    enabled: true,
    autoTicketConfig: { enabled: false },
    routeLabels: ['SecurityHubFinding'],
  };

  function runnerWith(matches: unknown[], active: Issue[] = [], existing: Issue | null = null) {
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    (runner as any).neptuneClient.executeQuery = jest.fn().mockResolvedValue(matches);
    store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(existing);
    store.createIssue = jest.fn().mockResolvedValue(true);
    store.updateIssue = jest.fn().mockResolvedValue(true);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue(active);
    store.resolveIssue = jest.fn().mockResolvedValue(true);
    return { runner, store };
  }

  beforeEach(() => mockIntegrationEmit.mockReset().mockResolvedValue([]));

  test('findings on one resource become one issue that lists them all', async () => {
    const { runner, store } = runnerWith([match('f1', 'a'), match('f2', 'a'), match('f3', 'b')]);

    await expect(runner.runRule(rule)).resolves.toEqual(
      expect.objectContaining({ issuesCreated: 2, errors: undefined })
    );
    const [onA, onB] = store.createIssue.mock.calls.map((call: [Issue]) => call[0]);
    expect(onA.id).toBe(store.generateIssueId('RULE-018', [host('a')]));
    expect(onA.resourcesInvolved.map((r: { resourceId: string }) => r.resourceId)).toEqual([
      host('a'),
      finding('f1'),
      finding('f2'),
    ]);
    expect(onA.metadata.matchCount).toBe(2);
    expect(onB.metadata.matchCount).toBe(1);
    expect(store.getIssueByRuleAndResources).toHaveBeenCalledWith('RULE-018', [host('a')]);
  });

  test('a resource keeps its issue while any finding remains, and old per-finding rows resolve', async () => {
    const grouped = { id: 'RULE-018-v2-grouped', ruleId: 'RULE-018', status: 'open' } as Issue;
    const legacy = { id: 'RULE-018-v2-perfinding', ruleId: 'RULE-018', status: 'open' } as Issue;
    const { runner, store } = runnerWith([match('f2', 'a')], [grouped, legacy], {
      ...grouped,
      resourcesInvolved: [],
      metadata: {},
    } as unknown as Issue);

    await runner.runRule(rule);

    const refreshed = store.updateIssue.mock.calls[0][0] as Issue;
    expect(refreshed.resourcesInvolved.map((r) => r.resourceId)).toEqual([
      host('a'),
      finding('f2'),
    ]);
    expect(refreshed.metadata.matchCount).toBe(1);
    expect(store.resolveIssue).toHaveBeenCalledTimes(1);
    expect(store.resolveIssue.mock.calls[0][0].id).toBe('RULE-018-v2-perfinding');
  });

  test('a rule without route labels still opens one issue per distinct path', async () => {
    const { runner, store } = runnerWith([match('f1', 'a'), match('f2', 'a')]);

    await runner.runRule({ ...rule, routeLabels: undefined });

    expect(store.createIssue).toHaveBeenCalledTimes(2);
    expect(store.createIssue.mock.calls[0][0].id).toBe(
      store.generateIssueId('RULE-018', [finding('f1'), host('a')])
    );
  });

  test('a suppressed issue reopens when a new finding joins it, not for the ones it accepted', async () => {
    const suppressed = {
      id: 'RULE-018-v2-grouped',
      ruleId: 'RULE-018',
      status: 'suppressed',
      severity: 'low',
      resourcesInvolved: [
        { resourceId: host('a'), resourceType: 'Ec2Instance' },
        { resourceId: finding('f1'), resourceType: 'SecurityHubFinding' },
      ],
      suppression: {
        by: 'analyst@example.com',
        at: '2026-10-01T00:00:00Z',
        reason: 'accepted',
        until: '2099-01-01T00:00:00Z',
        severity: 'critical',
      },
      metadata: {},
    } as unknown as Issue;

    const same = runnerWith([match('f1', 'a')], [suppressed], suppressed);
    same.store.reopenIssue = jest.fn().mockResolvedValue(true);
    await same.runner.runRule(rule);
    expect(same.store.reopenIssue).not.toHaveBeenCalled();

    const grown = runnerWith([match('f1', 'a'), match('f2', 'a')], [suppressed], suppressed);
    grown.store.reopenIssue = jest.fn().mockResolvedValue(true);
    await grown.runner.runRule(rule);
    expect(grown.store.reopenIssue).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'RULE-018-v2-grouped' }),
      expect.objectContaining({ reason: 'New SecurityHubFinding matched while suppressed' })
    );
  });

  describe('independent-detector labels', () => {
    const instanceArn = 'arn:aws:ec2:us-west-2:111122223333:instance/i-1';

    function element(id: string, label: string) {
      const { t } = Gremlin.process;
      return new Map<unknown, unknown>([
        [t.id, id],
        [t.label, label],
      ]);
    }

    async function runWithLabels(
      labelResources: string[] | undefined,
      ruleOverride: Partial<RiskRule> = {}
    ): Promise<Issue | undefined> {
      const { Path } = Gremlin.structure;
      const runner = new RiskRuleRunner('localhost:8182');
      if (labelResources) {
        (runner as any).independentFindingLabels = {
          resources: new Set(labelResources),
          complete: true,
        };
      }
      const store = (runner as any).issueStore;
      const neptune = (runner as any).neptuneClient;
      neptune.executeQuery = jest
        .fn()
        .mockResolvedValue([new Path(['i'], [element(instanceArn, 'Ec2Instance')])]);
      store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(null);
      store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);
      let created: Issue | undefined;
      store.createIssue = jest.fn().mockImplementation(async (issue: Issue) => {
        created = issue;
        return true;
      });
      const baseRule: RiskRule = {
        id: 'RULE-001',
        name: 'Independent-detector label host',
        description: 'test',
        severityHint: 'high',
        riskFactors: [],
        gremlinQueryTemplate: 'g.V()',
        ownerTeam: 'cloud-security',
        enabled: true,
        autoTicketConfig: { enabled: false },
      };
      await runner.runRule({ ...baseRule, ...ruleOverride });
      return created;
    }

    it('marks an issue corroborated when an independent detector flagged a resource', async () => {
      const created = await runWithLabels([instanceArn, 'arn:aws:s3:::other']);
      expect(created?.metadata.independentFinding).toBe(true);
    });

    it('marks an issue uncorroborated when the (complete) set misses it', async () => {
      const created = await runWithLabels(['arn:aws:s3:::other']);
      expect(created?.metadata.independentFinding).toBe(false);
    });

    it('leaves the label off without a complete label set, and for the detectors themselves', async () => {
      expect((await runWithLabels(undefined))?.metadata.independentFinding).toBeUndefined();
      expect(
        (await runWithLabels([], { id: 'RULE-018' }))?.metadata.independentFinding
      ).toBeUndefined();
    });

    it('loads the label set once per run, tolerating truncation and failures', async () => {
      const runner = new RiskRuleRunner('localhost:8182');
      const neptune = (runner as any).neptuneClient;
      neptune.executeQuery = jest.fn().mockResolvedValue(['arn:aws:s3:::a']);
      await expect((runner as any).loadIndependentFindingLabels()).resolves.toMatchObject({
        complete: true,
      });
      expect(neptune.executeQuery.mock.calls[0][0]).toContain(
        "hasLabel('SecurityHubFinding', 'GuardDutyFinding')"
      );

      neptune.executeQuery = jest.fn().mockResolvedValue(Array(5001).fill('arn:aws:s3:::a'));
      await expect((runner as any).loadIndependentFindingLabels()).resolves.toMatchObject({
        complete: false,
      });

      const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
      neptune.executeQuery = jest.fn().mockRejectedValue(new Error('denied'));
      await expect((runner as any).loadIndependentFindingLabels()).resolves.toMatchObject({
        complete: false,
      });
      warn.mockRestore();
    });
  });
});

describe('graph coverage tempering', () => {
  function element(id: string, label: string) {
    const { t } = Gremlin.process;
    return new Map<unknown, unknown>([
      [t.id, id],
      [t.label, label],
    ]);
  }

  it('grades the newest completed collection into a level', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const now = new Date('2026-10-27T12:00:00Z');
    const neptune = (runner as any).neptuneClient;

    neptune.executeQuery = jest
      .fn()
      .mockResolvedValue(['2026-10-27T11:00:00Z', '2026-10-20T00:00:00Z']);
    await expect((runner as any).loadCoverageLevel(now)).resolves.toBe('fresh');

    neptune.executeQuery = jest.fn().mockResolvedValue(['2026-10-20T00:00:00Z']);
    await expect((runner as any).loadCoverageLevel(now)).resolves.toBe('stale');

    neptune.executeQuery = jest.fn().mockResolvedValue([]);
    await expect((runner as any).loadCoverageLevel(now)).resolves.toBe('unknown');
  });

  it('stays tolerant when the coverage read fails', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    (runner as any).neptuneClient.executeQuery = jest.fn().mockRejectedValue(new Error('down'));

    await expect((runner as any).loadCoverageLevel()).resolves.toBe('unknown');
    warn.mockRestore();
  });

  it("tempers a stale run's likelihood and stamps the level on issue metadata", async () => {
    const { Path } = Gremlin.structure;
    const instanceArn = 'arn:aws:ec2:us-west-2:111122223333:instance/i-stale';
    const runner = new RiskRuleRunner('localhost:8182');
    (runner as any).coverageLevel = 'stale';
    const store = (runner as any).issueStore;
    const neptune = (runner as any).neptuneClient;
    neptune.executeQuery = jest
      .fn()
      .mockResolvedValue([new Path(['i'], [element(instanceArn, 'Ec2Instance')])]);
    store.getIssueByRuleAndResources = jest.fn().mockResolvedValue(null);
    store.getActiveIssuesByRule = jest.fn().mockResolvedValue([]);
    let created: Issue | undefined;
    store.createIssue = jest.fn().mockImplementation(async (issue: Issue) => {
      created = issue;
      return true;
    });

    await runner.runRule({
      id: 'RULE-001',
      name: 'Coverage host rule',
      description: 'test',
      severityHint: 'critical',
      riskFactors: [],
      gremlinQueryTemplate: 'g.V()',
      ownerTeam: 'cloud-security',
      enabled: true,
      autoTicketConfig: { enabled: false },
    });

    expect(created?.metadata.likelihoodFactors).toMatchObject({ coverage: 0.5 });
    expect(created?.metadata.coverageLevel).toBe('stale');
  });
});
