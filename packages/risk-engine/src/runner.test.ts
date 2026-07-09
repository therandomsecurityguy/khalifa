import type { Issue, RiskRule, GraphVertex } from './types';

jest.mock('./posture-trend-store', () => ({
  PostureTrendStore: jest.fn().mockImplementation(() => ({
    record: jest.fn().mockResolvedValue(undefined),
    recordMany: jest.fn().mockResolvedValue(undefined),
    getSeries: jest.fn().mockResolvedValue([]),
  })),
}));

jest.mock('@khalifa/integrations', () => ({
  IssueIntegrationsOrchestrator: jest.fn().mockImplementation(() => ({
    emit: jest.fn().mockResolvedValue([]),
    healthCheck: jest.fn().mockResolvedValue({}),
    configuredSinks: [],
  })),
}));

import { RiskRuleRunner } from './runner';

describe('RiskRuleRunner stale-issue fix', () => {
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

  const resources = [{ resourceId: 'arn:aws:s3:::bucket', resourceType: 'S3Bucket' }];

  test('refreshExistingIssue re-derives riskScore and updates fields', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    store.updateIssueFields = jest.fn().mockResolvedValue(undefined);

    await (runner as any).refreshExistingIssue(existingIssue, rule, newPath, resources);

    expect(store.updateIssueFields).toHaveBeenCalledTimes(1);
    const updated = store.updateIssueFields.mock.calls[0][0] as Issue;
    expect(updated.id).toBe('RULE-001-abc');
    expect(updated.createdAt).toBe('2024-01-01T00:00:00Z');
    expect(updated.owningTeam).toBe('cloud-security');
    expect(updated.status).toBe('open');
    expect(updated.updatedAt).not.toBe('2024-01-01T00:00:00Z');
    expect(updated.riskScore).not.toBe(50);
    expect(updated.severity).not.toBe('medium');
    expect(updated.metadata.lastRefreshedAt).toBeDefined();
  });

  test('refreshExistingIssue preserves id and createdAt but updates updatedAt', async () => {
    const runner = new RiskRuleRunner('localhost:8182');
    const store = (runner as any).issueStore;
    store.updateIssueFields = jest.fn().mockResolvedValue(undefined);

    await (runner as any).refreshExistingIssue(existingIssue, rule, newPath, resources);

    const updated = store.updateIssueFields.mock.calls[0][0] as Issue;
    expect(updated.id).toBe(existingIssue.id);
    expect(updated.createdAt).toBe(existingIssue.createdAt);
    expect(updated.owningTeam).toBe(existingIssue.owningTeam);
    expect(new Date(updated.updatedAt).getTime()).toBeGreaterThan(
      new Date(existingIssue.updatedAt).getTime()
    );
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
});
