import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  ScanCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';
import { DynamoDBIssueRepository, STATUS_HISTORY_LIMIT } from './issue-repository';
import type { Issue } from './types';

const key = { id: 'RULE-001-UlVMRS0wMDE6YXJu', ruleId: 'RULE-001' };
const issue: Issue = {
  ...key,
  resourcesInvolved: [{ resourceId: 'arn:aws:s3:::sensitive-data', resourceType: 'S3Bucket' }],
  pathSummary: [
    {
      from: 'arn:aws:iam::123456789012:role/app',
      to: 'arn:aws:s3:::sensitive-data',
      edgeType: 'READS',
    },
  ],
  riskScore: 82,
  severity: 'critical',
  status: 'open',
  createdAt: '2026-09-10T00:00:00.000Z',
  updatedAt: '2026-09-10T00:00:00.000Z',
  owningTeam: 'cloud-security',
  remediationHint: 'Restrict access',
  metadata: { environment: 'prod', scoringFactors: { exposure: 20 } },
  externalRefs: [{ system: 'linear', id: 'ENG-1', emittedAt: '2026-09-10T00:00:00.000Z' }],
};

function repositoryWith(implementation: (command: unknown) => Promise<Record<string, unknown>>): {
  repository: DynamoDBIssueRepository;
  send: jest.Mock;
} {
  const send = jest.fn(implementation);
  const client = { send } as unknown as DynamoDBDocumentClient;
  return {
    repository: new DynamoDBIssueRepository({
      tableName: 'SecurityIssues',
      client,
      now: () => new Date('2026-09-10T01:00:00.000Z'),
    }),
    send,
  };
}

describe('DynamoDBIssueRepository', () => {
  it('uses every canonical resource in a collision-resistant issue ID', () => {
    const { repository } = repositoryWith(async () => ({}));
    const resources = ['arn:aws:s3:::a', 'arn:aws:s3:::b', 'arn:aws:s3:::c', 'arn:aws:s3:::d'];
    const id = repository.generateIssueId('RULE-001', resources);
    expect(id).toMatch(/^RULE-001-v2-[a-f0-9]{32}$/);
    expect(repository.generateIssueId('RULE-001', [...resources].reverse())).toBe(id);
    expect(repository.generateIssueId('RULE-001', [...resources, resources[0]])).toBe(id);
    expect(
      repository.generateIssueId('RULE-001', [...resources.slice(0, 3), 'different'])
    ).not.toBe(id);
  });

  it('uses the complete composite key for strongly consistent point reads', async () => {
    const { repository, send } = repositoryWith(async () => ({ Item: issue }));

    await expect(repository.getIssue(key)).resolves.toEqual(issue);

    const command = send.mock.calls[0][0];
    expect(command).toBeInstanceOf(GetCommand);
    expect(command.input).toEqual(
      expect.objectContaining({ TableName: 'SecurityIssues', Key: key, ConsistentRead: true })
    );
  });

  it('queries by partition key to resolve lookup-by-id to a complete key', async () => {
    const { repository, send } = repositoryWith(async () => ({ Items: [issue] }));

    await expect(repository.getIssueById(issue.id)).resolves.toEqual(issue);

    const command = send.mock.calls[0][0];
    expect(command).toBeInstanceOf(QueryCommand);
    expect(command.input).toEqual(
      expect.objectContaining({
        KeyConditionExpression: '#id = :id',
        ExpressionAttributeValues: { ':id': issue.id },
        ConsistentRead: true,
        Limit: 2,
      })
    );
  });

  it('paginates the rule index to reuse a matching legacy issue', async () => {
    const unrelated = { ...issue, resourcesInvolved: [] };
    let page = 0;
    const { repository, send } = repositoryWith(async (command) => {
      if (command instanceof GetCommand) return {};
      return page++ === 0 ? { Items: [unrelated], LastEvaluatedKey: key } : { Items: [issue] };
    });

    await expect(
      repository.getIssueByRuleAndResources('RULE-001', ['arn:aws:s3:::sensitive-data'])
    ).resolves.toEqual(issue);
    expect(send).toHaveBeenCalledTimes(3);
  });

  it('rejects duplicate rows for an ID instead of choosing an ambiguous key', async () => {
    const { repository } = repositoryWith(async () => ({
      Items: [issue, { ...issue, ruleId: 'RULE-002' }],
    }));

    await expect(repository.getIssueById(issue.id)).rejects.toThrow(
      `Issue ID is not unique: ${issue.id}`
    );
  });

  it('normalizes legacy JSON strings on read', async () => {
    const legacy = {
      ...issue,
      resourcesInvolved: JSON.stringify(issue.resourcesInvolved),
      pathSummary: JSON.stringify(issue.pathSummary),
      metadata: JSON.stringify(issue.metadata),
      externalRefs: JSON.stringify(issue.externalRefs),
    };
    const { repository } = repositoryWith(async () => ({ Item: legacy }));

    await expect(repository.getIssue(key)).resolves.toEqual(issue);
  });

  it('writes structured fields as native DocumentClient values with the complete key', async () => {
    const { repository, send } = repositoryWith(async () => ({}));

    await expect(repository.updateIssue(issue)).resolves.toBe(true);
    await expect(repository.updateExternalRefs(key, issue.externalRefs || [])).resolves.toBe(true);

    const command = send.mock.calls[0][0];
    expect(command).toBeInstanceOf(UpdateCommand);
    expect(command.input.Key).toEqual(key);
    expect(command.input.ExpressionAttributeValues).toEqual(
      expect.objectContaining({
        ':resources': issue.resourcesInvolved,
        ':pathSummary': issue.pathSummary,
        ':metadata': issue.metadata,
        ':externalRefs': issue.externalRefs,
      })
    );
    expect(send.mock.calls[1][0].input.Key).toEqual(key);
    expect(send.mock.calls[1][0].input.ExpressionAttributeValues[':externalRefs']).toEqual(
      issue.externalRefs
    );
  });

  it('creates conditionally and reports a concurrent duplicate', async () => {
    const conditional = Object.assign(new Error('duplicate'), {
      name: 'ConditionalCheckFailedException',
    });
    const { repository, send } = repositoryWith(async () => {
      throw conditional;
    });

    await expect(repository.createIssue(issue)).resolves.toBe(false);
    expect(send.mock.calls[0][0]).toBeInstanceOf(PutCommand);
  });

  it('uses full keys and pins the status it read so a lost race writes nothing', async () => {
    const { repository, send } = repositoryWith(async () => ({}));
    const change = { by: 'analyst@example.com', reason: 'accepted' };

    await expect(
      repository.suppressIssue(issue, { ...change, until: '2026-10-10T00:00:00.000Z' })
    ).resolves.toBe(true);
    await expect(repository.reopenIssue({ ...issue, status: 'suppressed' }, change)).resolves.toBe(
      true
    );
    await expect(repository.resolveIssue(issue, change)).resolves.toBe(true);

    const commands = send.mock.calls.map(([command]) => command);
    for (const command of commands) {
      expect(command).toBeInstanceOf(UpdateCommand);
      expect(command.input.Key).toEqual(key);
      expect(command.input.ConditionExpression).toBe(
        'attribute_exists(#id) AND attribute_exists(#ruleId) AND #status = :from'
      );
    }
    expect(commands.map((command) => command.input.ExpressionAttributeValues[':from'])).toEqual([
      'open',
      'suppressed',
      'open',
    ]);
  });

  it('refuses a transition from a status that does not allow it without writing', async () => {
    const { repository, send } = repositoryWith(async () => ({}));
    const change = { by: 'analyst@example.com', reason: 'accepted' };

    await expect(
      repository.suppressIssue({ ...issue, status: 'resolved' }, { ...change, until: 'x' })
    ).resolves.toBe(false);
    await expect(repository.reopenIssue(issue, change)).resolves.toBe(false);
    expect(send).not.toHaveBeenCalled();
  });

  it('records who suppressed, why, until when, and the severity at the time', async () => {
    const { repository, send } = repositoryWith(async () => ({}));

    await repository.suppressIssue(issue, {
      by: 'analyst@example.com',
      reason: 'compensating control',
      until: '2026-10-10T00:00:00.000Z',
    });

    const { input } = send.mock.calls[0][0];
    expect(input.UpdateExpression).toContain('#suppression = :suppression');
    expect(input.UpdateExpression).toContain('REMOVE #resolvedAt, #resolvedReason');
    expect(input.ExpressionAttributeValues[':suppression']).toEqual({
      by: 'analyst@example.com',
      at: '2026-09-10T01:00:00.000Z',
      reason: 'compensating control',
      until: '2026-10-10T00:00:00.000Z',
      severity: 'critical',
    });
    expect(input.ExpressionAttributeValues[':statusHistory']).toEqual([
      {
        from: 'open',
        to: 'suppressed',
        at: '2026-09-10T01:00:00.000Z',
        by: 'analyst@example.com',
        reason: 'compensating control',
      },
    ]);
  });

  it('stamps resolution time and reason and clears any suppression', async () => {
    const { repository, send } = repositoryWith(async () => ({}));

    await repository.resolveIssue(
      { ...issue, status: 'suppressed' },
      { by: 'khalifa', reason: 'No longer matched by RULE-001' }
    );

    const { input } = send.mock.calls[0][0];
    expect(input.ExpressionAttributeValues).toEqual(
      expect.objectContaining({
        ':status': 'resolved',
        ':resolvedAt': '2026-09-10T01:00:00.000Z',
        ':resolvedReason': 'No longer matched by RULE-001',
      })
    );
    expect(input.UpdateExpression).toContain('REMOVE #suppression');
  });

  it('reopening clears suppression and resolution fields', async () => {
    const { repository, send } = repositoryWith(async () => ({}));

    await repository.reopenIssue(
      { ...issue, status: 'resolved' },
      { by: 'khalifa', reason: 'Matched again by RULE-001' }
    );

    expect(send.mock.calls[0][0].input.UpdateExpression).toContain(
      'REMOVE #suppression, #resolvedAt, #resolvedReason'
    );
  });

  it('caps status history to the newest entries', async () => {
    const { repository, send } = repositoryWith(async () => ({}));
    const old = Array.from({ length: STATUS_HISTORY_LIMIT }, (_, index) => ({
      from: 'open' as const,
      to: 'resolved' as const,
      at: `2026-01-01T00:00:${String(index).padStart(2, '0')}.000Z`,
      by: 'khalifa',
      reason: `run ${index}`,
    }));

    await repository.resolveIssue(
      { ...issue, statusHistory: old },
      { by: 'khalifa', reason: 'new' }
    );

    const history = send.mock.calls[0][0].input.ExpressionAttributeValues[':statusHistory'];
    expect(history).toHaveLength(STATUS_HISTORY_LIMIT);
    expect(history[0].reason).toBe('run 1');
    expect(history[STATUS_HISTORY_LIMIT - 1].reason).toBe('new');
  });

  it('loads open and suppressed issues for a rule', async () => {
    const { repository, send } = repositoryWith(async () => ({ Items: [issue] }));

    await expect(repository.getActiveIssuesByRule('RULE-001')).resolves.toEqual([issue]);
    expect(send.mock.calls[0][0].input).toEqual(
      expect.objectContaining({
        IndexName: 'RuleIdIndex',
        FilterExpression: '#status IN (:open, :suppressed)',
      })
    );
  });

  it('filters by several rules, since the rule index takes only one', async () => {
    const { repository, send } = repositoryWith(async () => ({ Items: [issue] }));

    await repository.listIssues({ ruleIds: ['RULE-001', 'RULE-013'], status: ['open'] });

    const { input } = send.mock.calls[0][0];
    expect(send.mock.calls[0][0]).toBeInstanceOf(QueryCommand);
    expect(input.IndexName).toBe('StatusIndex');
    expect(input.FilterExpression).toContain('#ruleId IN (:ruleIdFilter0, :ruleIdFilter1)');
    expect(input.ExpressionAttributeNames['#ruleId']).toBe('ruleId');
    expect(input.ExpressionAttributeValues).toEqual(
      expect.objectContaining({ ':ruleIdFilter0': 'RULE-001', ':ruleIdFilter1': 'RULE-013' })
    );
  });

  it('counts every severity and status through the status index, projecting only severity', async () => {
    const pages: Record<
      string,
      Array<{ Items: Array<{ severity: string }>; LastEvaluatedKey?: unknown }>
    > = {
      open: [
        { Items: [{ severity: 'high' }, { severity: 'critical' }], LastEvaluatedKey: key },
        { Items: [{ severity: 'high' }] },
      ],
      suppressed: [{ Items: [{ severity: 'medium' }] }],
      resolved: [{ Items: [{ severity: 'low' }, { severity: 'unknown' }] }],
    };
    const { repository, send } = repositoryWith(async (command) => {
      const input = (command as QueryCommand).input;
      return pages[input.ExpressionAttributeValues?.[':status'] as string].shift() ?? { Items: [] };
    });

    await expect(repository.getSeverityStatusCounts()).resolves.toEqual({
      critical: { open: 1, suppressed: 0, resolved: 0 },
      high: { open: 2, suppressed: 0, resolved: 0 },
      medium: { open: 0, suppressed: 1, resolved: 0 },
      low: { open: 0, suppressed: 0, resolved: 1 },
    });
    expect(send).toHaveBeenCalledTimes(4);
    for (const [command] of send.mock.calls) {
      expect(command.input).toEqual(
        expect.objectContaining({ IndexName: 'StatusIndex', ProjectionExpression: '#severity' })
      );
    }
  });

  it('paginates internal rule queries until all open issues are loaded', async () => {
    const secondIssue = { ...issue, id: 'RULE-001-second' };
    let page = 0;
    const { repository, send } = repositoryWith(async () => {
      page++;
      return page === 1 ? { Items: [issue], LastEvaluatedKey: key } : { Items: [secondIssue] };
    });

    await expect(repository.getOpenIssuesByRule('RULE-001')).resolves.toEqual([issue, secondIssue]);
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1][0].input.ExclusiveStartKey).toEqual(key);
  });

  it('paginates open-issue stats through the status index', async () => {
    const secondIssue = { ...issue, id: 'RULE-001-second', severity: 'high' as const };
    let page = 0;
    const { repository } = repositoryWith(async () =>
      page++ === 0 ? { Items: [issue], LastEvaluatedKey: key } : { Items: [secondIssue] }
    );

    await expect(repository.getOpenIssues()).resolves.toEqual([issue, secondIssue]);
  });

  it('matches resource ARNs inside structured resources across scan pages', async () => {
    const unrelated = {
      ...issue,
      id: 'RULE-001-unrelated',
      resourcesInvolved: [{ resourceId: 'arn:aws:s3:::other', resourceType: 'S3Bucket' }],
    };
    let page = 0;
    const { repository } = repositoryWith(async () => {
      page++;
      return page === 1 ? { Items: [unrelated], LastEvaluatedKey: key } : { Items: [issue] };
    });

    await expect(
      repository.getOpenIssuesByResourceArn('arn:aws:s3:::sensitive-data')
    ).resolves.toEqual([issue]);
  });

  describe('listIssues paging', () => {
    const make = (n: number, severity: Issue['severity']): Issue => ({
      ...issue,
      id: `RULE-001-${n}`,
      severity,
      updatedAt: `2026-09-${String(30 - (n % 28)).padStart(2, '0')}T00:00:00.000Z`,
    });

    it('keeps reading past filtered-out items until the page is full', async () => {
      // Each read returns one match among many non-matches, like a severity
      // filter over a mostly-high table.
      let read = 0;
      const { repository, send } = repositoryWith(async () => {
        read += 1;
        return {
          Items: [make(read, 'critical')],
          LastEvaluatedKey: { id: `k${read}`, ruleId: 'R' },
        };
      });

      const page = await repository.listIssues({
        severity: ['critical'],
        status: ['open'],
        limit: 3,
      });

      expect(page.items.map((i) => i.id)).toEqual(['RULE-001-1', 'RULE-001-2', 'RULE-001-3']);
      expect(send).toHaveBeenCalledTimes(3);
      expect(send.mock.calls[0][0].input).toEqual(
        expect.objectContaining({
          IndexName: 'StatusIndex',
          KeyConditionExpression: '#status = :statusKey',
          ScanIndexForward: false,
          Limit: 500,
        })
      );
      expect(send.mock.calls[0][0].input.FilterExpression).toContain('#severity IN');
      expect(send.mock.calls[0][0].input.FilterExpression).not.toContain('#status IN');
    });

    it('resumes right after the last issue returned, not the last item read', async () => {
      const items = [make(1, 'high'), make(2, 'high'), make(3, 'high')];
      const { repository, send } = repositoryWith(async () => ({ Items: items }));

      const first = await repository.listIssues({ status: ['open'], limit: 2 });
      expect(first.items).toHaveLength(2);
      expect(first.nextToken).toBeDefined();

      await repository.listIssues({ status: ['open'], limit: 2, nextToken: first.nextToken });
      expect(send.mock.calls[1][0].input.ExclusiveStartKey).toEqual({
        id: items[1].id,
        ruleId: items[1].ruleId,
        updatedAt: items[1].updatedAt,
        status: items[1].status,
      });
    });

    it('returns no token at the end and scans the table when no single status is chosen', async () => {
      const { repository, send } = repositoryWith(async () => ({ Items: [make(1, 'low')] }));

      const page = await repository.listIssues({ status: ['open', 'resolved'], limit: 50 });

      expect(page.items).toHaveLength(1);
      expect(page.nextToken).toBeUndefined();
      expect(send.mock.calls[0][0]).toBeInstanceOf(ScanCommand);
    });

    it('stops after its read budget and lets the caller continue', async () => {
      const { repository, send } = repositoryWith(async () => ({
        Items: [],
        LastEvaluatedKey: { id: 'far', ruleId: 'R' },
      }));

      const page = await repository.listIssues({ severity: ['critical'], status: ['open'] });

      expect(page.items).toEqual([]);
      expect(send).toHaveBeenCalledTimes(20);
      expect(page.nextToken).toBeDefined();
    });
  });

  describe('listIssues by createdAt', () => {
    const at = (day: number) => `2026-09-${String(day).padStart(2, '0')}T00:00:00.000Z`;
    const row = (id: string, status: Issue['status'], day: number): Issue => ({
      ...issue,
      id,
      status,
      createdAt: at(day),
    });
    const rows = [
      row('o1', 'open', 1),
      row('s2', 'suppressed', 2),
      row('r3', 'resolved', 3),
      row('o4', 'open', 4),
      row('r5', 'resolved', 5),
      row('r6', 'resolved', 6),
      row('o7', 'open', 7),
      row('s8', 'suppressed', 8),
      row('o9', 'open', 9),
    ];

    // Serves one status partition of StatusCreatedIndex, two items per read.
    function index() {
      return repositoryWith(async (command) => {
        const input = (command as QueryCommand).input;
        const status = input.ExpressionAttributeValues?.[':statusKey'];
        const sorted = rows
          .filter((r) => r.status === status)
          .sort((a, b) =>
            input.ScanIndexForward
              ? a.createdAt.localeCompare(b.createdAt)
              : b.createdAt.localeCompare(a.createdAt)
          );
        const after = input.ExclusiveStartKey?.id;
        const start = after ? sorted.findIndex((r) => r.id === after) + 1 : 0;
        const page = sorted.slice(start, start + 2);
        const last = page[page.length - 1];
        return {
          Items: page,
          LastEvaluatedKey:
            start + 2 < sorted.length
              ? { id: last.id, ruleId: last.ruleId, status: last.status, createdAt: last.createdAt }
              : undefined,
        };
      });
    }

    async function readAll(
      repository: DynamoDBIssueRepository,
      query: Parameters<DynamoDBIssueRepository['listIssues']>[0]
    ): Promise<string[]> {
      const ids: string[] = [];
      let nextToken: string | undefined;
      let pages = 0;
      do {
        const page = await repository.listIssues({ ...query, nextToken });
        ids.push(...page.items.map((i) => i.id));
        nextToken = page.nextToken;
        pages += 1;
      } while (nextToken && pages < 20);
      expect(nextToken).toBeUndefined();
      return ids;
    }

    it('merges every status newest first and keeps the order across pages', async () => {
      const { repository, send } = index();

      expect(await readAll(repository, { order: 'desc', limit: 3 })).toEqual([
        'o9',
        's8',
        'o7',
        'r6',
        'r5',
        'o4',
        'r3',
        's2',
        'o1',
      ]);
      expect(send.mock.calls[0][0].input).toEqual(
        expect.objectContaining({ IndexName: 'StatusCreatedIndex', ScanIndexForward: false })
      );
    });

    it('reads oldest first and only the chosen statuses', async () => {
      const { repository, send } = index();

      expect(
        await readAll(repository, { order: 'asc', status: ['open', 'suppressed'], limit: 2 })
      ).toEqual(['o1', 's2', 'o4', 'o7', 's8', 'o9']);
      const statuses = send.mock.calls.map(
        ([command]) => command.input.ExpressionAttributeValues[':statusKey']
      );
      expect(statuses).not.toContain('resolved');
      expect(send.mock.calls[0][0].input.ScanIndexForward).toBe(true);
    });

    it('hands back a usable cursor when a sparse filter spends the read budget', async () => {
      const { repository, send } = repositoryWith(async (command) => {
        const input = (command as QueryCommand).input;
        const status = input.ExpressionAttributeValues?.[':statusKey'];
        return {
          Items: [],
          LastEvaluatedKey: { id: 'x', ruleId: 'R', status, createdAt: at(1) },
        };
      });

      const page = await repository.listIssues({ order: 'desc', severity: ['critical'] });

      expect(page.items).toEqual([]);
      expect(send).toHaveBeenCalledTimes(20);
      const next = await repository.listIssues({
        order: 'desc',
        severity: ['critical'],
        nextToken: page.nextToken,
      });
      expect(next.nextToken).toBeDefined();
    });

    it('filters a single rule in the query instead of switching to the rule index', async () => {
      const { repository, send } = index();

      await repository.listIssues({ order: 'desc', ruleId: 'RULE-001', status: ['open'] });

      const input = send.mock.calls[0][0].input;
      expect(input.IndexName).toBe('StatusCreatedIndex');
      expect(input.FilterExpression).toBe('#ruleId IN (:ruleIdFilter0)');
      expect(input.ExpressionAttributeValues[':ruleIdFilter0']).toBe('RULE-001');
    });

    it('rejects tokens that are not a cursor this query issued', async () => {
      const { repository, send } = index();
      const first = await repository.listIssues({ order: 'desc', status: ['open'], limit: 1 });
      const decoded = JSON.parse(Buffer.from(first.nextToken!, 'base64url').toString('utf8'));
      const token = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
      send.mockClear();

      for (const nextToken of [
        'not-base64-json',
        token({ ...decoded, o: 'asc' }),
        token({ o: 'desc', c: { resolved: null } }),
        token({ o: 'desc', c: { open: { ...decoded.c.open, extra: 'x' } } }),
        token({ o: 'desc', c: { open: { ...decoded.c.open, status: 'resolved' } } }),
        token({ o: 'desc', c: { open: { ...decoded.c.open, createdAt: 1 } } }),
      ]) {
        await expect(
          repository.listIssues({ order: 'desc', status: ['open'], nextToken })
        ).rejects.toThrow('Invalid issue pagination token');
      }
      expect(send).not.toHaveBeenCalled();
    });

    it('falls back to index order on the first page until the index exists', async () => {
      const missing = Object.assign(
        new Error('The table does not have the specified index: StatusCreatedIndex'),
        { name: 'ValidationException' }
      );
      const { repository, send } = repositoryWith(async (command) => {
        if ((command as QueryCommand).input.IndexName === 'StatusCreatedIndex') throw missing;
        return { Items: [row('o1', 'open', 1)] };
      });

      const page = await repository.listIssues({ order: 'desc', status: ['open'] });

      expect(page.items.map((i) => i.id)).toEqual(['o1']);
      expect(send.mock.calls[1][0].input.IndexName).toBe('StatusIndex');
      const nextToken = Buffer.from(JSON.stringify({ o: 'desc', c: { open: null } })).toString(
        'base64url'
      );
      await expect(
        repository.listIssues({ order: 'desc', status: ['open'], nextToken })
      ).rejects.toThrow('specified index');
    });
  });
});
