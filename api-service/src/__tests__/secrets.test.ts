import type { Request, Response } from 'express';
import type { SecretRecord } from '../services/neptune-client';

const listSecretsQuery = jest.fn();
const getSecretQuery = jest.fn();
const secretReaderRows = jest.fn();
const listSecretAccounts = jest.fn();
const getOpenIssuesByRule = jest.fn();

jest.mock('@khalifa/risk-engine', () => ({
  ...jest.requireActual('@khalifa/risk-engine'),
  DynamoDBIssueRepository: jest.fn().mockImplementation(() => ({ getOpenIssuesByRule })),
}));
jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({
    listSecrets: listSecretsQuery,
    getSecret: getSecretQuery,
    secretReaderRows,
    listSecretAccounts,
  }),
}));

import {
  getSecret,
  listSecretReaderCounts,
  listSecrets,
  secretSharing,
  toInventoryItem,
} from '../routes/secrets';
import { clearReaderCountCache } from '../services/secret-reader-counts';
import { NeptuneClient, looksLikeSecret } from '../services/neptune-client';

const SECRET = 'arn:aws:secretsmanager:us-west-2:111122223333:secret:prod/api-key-Ab12';

function record(overrides: Partial<SecretRecord> = {}): SecretRecord {
  return {
    kind: 'secrets-manager',
    id: SECRET,
    name: 'prod/api-key',
    accountId: '111122223333',
    customerManagedKey: false,
    rotationEnabled: false,
    lastRotated: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    lastAccessed: null,
    lastModified: null,
    collectionRestricted: false,
    shares: [],
    sharedAccounts: 0,
    env: null,
    owner: null,
    ...overrides,
  };
}

function response(): Response & { body?: any; statusCode?: number } {
  const res: any = {};
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return res;
}

describe('secretSharing', () => {
  it('is this account only with no cross-account statements', () => {
    expect(secretSharing([], 0)).toEqual({ scope: 'account', accounts: 0 });
  });

  it('is outside for anyone without an org limit, or an account not collected', () => {
    expect(
      secretSharing([{ anyone: true, orgRestricted: false, named: 0, collected: 0 }], 0)
    ).toEqual({ scope: 'outside', accounts: 0 });
    expect(
      secretSharing([{ anyone: false, orgRestricted: false, named: 2, collected: 1 }], 0)
    ).toEqual({ scope: 'outside', accounts: 0 });
  });

  it('is the org for anyone limited by aws:PrincipalOrgID', () => {
    expect(
      secretSharing(
        [
          { anyone: false, orgRestricted: false, named: 1, collected: 1 },
          { anyone: true, orgRestricted: true, named: 0, collected: 0 },
        ],
        0
      )
    ).toEqual({ scope: 'org', accounts: 0 });
  });

  it('counts distinct collected accounts across statements, not the largest statement', () => {
    expect(
      secretSharing(
        [
          { anyone: false, orgRestricted: false, named: 1, collected: 1 },
          { anyone: false, orgRestricted: false, named: 1, collected: 1 },
        ],
        2
      )
    ).toEqual({ scope: 'collected', accounts: 2 });
  });
});

describe('toInventoryItem', () => {
  it('returns only the allowlisted fields', () => {
    const item = toInventoryItem(record({ customerManagedKey: true }), []);
    expect(Object.keys(item).sort()).toEqual(
      [
        'accountId',
        'collectionRestricted',
        'createdAt',
        'encryption',
        'env',
        'id',
        'issues',
        'kind',
        'lastAccessed',
        'lastModified',
        'lastRotated',
        'name',
        'owner',
        'region',
        'rotationEnabled',
        'sharing',
      ].sort()
    );
    expect(item).toMatchObject({ region: 'us-west-2', encryption: 'customer-managed' });
  });

  it('claims no sharing for a secret whose policy could not be read, or a parameter', () => {
    expect(toInventoryItem(record({ collectionRestricted: true }), []).sharing).toBeNull();
    expect(toInventoryItem(record({ kind: 'ssm-parameter' }), []).sharing).toBeNull();
  });
});

describe('GET /secrets', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    listSecretsQuery.mockResolvedValue({ items: [record()], truncated: false });
    getOpenIssuesByRule.mockResolvedValue([]);
  });

  it('attaches the open issues that name each secret, once each', async () => {
    getOpenIssuesByRule.mockImplementation(async (ruleId: string) =>
      ruleId === 'RULE-010'
        ? [
            {
              id: 'issue-1',
              ruleId,
              severity: 'high',
              createdAt: '2026-10-01T00:00:00.000Z',
              metadata: { ruleName: 'Secret shared outside' },
              resourcesInvolved: [
                { resourceId: SECRET, resourceType: 'Secret' },
                { resourceId: SECRET, resourceType: 'Secret' },
              ],
            },
          ]
        : []
    );
    const res = response();
    await listSecrets({} as Request, res);
    expect(res.body.items[0].issues).toEqual([
      {
        id: 'issue-1',
        ruleId: 'RULE-010',
        severity: 'high',
        title: 'Secret shared outside',
        openedAt: '2026-10-01T00:00:00.000Z',
      },
    ]);
    expect(res.body.issuesUnavailable).toBe(false);
    expect(getOpenIssuesByRule.mock.calls.map(([ruleId]) => ruleId)).toEqual([
      'RULE-010',
      'RULE-032',
      'RULE-033',
    ]);
  });

  it('still lists secrets when issue lookups fail, and says so', async () => {
    getOpenIssuesByRule.mockRejectedValue(new Error('dynamo down'));
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    const res = response();
    await listSecrets({} as Request, res);
    expect(res.body.items).toHaveLength(1);
    expect(res.body.issuesUnavailable).toBe(true);
  });

  it('fails closed with a generic error when the graph read fails', async () => {
    listSecretsQuery.mockRejectedValue(new Error('neptune: secret detail'));
    jest.spyOn(console, 'error').mockImplementation(() => {});
    const res = response();
    await listSecrets({} as Request, res);
    expect(res.statusCode).toBe(500);
    expect(JSON.stringify(res.body)).not.toContain('secret detail');
  });
});

describe('GET /secrets/:arn', () => {
  function request(arn: string) {
    return { params: { arn } } as unknown as Request<{ arn: string }>;
  }

  beforeEach(() => {
    jest.clearAllMocks();
    getOpenIssuesByRule.mockResolvedValue([]);
  });

  it('rejects anything but a secret or parameter ARN before reading the graph', async () => {
    for (const arn of [
      'arn:aws:iam::111122223333:role/admin',
      'arn:aws:s3:::bucket',
      'g.V().drop()',
      `${SECRET}\n`,
    ]) {
      const res = response();
      await getSecret(request(arn), res);
      expect(res.statusCode).toBe(400);
    }
    expect(getSecretQuery).not.toHaveBeenCalled();
  });

  it('is not found when the graph has no such secret or parameter', async () => {
    getSecretQuery.mockResolvedValue(null);
    const res = response();
    await getSecret(request(SECRET), res);
    expect(res.statusCode).toBe(404);
  });

  it('returns the allowlisted item with titled issues, from the catalog when unnamed', async () => {
    getSecretQuery.mockResolvedValue(record());
    getOpenIssuesByRule.mockImplementation(async (ruleId: string) =>
      ruleId === 'RULE-033'
        ? [
            {
              id: 'issue-2',
              ruleId,
              severity: 'low',
              createdAt: '2026-10-02T00:00:00.000Z',
              metadata: {},
              resourcesInvolved: [{ resourceId: SECRET, resourceType: 'Secret' }],
            },
          ]
        : []
    );
    const res = response();
    await getSecret(request(SECRET), res);
    expect(getSecretQuery).toHaveBeenCalledWith(SECRET);
    expect(res.body.item.id).toBe(SECRET);
    expect(res.body.item.issues[0].title).toMatch(/Another Collected Account/);
    expect(JSON.stringify(res.body)).not.toMatch(/description|kms_key_id|document_json/);
  });

  it('lists who can read a secret, and keeps the page when that lookup fails', async () => {
    getSecretQuery.mockResolvedValue(record());
    secretReaderRows.mockResolvedValue({
      rows: [
        {
          principal: {
            id: 'arn:aws:iam::111122223333:role/app',
            label: 'IamRole',
            name: 'app',
            admin: false,
          },
          policy: { type: 'inline', arn: '', name: 'app-read' },
          statement: {
            id: 'stmt-1',
            effect: 'Allow',
            actions: JSON.stringify(['secretsmanager:GetSecretValue']),
            notActions: null,
            resources: JSON.stringify(['*']),
            notResources: null,
            conditional: false,
          },
        },
      ],
      truncated: false,
    });
    const res = response();
    await getSecret(request(SECRET), res);
    expect(secretReaderRows).toHaveBeenCalledWith('111122223333', expect.any(Number));
    expect(res.body.readers).toMatchObject({
      truncated: false,
      unavailable: false,
      items: [{ name: 'app', type: 'role', grants: [{ policyName: 'app-read', scope: 'all' }] }],
    });
    expect(JSON.stringify(res.body.readers)).not.toMatch(/GetSecretValue|resources/);

    secretReaderRows.mockRejectedValue(new Error('timeout'));
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    const failed = response();
    await getSecret(request(SECRET), failed);
    expect(failed.body.item.id).toBe(SECRET);
    expect(failed.body.readers).toEqual({ items: [], truncated: false, unavailable: true });
  });

  it('does not evaluate readers for SSM parameters', async () => {
    getSecretQuery.mockResolvedValue(record({ kind: 'ssm-parameter' }));
    const res = response();
    await getSecret(request(SECRET), res);
    expect(res.body.readers).toBeNull();
    expect(secretReaderRows).not.toHaveBeenCalled();
  });

  it('accepts an SSM parameter ARN', async () => {
    getSecretQuery.mockResolvedValue(null);
    const res = response();
    await getSecret(request('arn:aws:ssm:us-west-2:111122223333:parameter/db/password'), res);
    expect(getSecretQuery).toHaveBeenCalled();
    expect(res.statusCode).toBe(404);
  });
});

describe('GET /secrets/reader-counts', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    clearReaderCountCache();
  });

  it('returns counts only, keyed by secret ARN', async () => {
    listSecretAccounts.mockResolvedValue({
      secrets: [{ id: SECRET, accountId: '111122223333' }],
      truncated: false,
    });
    secretReaderRows.mockResolvedValue({
      rows: [
        {
          principal: {
            id: 'arn:aws:iam::111122223333:role/app',
            label: 'IamRole',
            name: 'app',
            admin: true,
          },
          policy: { type: 'inline', arn: '', name: 'app-read' },
          statement: {
            id: 's1',
            effect: 'Allow',
            actions: JSON.stringify(['*']),
            notActions: null,
            resources: JSON.stringify(['*']),
            notResources: null,
            conditional: false,
          },
        },
      ],
      truncated: false,
    });
    const res = response();
    await listSecretReaderCounts({} as Request, res);
    expect(res.body).toEqual({
      counts: { [SECRET]: { total: 1, broad: 1, partial: false } },
      unavailableAccounts: 0,
      partialAccounts: 0,
      truncated: false,
    });
    expect(JSON.stringify(res.body)).not.toMatch(/app-read|role\/app/);
  });

  it('fails with a generic error when the secret list cannot be read', async () => {
    listSecretAccounts.mockRejectedValue(new Error('neptune: internal detail'));
    jest.spyOn(console, 'error').mockImplementation(() => {});
    const res = response();
    await listSecretReaderCounts({} as Request, res);
    expect(res.statusCode).toBe(500);
    expect(JSON.stringify(res.body)).not.toContain('internal detail');
  });
});

describe('NeptuneClient.listSecrets', () => {
  function row(entries: Record<string, unknown>) {
    return new Map<unknown, unknown>(Object.entries(entries));
  }

  it('keeps a single folded share as a list and never returns the key ARN', async () => {
    const execute = jest
      .fn()
      .mockResolvedValueOnce([
        row({
          id: SECRET,
          name: 'prod/api-key',
          account: '111122223333',
          rotation: true,
          rotated: '2026-10-01T00:00:00.000Z',
          created: '2026-01-01T00:00:00.000Z',
          accessed: '2026-10-20T00:00:00.000Z',
          key: 'arn:aws:kms:us-west-2:111122223333:key/abcd',
          restricted: '',
          shares: [row({ anyone: true, org: true, named: 0, collected: 0 })],
          sharedAccounts: 2,
        }),
      ])
      .mockResolvedValueOnce([
        row({
          id: 'arn:aws:ssm:us-west-2:111122223333:parameter/db/password',
          name: '/db/password',
          account: '111122223333',
          modified: '2026-09-01T00:00:00.000Z',
          key: 'alias/aws/ssm',
          type: 'SecureString',
          env: 'prod',
          owner: 'payments',
        }),
      ])
      .mockResolvedValueOnce([
        row({
          id: 'arn:aws:ssm:us-west-2:111122223333:parameter/app/db-password',
          name: '/app/db-password',
          account: '111122223333',
          type: 'String',
        }),
        row({
          id: 'arn:aws:ssm:us-west-2:111122223333:parameter/app/log-level',
          name: '/app/log-level',
          account: '111122223333',
          type: 'String',
        }),
      ]);
    const graph = new NeptuneClient(
      { endpoint: 'cluster.example.com' },
      { runtime: { execute, close: jest.fn() } }
    );

    const { items, truncated } = await graph.listSecrets(10);
    expect(truncated).toBe(false);
    expect(items[0]).toMatchObject({
      rotationEnabled: true,
      createdAt: '2026-01-01T00:00:00.000Z',
      lastAccessed: '2026-10-20T00:00:00.000Z',
      customerManagedKey: true,
      sharedAccounts: 2,
      shares: [{ anyone: true, orgRestricted: true, named: 0, collected: 0 }],
    });
    expect(items[1]).toMatchObject({
      kind: 'ssm-parameter',
      customerManagedKey: false,
      createdAt: null,
      lastAccessed: null,
      env: 'prod',
      owner: 'payments',
    });
    expect(items.slice(2).map((item) => [item.kind, item.name])).toEqual([
      ['ssm-plaintext', '/app/db-password'],
    ]);
    expect(JSON.stringify(items)).not.toContain('key/abcd');
    expect(String(execute.mock.calls[1][0])).toContain('SecureString');
  });

  it('finds one secret only among Secret and parameter vertices', async () => {
    const execute = jest.fn().mockResolvedValue([]);
    const graph = new NeptuneClient(
      { endpoint: 'cluster.example.com' },
      { runtime: { execute, close: jest.fn() } }
    );

    await expect(graph.getSecret('arn:aws:iam::111122223333:role/admin')).resolves.toBeNull();
    expect(execute).toHaveBeenCalledTimes(2);
    expect(String(execute.mock.calls[0][0])).toContain('Secret');
    expect(String(execute.mock.calls[1][0])).toContain('Parameter');
  });

  it('returns a plain-text parameter only when its name looks like a credential', async () => {
    const param = (name: string, type: string) => [
      row({
        id: `arn:aws:ssm:us-west-2:111122223333:parameter${name}`,
        name,
        account: '111122223333',
        type,
      }),
    ];
    const graph = (rows: unknown[]) =>
      new NeptuneClient(
        { endpoint: 'cluster.example.com' },
        {
          runtime: {
            execute: jest.fn().mockResolvedValueOnce([]).mockResolvedValueOnce(rows),
            close: jest.fn(),
          },
        }
      );
    await expect(graph(param('/app/api-key', 'String')).getSecret('x')).resolves.toMatchObject({
      kind: 'ssm-plaintext',
    });
    await expect(graph(param('/app/log-level', 'String')).getSecret('x')).resolves.toBeNull();
    await expect(graph(param('/app/db', 'SecureString')).getSecret('x')).resolves.toMatchObject({
      kind: 'ssm-parameter',
    });
  });
});

describe('looksLikeSecret', () => {
  it.each([
    '/prod/db/password',
    'DB_PASSWD',
    'github-token',
    '/svc/api-key',
    'stripe_api_key',
    'tls/private_key',
    'aws-credentials',
    'oauth/client-secret',
  ])('flags %s', (name) => expect(looksLikeSecret(name)).toBe(true));

  it.each(['/app/log-level', '/feature/flags', 'region', '/db/host'])('leaves %s', (name) =>
    expect(looksLikeSecret(name)).toBe(false)
  );
});

describe('NeptuneClient.secretReaderRows', () => {
  const map = (entries: Record<string, unknown>) =>
    new Map<unknown, unknown>(Object.entries(entries));

  it('reads principals, policies and statements, and caps the rows', async () => {
    const result = map({
      principal: map({
        id: 'arn:aws:iam::111122223333:role/app',
        label: 'IamRole',
        name: 'app',
        admin: '',
        adminRole: true,
      }),
      doc: map({ type: 'aws-managed', arn: 'arn:aws:iam::aws:policy/PowerUserAccess', name: 'x' }),
      statement: map({
        id: 'stmt-1',
        effect: 'Allow',
        actions: '',
        notActions: '["iam:*"]',
        resources: '["*"]',
        notResources: '',
        conditions: '{"Bool":{}}',
      }),
    });
    const execute = jest.fn().mockResolvedValue([result, result]);
    const graph = new NeptuneClient(
      { endpoint: 'cluster.example.com' },
      { runtime: { execute, close: jest.fn() } }
    );

    const { rows, truncated } = await graph.secretReaderRows('111122223333', 1);
    expect(truncated).toBe(true);
    expect(rows).toEqual([
      {
        principal: {
          id: 'arn:aws:iam::111122223333:role/app',
          label: 'IamRole',
          name: 'app',
          admin: true,
        },
        policy: { type: 'aws-managed', arn: 'arn:aws:iam::aws:policy/PowerUserAccess', name: 'x' },
        statement: {
          id: 'stmt-1',
          effect: 'Allow',
          actions: null,
          notActions: '["iam:*"]',
          resources: '["*"]',
          notResources: null,
          conditional: true,
        },
      },
    ]);
    expect(String(execute.mock.calls[0][0])).toContain('111122223333');
  });
});
