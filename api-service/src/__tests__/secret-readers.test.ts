import {
  countReaders,
  isBroadReader,
  prepareStatements,
  readersFor,
  secretReaders,
  type ReaderRow,
} from '../services/secret-readers';

const ARN = 'arn:aws:secretsmanager:us-west-2:111122223333:secret:prod/payments/key-Ab12Cd';
let nextStatement = 0;

function row(
  principal: string,
  statement: Partial<ReaderRow['statement']>,
  policy: Partial<ReaderRow['policy']> = {},
  label = 'IamRole',
  admin = false
): ReaderRow {
  return {
    principal: {
      id: `arn:aws:iam::111122223333:role/${principal}`,
      label,
      name: principal,
      admin,
    },
    policy: { type: 'inline', arn: '', name: `${principal}-policy`, ...policy },
    statement: {
      id: `stmt-${nextStatement++}`,
      effect: 'Allow',
      actions: JSON.stringify(['secretsmanager:GetSecretValue']),
      notActions: null,
      resources: JSON.stringify([ARN]),
      notResources: null,
      conditional: false,
      ...statement,
    },
  };
}

const read = (rows: ReaderRow[]) => secretReaders(rows, ARN, 500).readers;
const scopes = (rows: ReaderRow[]) => read(rows).map((r) => [r.name, r.grants[0].scope]);

describe('secretReaders', () => {
  it('finds readers by exact ARN, pattern and *, broadest first', () => {
    expect(
      scopes([
        row('exact', {}),
        row('pattern', { resources: JSON.stringify(['arn:aws:secretsmanager:*:*:secret:prod/*']) }),
        row('admin', { actions: JSON.stringify(['*']), resources: JSON.stringify(['*']) }),
      ])
    ).toEqual([
      ['admin', 'all'],
      ['pattern', 'pattern'],
      ['exact', 'secret'],
    ]);
  });

  it('matches actions and ARNs without regard to case, and ignores other secrets', () => {
    expect(
      read([
        row('mixed', { actions: JSON.stringify(['SecretsManager:Get*']) }),
        row('other', {
          resources: JSON.stringify(['arn:aws:secretsmanager:us-west-2:111122223333:secret:dev/*']),
        }),
        row('list-only', { actions: JSON.stringify(['secretsmanager:ListSecrets']) }),
      ]).map((r) => r.name)
    ).toEqual(['mixed']);
  });

  it('counts NotAction that does not exclude the read, and NotResource that does not name it', () => {
    const readers = read([
      row('power-user', {
        actions: null,
        notActions: JSON.stringify(['iam:*', 'organizations:*']),
        resources: JSON.stringify(['*']),
      }),
      row('no-secrets', {
        actions: null,
        notActions: JSON.stringify(['secretsmanager:*']),
        resources: JSON.stringify(['*']),
      }),
      row('all-but-dev', {
        resources: null,
        notResources: JSON.stringify(['arn:aws:secretsmanager:*:*:secret:dev/*']),
      }),
      row('all-but-prod', {
        resources: null,
        notResources: JSON.stringify(['arn:aws:secretsmanager:*:*:secret:prod/*']),
      }),
    ]);
    expect(readers.map((r) => [r.name, r.grants[0].scope, r.grants[0].notAction])).toEqual([
      ['power-user', 'all', true],
      ['all-but-dev', 'not-resource', false],
    ]);
  });

  it('drops a principal an unconditional Deny covers, and flags a conditional one', () => {
    const deny = (conditional: boolean) => ({
      effect: 'Deny',
      actions: JSON.stringify(['secretsmanager:GetSecretValue']),
      resources: JSON.stringify(['*']),
      conditional,
    });
    const readers = read([
      row('readonly', { actions: JSON.stringify(['*']), resources: JSON.stringify(['*']) }),
      row('readonly', deny(false)),
      row('maybe', {}),
      row('maybe', deny(true)),
    ]);
    expect(readers.map((r) => [r.name, r.mayBeDenied])).toEqual([['maybe', true]]);
  });

  it('names policies, keeps groups and users, and skips other labels', () => {
    const readers = read([
      row(
        'team',
        {},
        { type: 'managed', arn: 'arn:aws:iam::111122223333:policy/team/SecretsRead' },
        'IamGroup'
      ),
      row(
        'bot',
        {},
        { type: 'aws-managed', arn: 'arn:aws:iam::aws:policy/SecretsManagerReadWrite' },
        'IamUser'
      ),
      row('instance', {}, {}, 'Ec2Instance'),
    ]);
    expect(
      readers.map((r) => [r.name, r.type, r.grants[0].policyName, r.grants[0].policyKind])
    ).toEqual([
      ['bot', 'user', 'SecretsManagerReadWrite', 'aws-managed'],
      ['team', 'group', 'team/SecretsRead', 'managed'],
    ]);
  });

  it('treats unreadable stored lists as absent rather than as wildcards', () => {
    expect(read([row('broken', { actions: 'not json', resources: '{}' })])).toEqual([]);
  });

  it('caps the list and says so', () => {
    const rows = Array.from({ length: 3 }, (_, i) => row(`r${i}`, {}));
    expect(secretReaders(rows, ARN, 2)).toMatchObject({ truncated: true });
    expect(secretReaders(rows, ARN, 2).readers).toHaveLength(2);
  });

  it('ignores statements whose resources can only be other services', () => {
    expect(
      read([
        row('s3-only', {
          actions: JSON.stringify(['*']),
          resources: JSON.stringify(['arn:aws:s3:::bucket/*']),
        }),
        row('any-service', { resources: JSON.stringify(['arn:aws:*:us-west-2:111122223333:*']) }),
      ]).map((r) => r.name)
    ).toEqual(['any-service']);
  });

  it('shares one statement across every principal it is attached to', () => {
    const shared = { id: 'managed-stmt', resources: JSON.stringify(['*']) };
    expect(read([row('a', shared), row('b', shared)]).map((r) => r.name)).toEqual(['a', 'b']);
  });

  it('counts the same readers as the full list, broad ones included', () => {
    const rows = [
      row('exact', {}),
      row('admin', { actions: JSON.stringify(['*']), resources: JSON.stringify(['*']) }),
      row('power', {
        actions: null,
        notActions: JSON.stringify(['iam:*']),
        resources: JSON.stringify(['*']),
      }),
      row('denied', { resources: JSON.stringify(['*']) }),
      row('denied', { effect: 'Deny', resources: JSON.stringify(['*']) }),
      row('maybe', {}),
      row('maybe', { effect: 'Deny', conditional: true }),
    ];
    const statements = prepareStatements(rows);
    const readers = readersFor(statements, ARN);
    expect(countReaders(statements, ARN)).toEqual({
      total: readers.length,
      broad: readers.filter(isBroadReader).length,
    });
    expect(countReaders(statements, ARN)).toEqual({ total: 4, broad: 2 });
  });

  it('keeps statements with no id apart instead of merging them', () => {
    const noId = (principal: string, resources: string[]) =>
      row(principal, { id: '', resources: JSON.stringify(resources) });
    const readers = read([
      noId('reads-it', [ARN]),
      noId('reads-other', ['arn:aws:secretsmanager:us-west-2:111122223333:secret:dev/*']),
    ]);
    expect(readers.map((r) => r.name)).toEqual(['reads-it']);
  });

  it('keeps statements with the same id in different policies apart', () => {
    const readers = read([
      row(
        'reads-it',
        { id: 'AllowRead' },
        { type: 'inline', arn: 'arn:aws:iam::111122223333:role/a/inline-policy/p', name: 'p' }
      ),
      row(
        'reads-other',
        {
          id: 'AllowRead',
          resources: JSON.stringify(['arn:aws:secretsmanager:us-west-2:111122223333:secret:dev/*']),
        },
        { type: 'inline', arn: 'arn:aws:iam::111122223333:role/b/inline-policy/p', name: 'p' }
      ),
    ]);
    expect(readers.map((r) => r.name)).toEqual(['reads-it']);
  });
});
