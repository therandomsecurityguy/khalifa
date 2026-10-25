import {
  actionGrantsSecretRead,
  deriveSecretGrantScope,
  deriveStatementPrincipalProperties,
  deriveStatementSecretProperties,
  grantTarget,
  hasCrossAccountPrincipal,
  isOrgRestricted,
  isWildcardSecretResource,
  statementGrantsSecretRead,
} from './policy-statements';
import { addStatementNodeAndEdges } from '../index';
import type { GraphEdge, GraphNode } from '../../shared/types';

describe('actionGrantsSecretRead', () => {
  it.each([
    ['*', true],
    ['*:*', true],
    ['secretsmanager:GetSecretValue', true],
    ['secretsmanager:getsecretvalue', true],
    ['secretsmanager:ListSecrets', false],
    ['secretsmanager:List*', false],
    ['secretsmanager:BatchGetSecretValue', true],
    ['secretsmanager:get*', true],
    ['secretsmanager:*', true],
    ['secretsmanager:*', true],
    ['secretsmanager:PutSecretValue', false],
    ['secretsmanager:DescribeSecret', false],
    ['s3:GetObject', false],
    ['s3:*', false],
    ['GetSecretValue', false],
  ])('%s -> %s', (action, expected) => {
    expect(actionGrantsSecretRead(action as string)).toBe(expected);
  });
});

describe('statementGrantsSecretRead', () => {
  it('matches string, array, and wildcard forms', () => {
    expect(statementGrantsSecretRead('secretsmanager:GetSecretValue')).toBe(true);
    expect(statementGrantsSecretRead(['s3:GetObject', 'secretsmanager:GetSecretValue'])).toBe(true);
    expect(statementGrantsSecretRead(['secretsmanager:ListSecrets'])).toBe(false);
    expect(statementGrantsSecretRead('*')).toBe(true);
    expect(statementGrantsSecretRead(['s3:GetObject'])).toBe(false);
    expect(statementGrantsSecretRead(undefined)).toBe(false);
  });
});

describe('isWildcardSecretResource', () => {
  it('treats * and secretsmanager ARNs containing wildcards as broad', () => {
    expect(isWildcardSecretResource('*')).toBe(true);
    expect(isWildcardSecretResource('arn:aws:secretsmanager:us-east-1:123:secret:*')).toBe(true);
    expect(isWildcardSecretResource('arn:aws:secretsmanager:*:*:secret:*')).toBe(true);
    expect(isWildcardSecretResource('arn:aws:secretsmanager:us-east-1:123:secret:prod-*')).toBe(
      true
    );
  });

  it('rejects scoped ARNs and other services', () => {
    expect(
      isWildcardSecretResource('arn:aws:secretsmanager:us-east-1:123:secret:prod/db-AbCdEf')
    ).toBe(false);
    expect(isWildcardSecretResource('arn:aws:s3:::my-bucket/*')).toBe(false);
    expect(isWildcardSecretResource('arn:aws:iam::123:role/foo')).toBe(false);
  });
});

describe('hasCrossAccountPrincipal', () => {
  const accountId = '111122223333';

  it('flags wildcard and foreign-account principals', () => {
    expect(hasCrossAccountPrincipal({ Principal: '*' }, accountId)).toBe(true);
    expect(
      hasCrossAccountPrincipal({ Principal: { AWS: 'arn:aws:iam::999999999999:root' } }, accountId)
    ).toBe(true);
    expect(
      hasCrossAccountPrincipal(
        {
          Principal: { AWS: ['arn:aws:iam::111122223333:root', 'arn:aws:iam::999999999999:root'] },
        },
        accountId
      )
    ).toBe(true);
  });

  it('flags a bare foreign account ID', () => {
    expect(hasCrossAccountPrincipal({ Principal: { AWS: '999999999999' } }, accountId)).toBe(true);
  });

  it('does not flag same-account or service principals', () => {
    expect(
      hasCrossAccountPrincipal({ Principal: { AWS: 'arn:aws:iam::111122223333:root' } }, accountId)
    ).toBe(false);
    expect(
      hasCrossAccountPrincipal({ Principal: { Service: 'rds.amazonaws.com' } }, accountId)
    ).toBe(false);
  });

  it('returns false for identity-policy statements without a Principal', () => {
    expect(hasCrossAccountPrincipal({ Effect: 'Allow' }, accountId)).toBe(false);
    expect(hasCrossAccountPrincipal({}, accountId)).toBe(false);
    expect(hasCrossAccountPrincipal(undefined, accountId)).toBe(false);
  });
});

describe('deriveSecretGrantScope', () => {
  it('classifies wildcard resources, scoped ARNs, NotResource, and empty statements', () => {
    expect(deriveSecretGrantScope({ Resource: '*' })).toBe('wildcard');
    expect(
      deriveSecretGrantScope({ Resource: ['arn:aws:secretsmanager:us-east-1:1:secret:*'] })
    ).toBe('wildcard');
    expect(
      deriveSecretGrantScope({ Resource: ['arn:aws:secretsmanager:us-east-1:1:secret:db-AbCdEf'] })
    ).toBe('scoped');
    expect(deriveSecretGrantScope({ NotResource: 'arn:aws:iam::1:role/x' })).toBe('not_resource');
    expect(deriveSecretGrantScope({})).toBe('none');
  });
});

describe('deriveStatementSecretProperties', () => {
  const accountId = '111122223333';

  it('marks Allow GetSecretValue on * as the wildcard exfiltration pattern', () => {
    const props = deriveStatementSecretProperties(
      {
        Effect: 'Allow',
        Action: ['secretsmanager:GetSecretValue', 'secretsmanager:ListSecrets'],
        Resource: '*',
      },
      accountId
    );
    expect(props).toEqual({
      grants_secret_read: true,
      secret_grant_scope: 'wildcard',
      has_cross_account_principal: false,
    });
  });

  it('marks cross-account resource-policy grants with scoped ARNs', () => {
    const props = deriveStatementSecretProperties(
      {
        Effect: 'Allow',
        Action: ['secretsmanager:GetSecretValue'],
        Resource: 'arn:aws:secretsmanager:us-east-1:111122223333:secret:db-AbCdEf',
        Principal: { AWS: 'arn:aws:iam::999999999999:root' },
      },
      accountId
    );
    expect(props).toEqual({
      grants_secret_read: true,
      secret_grant_scope: 'scoped',
      has_cross_account_principal: true,
    });
  });

  it('does not flag Deny statements or unrelated actions', () => {
    const deny = deriveStatementSecretProperties(
      { Effect: 'Deny', Action: ['secretsmanager:GetSecretValue'], Resource: '*' },
      accountId
    );
    expect(deny.grants_secret_read).toBe(false);

    const unrelated = deriveStatementSecretProperties(
      { Effect: 'Allow', Action: ['s3:GetObject'], Resource: '*' },
      accountId
    );
    expect(unrelated.grants_secret_read).toBe(false);
    expect(unrelated.secret_grant_scope).toBe('wildcard');
  });
});

describe('grantTarget', () => {
  it.each([
    ['arn:aws:s3:::payments-exports/*', 'arn:aws:s3:::payments-exports'],
    ['arn:aws:s3:::payments-exports/reports/2026/*', 'arn:aws:s3:::payments-exports'],
    ['arn:aws:s3:::payments-exports/key.csv', 'arn:aws:s3:::payments-exports'],
    ['arn:aws-us-gov:s3:::gov-bucket/*', 'arn:aws-us-gov:s3:::gov-bucket'],
    ['arn:aws:s3:::payments-exports', 'arn:aws:s3:::payments-exports'],
    // A wildcard bucket name is not one bucket; it stays unmatched.
    ['arn:aws:s3:::logs-*/*', 'arn:aws:s3:::logs-*/*'],
    [
      'arn:aws:dynamodb:us-west-2:111122223333:table/orders',
      'arn:aws:dynamodb:us-west-2:111122223333:table/orders',
    ],
  ])('%s -> %s', (resource, target) => {
    expect(grantTarget(resource)).toBe(target);
  });

  it('writes one GRANTS edge to the bucket for bucket and bucket/* resources', () => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    addStatementNodeAndEdges(
      nodes,
      edges,
      'arn:aws:iam::111122223333:policy/read-exports',
      JSON.stringify({
        Statement: {
          Effect: 'Allow',
          Action: ['s3:ListBucket', 's3:GetObject'],
          Resource: ['arn:aws:s3:::payments-exports', 'arn:aws:s3:::payments-exports/*', '*'],
        },
      }),
      '111122223333'
    );
    expect(edges.filter((edge) => edge.label === 'GRANTS').map((edge) => edge.to)).toEqual([
      'arn:aws:s3:::payments-exports',
    ]);
  });
});

describe('deriveStatementPrincipalProperties', () => {
  const accountId = '111122223333';

  it('lists the other accounts a statement names, once each', () => {
    expect(
      deriveStatementPrincipalProperties(
        {
          Principal: {
            AWS: [
              'arn:aws:iam::999999999999:role/reader',
              '999999999999',
              'arn:aws:iam::444455556666:root',
              'arn:aws:iam::111122223333:role/own',
            ],
          },
        },
        accountId
      )
    ).toEqual({
      principal_is_anyone: false,
      principal_org_restricted: false,
      principal_account_ids: ['444455556666', '999999999999'],
      principal_account_count: 2,
    });
  });

  it('marks anyone, and anyone limited to an organization', () => {
    const orgOnly = {
      Principal: '*',
      Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-2pydbopsis' } },
    };
    expect(deriveStatementPrincipalProperties(orgOnly, accountId)).toMatchObject({
      principal_is_anyone: true,
      principal_org_restricted: true,
      principal_account_count: 0,
    });
    expect(
      deriveStatementPrincipalProperties({ Principal: { AWS: '*' } }, accountId)
    ).toMatchObject({ principal_is_anyone: true, principal_org_restricted: false });
  });

  it('adds nothing to identity policy statements', () => {
    expect(deriveStatementPrincipalProperties({ Effect: 'Allow' }, accountId)).toEqual({});
  });
});

describe('isOrgRestricted', () => {
  const condition = (operator: string, key: string, value: unknown) => ({
    Condition: { [operator]: { [key]: value } },
  });

  it.each([
    ['StringEquals', 'aws:PrincipalOrgID', 'o-2pydbopsis'],
    ['StringEquals', 'aws:PrincipalOrgID', ['o-2pydbopsis']],
    ['StringLike', 'AWS:PrincipalOrgID', 'o-2pydbopsis'],
    ['ForAnyValue:StringLike', 'aws:PrincipalOrgPaths', 'o-2pydbopsis/r-ab12/ou-ab12-11111111/*'],
  ])('accepts %s %s %j', (operator, key, value) => {
    expect(isOrgRestricted(condition(operator, key, value))).toBe(true);
  });

  it.each([
    // Passes for a principal in no organization, or any organization.
    ['StringEqualsIfExists', 'aws:PrincipalOrgID', 'o-2pydbopsis'],
    ['StringNotEquals', 'aws:PrincipalOrgID', 'o-2pydbopsis'],
    ['ForAllValues:StringLike', 'aws:PrincipalOrgPaths', 'o-2pydbopsis/*'],
    ['StringLike', 'aws:PrincipalOrgID', 'o-*'],
    ['StringLike', 'aws:PrincipalOrgID', '*'],
    ['StringEquals', 'aws:PrincipalOrgID', []],
    // Not an organization limit.
    ['StringEquals', 'aws:SourceAccount', '999999999999'],
  ])('rejects %s %s %j', (operator, key, value) => {
    expect(isOrgRestricted(condition(operator, key, value))).toBe(false);
  });

  it('rejects a statement without conditions', () => {
    expect(isOrgRestricted({ Principal: '*' })).toBe(false);
  });
});

describe('SHARES_WITH edges', () => {
  it('link an Allow statement to each other account it names', () => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const policy =
      'arn:aws:secretsmanager:us-west-2:111122223333:secret:app-AbCdEf/resource-policy';
    addStatementNodeAndEdges(
      nodes,
      edges,
      policy,
      JSON.stringify({
        Statement: [
          {
            Sid: 'Share',
            Effect: 'Allow',
            Principal: { AWS: ['arn:aws:iam::999999999999:root', '444455556666'] },
            Action: 'secretsmanager:GetSecretValue',
            Resource: '*',
          },
          {
            Sid: 'Block',
            Effect: 'Deny',
            Principal: { AWS: 'arn:aws:iam::777777777777:root' },
            Action: 'secretsmanager:*',
            Resource: '*',
          },
        ],
      }),
      '111122223333'
    );

    expect(edges.filter((edge) => edge.label === 'SHARES_WITH')).toEqual([
      {
        from: `${policy}/statement/Share`,
        to: 'arn:aws:iam::444455556666:root',
        label: 'SHARES_WITH',
      },
      {
        from: `${policy}/statement/Share`,
        to: 'arn:aws:iam::999999999999:root',
        label: 'SHARES_WITH',
      },
    ]);
    expect(nodes.find((node) => node.id === `${policy}/statement/Share`)?.properties).toMatchObject(
      { principal_account_ids: ['444455556666', '999999999999'], principal_account_count: 2 }
    );
  });
});
