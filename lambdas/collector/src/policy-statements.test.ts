import {
  actionGrantsSecretRead,
  deriveSecretGrantScope,
  deriveStatementSecretProperties,
  grantTarget,
  hasCrossAccountPrincipal,
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
