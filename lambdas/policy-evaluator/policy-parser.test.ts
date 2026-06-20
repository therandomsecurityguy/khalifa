import {
  parsePolicyDocument,
  parseTrustPolicyDocument,
  isActionMatched,
  isResourceMatched,
  isActionInList,
  isResourceInList,
  expandActionPattern,
} from './policy-parser';

describe('parsePolicyDocument', () => {
  it('parses a simple Allow policy', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
        },
      ],
    });

    const result = parsePolicyDocument(doc);
    expect(result.Version).toBe('2012-10-17');
    expect(result.Statement).toHaveLength(1);
    expect(result.Statement[0].effect).toBe('Allow');
    expect(result.Statement[0].actions).toEqual(['s3:GetObject']);
    expect(result.Statement[0].resources).toEqual(['arn:aws:s3:::my-bucket/*']);
  });

  it('parses a policy with multiple actions and resources', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: ['s3:GetObject', 's3:PutObject'],
          Resource: ['arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-b/*'],
        },
      ],
    });

    const result = parsePolicyDocument(doc);
    expect(result.Statement[0].actions).toEqual(['s3:GetObject', 's3:PutObject']);
    expect(result.Statement[0].resources).toEqual([
      'arn:aws:s3:::bucket-a/*',
      'arn:aws:s3:::bucket-b/*',
    ]);
  });

  it('parses a Deny statement', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Deny', Action: 'iam:*', Resource: '*' }],
    });

    const result = parsePolicyDocument(doc);
    expect(result.Statement[0].effect).toBe('Deny');
    expect(result.Statement[0].actions).toEqual(['iam:*']);
  });

  it('parses a statement with conditions', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringEquals: { 'aws:SourceVpc': 'vpc-12345' },
          },
        },
      ],
    });

    const result = parsePolicyDocument(doc);
    expect(result.Statement[0].conditions).toEqual({
      StringEquals: { 'aws:SourceVpc': ['vpc-12345'] },
    });
  });

  it('parses NotAction and NotResource', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          NotAction: 'iam:*',
          Resource: '*',
          NotResource: 'arn:aws:s3:::sensitive-bucket/*',
        },
      ],
    });

    const result = parsePolicyDocument(doc);
    expect(result.Statement[0].notActions).toEqual(['iam:*']);
    expect(result.Statement[0].notResources).toEqual(['arn:aws:s3:::sensitive-bucket/*']);
  });

  it('handles Sid', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Sid: 'MyStatement', Effect: 'Allow', Action: '*', Resource: '*' }],
    });

    const result = parsePolicyDocument(doc);
    expect(result.Statement[0].sid).toBe('MyStatement');
  });

  it('assigns default sid when missing', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
    });

    const result = parsePolicyDocument(doc);
    expect(result.Statement[0].sid).toBe('stmt-0');
  });
});

describe('parseTrustPolicyDocument', () => {
  it('parses a trust policy with AWS principal', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::111122223333:root' },
          Action: 'sts:AssumeRole',
        },
      ],
    });

    const result = parseTrustPolicyDocument(doc);
    expect(result).toHaveLength(1);
    expect(result[0].principalType).toBe('AWS');
    expect(result[0].principalValue).toBe('arn:aws:iam::111122223333:root');
  });

  it('parses a trust policy with Service principal', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'lambda.amazonaws.com' },
          Action: 'sts:AssumeRole',
        },
      ],
    });

    const result = parseTrustPolicyDocument(doc);
    expect(result).toHaveLength(1);
    expect(result[0].principalType).toBe('Service');
    expect(result[0].principalValue).toBe('lambda.amazonaws.com');
  });

  it('parses multiple principals', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            AWS: ['arn:aws:iam::111122223333:root', 'arn:aws:iam::444455556666:root'],
          },
          Action: 'sts:AssumeRole',
        },
      ],
    });

    const result = parseTrustPolicyDocument(doc);
    expect(result).toHaveLength(2);
  });

  it('skips Deny statements', () => {
    const doc = JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: { AWS: '*' },
          Action: 'sts:AssumeRole',
        },
      ],
    });

    const result = parseTrustPolicyDocument(doc);
    expect(result).toHaveLength(0);
  });
});

describe('isActionMatched', () => {
  it('matches exact action', () => {
    expect(isActionMatched('s3:GetObject', 's3:GetObject')).toBe(true);
  });

  it('matches wildcard *', () => {
    expect(isActionMatched('*', 's3:GetObject')).toBe(true);
  });

  it('matches wildcard *:*', () => {
    expect(isActionMatched('*:*', 's3:GetObject')).toBe(true);
  });

  it('matches service wildcard', () => {
    expect(isActionMatched('s3:*', 's3:GetObject')).toBe(true);
  });

  it('matches prefix wildcard', () => {
    expect(isActionMatched('s3:Get*', 's3:GetObject')).toBe(true);
  });

  it('does not match different service', () => {
    expect(isActionMatched('s3:GetObject', 'dynamodb:GetItem')).toBe(false);
  });

  it('matches case-insensitively', () => {
    expect(isActionMatched('S3:GetObject', 's3:getobject')).toBe(true);
  });
});

describe('isResourceMatched', () => {
  it('matches exact resource', () => {
    expect(isResourceMatched('arn:aws:s3:::my-bucket/key', 'arn:aws:s3:::my-bucket/key')).toBe(
      true
    );
  });

  it('matches wildcard', () => {
    expect(isResourceMatched('*', 'arn:aws:s3:::my-bucket/key')).toBe(true);
  });

  it('matches ARN wildcard', () => {
    expect(isResourceMatched('arn:aws:s3:::my-bucket/*', 'arn:aws:s3:::my-bucket/file.txt')).toBe(
      true
    );
  });

  it('does not match different resource', () => {
    expect(isResourceMatched('arn:aws:s3:::bucket-a/*', 'arn:aws:s3:::bucket-b/file')).toBe(false);
  });
});

describe('isActionInList', () => {
  it('returns true when action matches a pattern in the list', () => {
    expect(isActionInList('s3:GetObject', ['s3:*', 'dynamodb:*'])).toBe(true);
  });

  it('returns false when no pattern matches', () => {
    expect(isActionInList('kms:Decrypt', ['s3:*', 'dynamodb:*'])).toBe(false);
  });
});

describe('isResourceInList', () => {
  it('returns true when resource matches a pattern in the list', () => {
    expect(isResourceInList('arn:aws:s3:::my-bucket/key', ['arn:aws:s3:::my-bucket/*', '*'])).toBe(
      true
    );
  });
});

describe('expandActionPattern', () => {
  it('expands * to *:*', () => {
    expect(expandActionPattern('*')).toEqual(['*:*']);
  });

  it('returns exact action for non-wildcard', () => {
    expect(expandActionPattern('s3:GetObject')).toEqual(['s3:GetObject']);
  });

  it('returns wildcard pattern as-is', () => {
    expect(expandActionPattern('s3:*')).toEqual(['s3:*']);
  });
});
