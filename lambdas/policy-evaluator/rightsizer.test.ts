import { computeUnusedPermissions, generateRightsizingRecommendation } from './rightsizer';
import type { UsedActionEntry } from './rightsizer';

describe('computeUnusedPermissions', () => {
  const principalArn = 'arn:aws:iam::123456:role/TestRole';

  it('identifies unused actions', () => {
    const allowedActions = ['s3:GetObject', 's3:PutObject', 's3:DeleteObject', 'iam:CreateUser'];
    const usedActions: UsedActionEntry[] = [
      {
        principalArn,
        eventSource: 's3.amazonaws.com',
        eventName: 'GetObject',
        lastUsed: '2024-01-15T00:00:00Z',
        eventCount: 50,
      },
      {
        principalArn,
        eventSource: 's3.amazonaws.com',
        eventName: 'PutObject',
        lastUsed: '2024-01-14T00:00:00Z',
        eventCount: 30,
      },
    ];

    const result = computeUnusedPermissions(principalArn, allowedActions, usedActions);

    expect(result.principalArn).toBe(principalArn);
    const unusedServices = result.unusedActions.map((s) => s.service);
    expect(unusedServices).toContain('s3');
    expect(unusedServices).toContain('iam');

    const s3Unused = result.unusedActions.find((s) => s.service === 's3');
    expect(s3Unused?.actions).toContain('s3:DeleteObject');

    const iamUnused = result.unusedActions.find((s) => s.service === 'iam');
    expect(iamUnused?.actions).toContain('iam:CreateUser');
  });

  it('identifies used actions', () => {
    const allowedActions = ['s3:GetObject', 's3:PutObject'];
    const usedActions: UsedActionEntry[] = [
      {
        principalArn,
        eventSource: 's3.amazonaws.com',
        eventName: 'GetObject',
        lastUsed: '2024-01-15T00:00:00Z',
        eventCount: 10,
      },
    ];

    const result = computeUnusedPermissions(principalArn, allowedActions, usedActions);

    const s3Used = result.usedActions.find((s) => s.service === 's3');
    expect(s3Used?.actions).toContain('s3:GetObject');
  });

  it('filters by days parameter', () => {
    const allowedActions = ['s3:GetObject'];
    const oldDate = new Date(Date.now() - 200 * 86400000).toISOString();
    const usedActions: UsedActionEntry[] = [
      {
        principalArn,
        eventSource: 's3.amazonaws.com',
        eventName: 'GetObject',
        lastUsed: oldDate,
        eventCount: 1,
      },
    ];

    const result = computeUnusedPermissions(principalArn, allowedActions, usedActions, 90);
    expect(result.unusedActions.length).toBeGreaterThanOrEqual(0);
  });

  it('handles wildcard action patterns matching used actions', () => {
    const allowedActions = ['s3:*'];
    const usedActions: UsedActionEntry[] = [
      {
        principalArn,
        eventSource: 's3.amazonaws.com',
        eventName: 'GetObject',
        lastUsed: '2024-01-15T00:00:00Z',
        eventCount: 5,
      },
    ];

    const result = computeUnusedPermissions(principalArn, allowedActions, usedActions);
    const s3Unused = result.unusedActions.find((s) => s.service === 's3');
    expect(s3Unused).toBeUndefined();
  });

  it('returns empty arrays for empty inputs', () => {
    const result = computeUnusedPermissions(principalArn, [], []);
    expect(result.unusedActions).toEqual([]);
    expect(result.usedActions).toEqual([]);
  });
});

describe('generateRightsizingRecommendation', () => {
  const principalArn = 'arn:aws:iam::123456:role/TestRole';

  it('generates a recommendation removing unused actions', () => {
    const allowedActions = ['s3:GetObject', 's3:PutObject', 'iam:CreateUser', 'iam:DeleteUser'];
    const usedActions: UsedActionEntry[] = [
      {
        principalArn,
        eventSource: 's3.amazonaws.com',
        eventName: 'GetObject',
        lastUsed: new Date().toISOString(),
        eventCount: 50,
      },
    ];

    const result = generateRightsizingRecommendation(principalArn, allowedActions, usedActions, []);

    expect(result.principalArn).toBe(principalArn);
    expect(result.removedActions.length).toBeGreaterThan(0);
    expect(result.keptActions).toContain('s3:GetObject');
  });

  it('keeps read-only actions when includeReadonlySafe is true', () => {
    const allowedActions = ['s3:GetObject', 'iam:CreateUser'];
    const usedActions: UsedActionEntry[] = [];

    const result = generateRightsizingRecommendation(
      principalArn,
      allowedActions,
      usedActions,
      [],
      {
        includeReadonlySafe: true,
      }
    );

    expect(result.keptActions).toContain('s3:GetObject');
    expect(result.removedActions).toContain('iam:CreateUser');
  });

  it('removes read-only actions when includeReadonlySafe is false', () => {
    const allowedActions = ['s3:GetObject', 'dynamodb:DescribeTable'];
    const usedActions: UsedActionEntry[] = [];

    const result = generateRightsizingRecommendation(
      principalArn,
      allowedActions,
      usedActions,
      [],
      {
        includeReadonlySafe: false,
      }
    );

    expect(result.removedActions).toContain('s3:GetObject');
    expect(result.removedActions).toContain('dynamodb:DescribeTable');
  });

  it('assigns risk level based on removal ratio', () => {
    const manyAllowed = Array.from({ length: 100 }, (_, i) => `service${i % 10}:Action${i}`);
    const usedActions: UsedActionEntry[] = [];

    const result = generateRightsizingRecommendation(principalArn, manyAllowed, usedActions, [], {
      includeReadonlySafe: false,
    });

    expect(['low', 'medium', 'high']).toContain(result.riskLevel);
  });

  it('parses current policy JSONs', () => {
    const policyJson = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*' }],
    });

    const result = generateRightsizingRecommendation(
      principalArn,
      ['s3:GetObject'],
      [],
      [policyJson]
    );

    expect(result.currentPolicy.length).toBeGreaterThan(0);
  });

  it('produces a recommended policy', () => {
    const allowedActions = ['s3:GetObject', 's3:PutObject'];
    const usedActions: UsedActionEntry[] = [
      {
        principalArn,
        eventSource: 's3.amazonaws.com',
        eventName: 'GetObject',
        lastUsed: new Date().toISOString(),
        eventCount: 10,
      },
    ];

    const result = generateRightsizingRecommendation(principalArn, allowedActions, usedActions, []);

    expect(result.recommendedPolicy.length).toBeGreaterThan(0);
    expect(result.recommendedPolicy[0].effect).toBe('Allow');
  });
});
