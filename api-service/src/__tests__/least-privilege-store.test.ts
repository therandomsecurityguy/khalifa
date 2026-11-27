import {
  mapFindingRecord,
  parseLeastPrivilegeToken,
  parseRecommendedPolicy,
} from '../services/least-privilege-store';

describe('parseRecommendedPolicy', () => {
  it('parses a valid policy JSON string', () => {
    const json = JSON.stringify([
      { sid: 'RightsizedAllow', effect: 'Allow', actions: ['s3:GetObject'], resources: ['*'] },
    ]);
    const result = parseRecommendedPolicy(json);
    expect(result).toHaveLength(1);
    expect(result[0].effect).toBe('Allow');
    expect(result[0].actions).toContain('s3:GetObject');
  });

  it('returns empty array for undefined', () => {
    expect(parseRecommendedPolicy(undefined)).toEqual([]);
  });

  it('returns empty array for invalid JSON', () => {
    expect(parseRecommendedPolicy('not-json')).toEqual([]);
  });
});

describe('mapFindingRecord', () => {
  it('maps a full record to a finding', () => {
    const finding = mapFindingRecord({
      accountId: '123456789012',
      principalArn: 'arn:aws:iam::123456789012:role/MyRole',
      principalType: 'role',
      allowedActionCount: 10,
      removedActionCount: 6,
      keptActionCount: 4,
      removedActions: ['iam:CreateUser'],
      keptActions: ['s3:GetObject'],
      recommendedPolicyJson: JSON.stringify([
        { sid: 'RightsizedAllow', effect: 'Allow', actions: ['s3:GetObject'], resources: ['*'] },
      ]),
      riskLevel: 'high',
      confidence: 0.5,
      isAdmin: false,
      blastRadius: 3,
      lastSweptAt: '2024-01-01T00:00:00Z',
    });

    expect(finding.accountId).toBe('123456789012');
    expect(finding.principalType).toBe('role');
    expect(finding.removedActionCount).toBe(6);
    expect(finding.riskLevel).toBe('high');
    expect(finding.recommendedPolicy).toHaveLength(1);
  });

  it('defaults missing fields', () => {
    const finding = mapFindingRecord({});
    expect(finding.accountId).toBe('');
    expect(finding.principalType).toBe('role');
    expect(finding.removedActions).toEqual([]);
    expect(finding.recommendedPolicy).toEqual([]);
    expect(finding.riskLevel).toBe('low');
  });
});

describe('parseLeastPrivilegeToken', () => {
  const token = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64');
  const key = {
    accountId: { S: '111122223333' },
    principalArn: { S: 'arn:aws:iam::111122223333:role/x' },
  };

  it('accepts and re-shapes the table key', () => {
    expect(parseLeastPrivilegeToken(token(key))).toEqual(key);
  });

  it.each([
    ['not JSON', Buffer.from('not json').toString('base64')],
    ['an array', token([1, 2])],
    ['a missing key', token({ accountId: { S: '111122223333' } })],
    ['a non-string key value', token({ accountId: { N: '1' }, principalArn: { S: 'x' } })],
    [
      'an oversized key value',
      token({ accountId: { S: 'a'.repeat(2_049) }, principalArn: { S: 'x' } }),
    ],
  ])('rejects %s', (_case, value) => {
    expect(() => parseLeastPrivilegeToken(value)).toThrow('Invalid pagination token');
  });

  it('caps the encoded token length', () => {
    expect(() => parseLeastPrivilegeToken('x'.repeat(2_049))).toThrow('Invalid pagination token');
  });
});
