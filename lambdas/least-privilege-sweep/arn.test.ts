import { extractAccountId, extractPrincipalType, isServiceLinkedRole } from './arn';

describe('extractAccountId', () => {
  it('extracts the account id from a role ARN', () => {
    expect(extractAccountId('arn:aws:iam::123456789012:role/MyRole')).toBe('123456789012');
  });

  it('extracts the account id from a user ARN', () => {
    expect(extractAccountId('arn:aws:iam::999999999999:user/alice')).toBe('999999999999');
  });

  it('returns empty string for malformed ARN', () => {
    expect(extractAccountId('not-an-arn')).toBe('');
  });
});

describe('extractPrincipalType', () => {
  it('identifies a role', () => {
    expect(extractPrincipalType('arn:aws:iam::123456789012:role/MyRole')).toBe('role');
  });

  it('identifies a user', () => {
    expect(extractPrincipalType('arn:aws:iam::123456789012:user/alice')).toBe('user');
  });

  it('returns unknown for other types', () => {
    expect(extractPrincipalType('arn:aws:iam::123456789012:group/admins')).toBe('unknown');
  });
});

describe('isServiceLinkedRole', () => {
  it('detects service-linked roles', () => {
    expect(
      isServiceLinkedRole(
        'arn:aws:iam::123456789012:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling'
      )
    ).toBe(true);
  });

  it('returns false for normal roles', () => {
    expect(isServiceLinkedRole('arn:aws:iam::123456789012:role/MyRole')).toBe(false);
  });
});
