import { isRoleArn, roleVertexId } from './iam-ids';

const ACCOUNT = '111111111111';

describe('roleVertexId', () => {
  it.each([
    ['a role name', 'app', `arn:aws:iam::${ACCOUNT}:role/app`],
    [
      'an ARN without a path',
      `arn:aws:iam::${ACCOUNT}:role/app`,
      `arn:aws:iam::${ACCOUNT}:role/app`,
    ],
    [
      'an ARN with a path',
      `arn:aws:iam::${ACCOUNT}:role/service-role/app-role-x1y2`,
      `arn:aws:iam::${ACCOUNT}:role/app-role-x1y2`,
    ],
    [
      'an SSO role ARN',
      'arn:aws:iam::222222222222:role/aws-reserved/sso.amazonaws.com/us-west-2/AWSReservedSSO_Admin_abc',
      'arn:aws:iam::222222222222:role/AWSReservedSSO_Admin_abc',
    ],
  ])('normalizes %s', (_name, input, expected) => {
    expect(roleVertexId(ACCOUNT, input)).toBe(expected);
  });

  it('recognizes role ARNs only', () => {
    expect(isRoleArn(`arn:aws:iam::${ACCOUNT}:role/service-role/x`)).toBe(true);
    expect(isRoleArn(`arn:aws:iam::${ACCOUNT}:user/x`)).toBe(false);
    expect(isRoleArn(`arn:aws:iam::${ACCOUNT}:root`)).toBe(false);
    expect(isRoleArn('lambda.amazonaws.com')).toBe(false);
  });
});
