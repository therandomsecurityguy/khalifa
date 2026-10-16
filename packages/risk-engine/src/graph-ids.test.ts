import { effectivePermissionId } from './graph-ids';

describe('effectivePermissionId', () => {
  it('keys the derived permission vertex by the principal ARN', () => {
    const arn = 'arn:aws:iam::111122223333:role/Admin';
    expect(effectivePermissionId(arn)).toBe(`eff-perm:${arn}`);
    expect(effectivePermissionId(arn)).toBe(effectivePermissionId(arn));
    expect(effectivePermissionId(arn)).not.toBe(effectivePermissionId(`${arn}2`));
  });
});
