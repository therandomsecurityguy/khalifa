import { effectivePermissionId } from './graph-ids';

describe('effectivePermissionId', () => {
  it('derives a stable id from the principal ARN', () => {
    const arn = 'arn:aws:iam::111122223333:role/Admin';
    expect(effectivePermissionId(arn)).toBe(`eff-perm:${arn}`);
    expect(effectivePermissionId(arn)).toBe(effectivePermissionId(arn));
  });

  it('distinguishes principals', () => {
    expect(effectivePermissionId('arn:aws:iam::111122223333:role/A')).not.toBe(
      effectivePermissionId('arn:aws:iam::111122223333:role/B')
    );
  });
});
