import { summarizePublicAccessBlock } from './bucket-public-access';

describe('summarizePublicAccessBlock', () => {
  it('reports all four settings when every one is on', () => {
    expect(
      summarizePublicAccessBlock({
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true,
      })
    ).toEqual({
      block_public_acls: true,
      ignore_public_acls: true,
      block_public_policy: true,
      restrict_public_buckets: true,
    });
  });

  // NoSuchPublicAccessBlockConfiguration: every property must still be written,
  // as false, so the evaluator does not mistake the bucket for uncollected.
  it('reports all four as false for a bucket with no configuration', () => {
    expect(summarizePublicAccessBlock(undefined)).toEqual({
      block_public_acls: false,
      ignore_public_acls: false,
      block_public_policy: false,
      restrict_public_buckets: false,
    });
  });

  it('treats an omitted setting as off', () => {
    const s = summarizePublicAccessBlock({ BlockPublicAcls: true, BlockPublicPolicy: true });

    expect(s.block_public_acls).toBe(true);
    expect(s.ignore_public_acls).toBe(false);
    expect(s.restrict_public_buckets).toBe(false);
  });
});
