import { recomputeDeduplicationId, recomputeReasons, RECOMPUTE_DEDUP_WINDOW_MS } from './recompute';

describe('recomputeReasons', () => {
  it('names the IAM node labels and edge labels that make a batch stale', () => {
    const reasons = recomputeReasons(
      [
        { id: 'role', label: 'IamRole', properties: {} },
        { id: 'bucket', label: 'S3Bucket', properties: {} },
        { id: 'policy', label: 'IamPolicyDocument', properties: {} },
      ],
      [
        { from: 'role', to: 'ext', label: 'TRUSTS' },
        { from: 'img', to: 'repo', label: 'BELONGS_TO' },
      ]
    );
    expect(reasons).toEqual(['IamPolicyDocument', 'IamRole', 'TRUSTS']);
  });

  it('is empty for collection that cannot move an escalation', () => {
    expect(
      recomputeReasons(
        [{ id: 'bucket', label: 'S3Bucket', properties: {} }],
        [{ from: 'img', to: 'repo', label: 'BELONGS_TO' }]
      )
    ).toEqual([]);
  });
});

describe('recomputeDeduplicationId', () => {
  it('buckets ids into five-minute windows', () => {
    const start = 1_700_000_100_000; // on a five-minute boundary
    expect(recomputeDeduplicationId(start)).toBe(recomputeDeduplicationId(start + 1_000));
    expect(recomputeDeduplicationId(start + RECOMPUTE_DEDUP_WINDOW_MS - 1)).toBe(
      recomputeDeduplicationId(start)
    );
    expect(recomputeDeduplicationId(start + RECOMPUTE_DEDUP_WINDOW_MS)).not.toBe(
      recomputeDeduplicationId(start)
    );
  });
});
