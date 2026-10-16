import { enumerateGraph, type GraphSubmitter } from '../../shared/graph-scan';
import type { BucketRef } from './s3-sampler';

/**
 * Every S3 bucket the collector has seen, across all collected accounts, from
 * the graph. The scanner runs in one account, so S3 `ListBuckets` only finds
 * the home account's buckets; the graph is what covers the prod accounts.
 */
export async function listBucketsFromGraph(client: GraphSubmitter): Promise<BucketRef[]> {
  const rows = await enumerateGraph(
    client,
    (start, end) => `
      g.V().hasLabel('S3Bucket')
        .project('name', 'accountId')
          .by('name')
          .by('account_id')
        .range(${start}, ${end})
    `,
    { label: 's3-buckets' }
  );

  return rows
    .map((row) => {
      const item = row as { get(key: string): unknown };
      return {
        name: String(item.get('name') || ''),
        accountId: String(item.get('accountId') || ''),
      };
    })
    .filter((bucket) => bucket.name.length > 0);
}
