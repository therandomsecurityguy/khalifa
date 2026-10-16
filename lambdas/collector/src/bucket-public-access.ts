// CIS 2.1.4 asks whether Block Public Access is on, not whether a bucket is
// public. The collector stored the GetPublicAccessBlock response as one object,
// which the graph writer serializes to a string, so no query could read a flag.
// The four settings are lifted to scalar properties instead.
//
// A bucket with no configuration (NoSuchPublicAccessBlockConfiguration) has all
// four off. The previous fallback set only two of them, leaving the other two
// absent -- which a query cannot tell apart from "not yet collected".

export interface BucketPublicAccessBlock {
  block_public_acls: boolean;
  ignore_public_acls: boolean;
  block_public_policy: boolean;
  restrict_public_buckets: boolean;
}

interface PublicAccessBlockConfiguration {
  BlockPublicAcls?: boolean;
  IgnorePublicAcls?: boolean;
  BlockPublicPolicy?: boolean;
  RestrictPublicBuckets?: boolean;
}

export function summarizePublicAccessBlock(
  config: PublicAccessBlockConfiguration | undefined
): BucketPublicAccessBlock {
  return {
    block_public_acls: config?.BlockPublicAcls === true,
    ignore_public_acls: config?.IgnorePublicAcls === true,
    block_public_policy: config?.BlockPublicPolicy === true,
    restrict_public_buckets: config?.RestrictPublicBuckets === true,
  };
}
