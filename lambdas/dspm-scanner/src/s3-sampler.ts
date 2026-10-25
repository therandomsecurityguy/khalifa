import {
  S3Client,
  GetBucketTaggingCommand,
  ListBucketsCommand,
  ListObjectsV2Command,
  GetObjectCommand,
} from '@aws-sdk/client-s3';
import { appendAll } from '../../shared/arrays';
import type { Classifier, ClassificationMatch, ClassificationResult } from './classifier';
import type { MacieScanner } from './macie-classifier';

const MAX_OBJECTS_PER_BUCKET = 50;
// Ranged GETs cap the transferred bytes at the sample size regardless of the
// listed object size, so hostile or racing listings cannot force a full read.
export interface ScanBudget {
  /** Wall-clock deadline for untrusted-content classification (Date.now ms). */
  deadlineAt: number;
}

/** Hard CPU budget for classifying untrusted content; stops sampling when hit. */
export function createScanBudget(budgetMs: number, nowMs = Date.now()): ScanBudget {
  if (!Number.isSafeInteger(budgetMs) || budgetMs < 1) {
    throw new Error('Classification budget must be a positive integer (ms)');
  }
  return { deadlineAt: nowMs + budgetMs };
}

function budgetExceeded(budget?: ScanBudget): boolean {
  return budget !== undefined && Date.now() >= budget.deadlineAt;
}
// Buckets opt in to content sampling with this tag; `tagged-only` samples nothing else.
const DSPM_SCAN_TAG = 'dspm-scan';
const MAX_OBJECT_SIZE_BYTES = 1 * 1024 * 1024;
const MAX_SAMPLE_SIZE_BYTES = 256 * 1024;
const MAX_SAMPLE_RANGE = `bytes=0-${MAX_SAMPLE_SIZE_BYTES - 1}`;

export interface BucketRef {
  name: string;
  accountId?: string;
}

export interface BucketScanResult {
  bucketArn: string;
  bucketName: string;
  accountId?: string;
  result: ClassificationResult | null;
  error?: string;
  /** Engine selected for this bucket: Macie, regex sampling, or nothing. */
  engine: 'macie' | 'regex' | 'none';
  /** Macie automated discovery monitors this bucket (server-side, no object reads). */
  macieCovered: boolean;
  /** The bucket carries the `dspm-scan` opt-in tag. */
  optedIn: boolean;
}

/**
 * Default bucket inventory: the account the scanner runs in. The scheduled
 * scanner passes the graph's S3Bucket nodes instead, so it covers every
 * collected account, not just the home account.
 */
export async function listBuckets(s3Client: S3Client): Promise<BucketRef[]> {
  const response = await s3Client.send(new ListBucketsCommand({}));
  return (response.Buckets || [])
    .filter((bucket): bucket is { Name: string } => Boolean(bucket.Name))
    .map((bucket) => ({ name: bucket.Name }));
}

export async function scanBuckets(
  s3Client: S3Client,
  classifiers: Classifier[],
  scanMode: string,
  macieScanner?: MacieScanner,
  budget?: ScanBudget,
  buckets?: BucketRef[]
): Promise<BucketScanResult[]> {
  const results: BucketScanResult[] = [];
  const refs = buckets ?? (await listBuckets(s3Client));

  for (const bucket of refs) {
    const bucketName = bucket.name;
    const bucketArn = `arn:aws:s3:::${bucketName}`;

    try {
      // Macie coverage is checked even for untagged buckets: a covered bucket is
      // scanned server-side with no object reads, and a covered bucket that IS
      // tagged is the misconfiguration the caller must fail on (prod bucket in
      // the non-prod allowlist). Tags are only read in tagged-only mode.
      const macieCovered = macieScanner ? await macieScanner.hasCoverage(bucketName) : false;
      const optedIn = scanMode === 'tagged-only' ? await optedInFor(s3Client, bucketName) : false;

      if (scanMode === 'off' || (scanMode !== 'all' && !macieCovered && !optedIn)) {
        results.push({
          bucketArn,
          bucketName,
          accountId: bucket.accountId,
          result: null,
          engine: 'none',
          macieCovered,
          optedIn,
        });
        continue;
      }

      const result = await scanBucket(
        s3Client,
        bucketName,
        classifiers,
        macieScanner,
        budget,
        macieCovered
      );
      results.push({
        bucketArn,
        bucketName,
        accountId: bucket.accountId,
        result,
        engine: macieCovered ? 'macie' : 'regex',
        macieCovered,
        optedIn,
      });
    } catch (e) {
      results.push({
        bucketArn,
        bucketName,
        accountId: bucket.accountId,
        result: null,
        engine: 'none',
        macieCovered: false,
        optedIn: false,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  return results;
}

/**
 * The bucket has opted in to content sampling via the `dspm-scan` tag.
 * Shared by the scheduled scan and the SQS path: event-driven scans must
 * apply the same opt-in gate, or any queue producer could force object
 * reads on buckets that never opted in.
 */
export async function optedInFor(s3Client: S3Client, bucketName: string): Promise<boolean> {
  try {
    const tagging = await s3Client.send(new GetBucketTaggingCommand({ Bucket: bucketName }));
    return (tagging.TagSet || []).some(
      (tag) => tag.Key === DSPM_SCAN_TAG && /^(true|yes|1)$/i.test(tag.Value || '')
    );
  } catch (error) {
    // No tag set, or a bucket policy that hides it: the bucket has not opted in.
    const name = error instanceof Error ? error.name : '';
    if (name === 'NoSuchTagSet' || /AccessDenied/.test(name)) return false;
    throw error;
  }
}

async function scanBucket(
  s3Client: S3Client,
  bucketName: string,
  classifiers: Classifier[],
  macieScanner?: MacieScanner,
  budget?: ScanBudget,
  macieCovered = false
): Promise<ClassificationResult> {
  // Macie primary: when Macie monitors this bucket, use its server-side
  // findings only and never download object bytes. Coverage is decided once by
  // the caller — re-checking here made a transient DescribeBuckets failure
  // (hasCoverage swallows errors as false) send a covered bucket down the
  // regex path, where the cross-account ListBucket is denied and aborts the
  // whole scan.
  if (macieCovered && macieScanner) {
    const macieMatches = await macieScanner.getFindingsForBucket(bucketName);
    return aggregateResults(macieMatches, 0, 0, classifiers, 'macie');
  }

  // Regex fallback for buckets Macie does not cover.
  let scanned = 0;
  let skippedKms = 0;
  const allMatches: ClassificationMatch[] = [];

  const listResponse = await s3Client.send(
    new ListObjectsV2Command({ Bucket: bucketName, MaxKeys: MAX_OBJECTS_PER_BUCKET })
  );

  const objects = listResponse.Contents || [];

  for (const obj of objects) {
    if (budgetExceeded(budget)) break;
    if (!obj.Key || !obj.Size) continue;

    if (obj.Size > MAX_OBJECT_SIZE_BYTES) {
      scanned++;
      continue;
    }

    try {
      const getResponse = await s3Client.send(
        new GetObjectCommand({ Bucket: bucketName, Key: obj.Key, Range: MAX_SAMPLE_RANGE })
      );

      const body = await getResponse.Body?.transformToString('utf-8');
      if (!body) {
        scanned++;
        continue;
      }

      const content = body.slice(0, MAX_SAMPLE_SIZE_BYTES);
      for (const classifier of classifiers) {
        if (budgetExceeded(budget)) break;
        const matches = await classifier.classify(content);
        appendAll(allMatches, matches);
      }

      scanned++;
    } catch (e) {
      if (isKmsError(e)) {
        skippedKms++;
      } else {
        scanned++;
      }
    }
  }

  return aggregateResults(allMatches, scanned, skippedKms, classifiers);
}

const ContentRangeFormat = /bytes \d+-\d+\/(\d+)/;

function parseTotalSize(contentRange: string | undefined): number | null {
  if (!contentRange) return null;
  const match = contentRange.match(ContentRangeFormat);
  return match ? Number(match[1]) : null;
}

export function isKmsError(error: unknown): boolean {
  const name = error instanceof Error ? error.name : '';
  const message = error instanceof Error ? error.message : String(error);
  return /^KMS\./.test(name) || /kms|customer master key|cmk/i.test(message);
}

export async function scanObject(
  s3Client: S3Client,
  bucketName: string,
  key: string,
  size: number,
  classifiers: Classifier[]
): Promise<ClassificationResult | null> {
  // The event-provided size is a pre-filter only; it is never trusted as the
  // authoritative size (a missing/zero size used to bypass the large-object
  // guard and force a full download). The ranged GET below caps the transfer,
  // and the ContentRange total is the authoritative size.
  if (size > MAX_OBJECT_SIZE_BYTES) return null;

  try {
    const getResponse = await s3Client.send(
      new GetObjectCommand({ Bucket: bucketName, Key: key, Range: MAX_SAMPLE_RANGE })
    );
    const totalSize = parseTotalSize(getResponse.ContentRange);
    if (totalSize !== null && totalSize > MAX_OBJECT_SIZE_BYTES) return null;

    const body = await getResponse.Body?.transformToString('utf-8');
    if (!body) return null;

    const content = body.slice(0, MAX_SAMPLE_SIZE_BYTES);
    const allMatches: ClassificationMatch[] = [];
    for (const classifier of classifiers) {
      allMatches.push(...(await classifier.classify(content)));
    }
    return aggregateResults(allMatches, 1, 0, classifiers);
  } catch (e) {
    if (isKmsError(e)) {
      return aggregateResults([], 0, 1, classifiers);
    }
    return null;
  }
}

export function aggregateResults(
  matches: ClassificationMatch[],
  sampleSize: number,
  skippedKms: number,
  classifiers: Classifier[],
  classifierName?: string
): ClassificationResult {
  const byType = new Map<string, ClassificationMatch>();
  let secretCount = 0;

  for (const match of matches) {
    const existing = byType.get(match.piiType);
    if (existing) {
      existing.count += match.count;
      existing.confidence = Math.max(existing.confidence, match.confidence);
    } else {
      byType.set(match.piiType, { ...match });
    }

    if (
      match.piiType === 'private_key' ||
      match.piiType === 'aws_secret_key' ||
      match.piiType === 'gcp_service_account' ||
      match.piiType === 'high_entropy_secret' ||
      match.piiType === 'github_token' ||
      match.piiType === 'slack_token' ||
      match.piiType === 'stripe_key'
    ) {
      secretCount += match.count;
    }
  }

  const piiTypes = [...byType.keys()] as any;
  const maxConfidence = matches.reduce((max, match) => Math.max(max, match.confidence), 0);

  return {
    piiTypes,
    secretCount,
    matches: [...byType.values()],
    sampleSize,
    skippedKms,
    confidence: maxConfidence,
    scannedAt: new Date().toISOString(),
    classifier: classifierName ?? classifiers.map((c) => c.name).join(','),
  };
}
