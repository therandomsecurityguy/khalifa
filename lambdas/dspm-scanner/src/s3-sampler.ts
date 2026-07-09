import {
  S3Client,
  ListBucketsCommand,
  ListObjectsV2Command,
  GetObjectCommand,
} from '@aws-sdk/client-s3';
import type { Classifier, ClassificationMatch, ClassificationResult } from './classifier';

const MAX_OBJECTS_PER_BUCKET = 50;
const MAX_OBJECT_SIZE_BYTES = 1 * 1024 * 1024;
const MAX_SAMPLE_SIZE_BYTES = 256 * 1024;

export interface BucketScanResult {
  bucketArn: string;
  bucketName: string;
  result: ClassificationResult | null;
  error?: string;
}

export async function scanBuckets(
  s3Client: S3Client,
  classifiers: Classifier[],
  scanMode: string,
  macieClassifier?: { getFindingsForBucket(name: string): Promise<ClassificationMatch[]> }
): Promise<BucketScanResult[]> {
  const results: BucketScanResult[] = [];

  const bucketsResponse = await s3Client.send(new ListBucketsCommand({}));
  const buckets = bucketsResponse.Buckets || [];

  for (const bucket of buckets) {
    if (!bucket.Name) continue;
    const bucketArn = `arn:aws:s3:::${bucket.Name}`;

    if (scanMode === 'off') {
      results.push({ bucketArn, bucketName: bucket.Name, result: null });
      continue;
    }

    try {
      const result = await scanBucket(s3Client, bucket.Name, classifiers, macieClassifier);
      results.push({ bucketArn, bucketName: bucket.Name, result });
    } catch (e) {
      results.push({
        bucketArn,
        bucketName: bucket.Name,
        result: null,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  return results;
}

async function scanBucket(
  s3Client: S3Client,
  bucketName: string,
  classifiers: Classifier[],
  macieClassifier?: { getFindingsForBucket(name: string): Promise<ClassificationMatch[]> }
): Promise<ClassificationResult> {
  let scanned = 0;
  const allMatches: ClassificationMatch[] = [];

  const listResponse = await s3Client.send(
    new ListObjectsV2Command({ Bucket: bucketName, MaxKeys: MAX_OBJECTS_PER_BUCKET })
  );

  const objects = listResponse.Contents || [];

  for (const obj of objects) {
    if (!obj.Key || !obj.Size) continue;

    if (obj.Size > MAX_OBJECT_SIZE_BYTES) {
      scanned++;
      continue;
    }

    try {
      const getResponse = await s3Client.send(
        new GetObjectCommand({ Bucket: bucketName, Key: obj.Key })
      );

      const body = await getResponse.Body?.transformToString('utf-8');
      if (!body) {
        scanned++;
        continue;
      }

      const content = body.slice(0, MAX_SAMPLE_SIZE_BYTES);
      for (const classifier of classifiers) {
        const matches = await classifier.classify(content);
        allMatches.push(...matches);
      }

      scanned++;
    } catch {
      scanned++;
    }
  }

  if (macieClassifier) {
    const macieMatches = await macieClassifier.getFindingsForBucket(bucketName);
    allMatches.push(...macieMatches);
  }

  return aggregateResults(allMatches, scanned, classifiers);
}

function aggregateResults(
  matches: ClassificationMatch[],
  sampleSize: number,
  classifiers: Classifier[]
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
      match.piiType === 'high_entropy_secret'
    ) {
      secretCount += match.count;
    }
  }

  const piiTypes = [...byType.keys()] as any;
  const maxConfidence = matches.length > 0 ? Math.max(...matches.map((m) => m.confidence)) : 0;

  return {
    piiTypes,
    secretCount,
    matches: [...byType.values()],
    sampleSize,
    confidence: maxConfidence,
    scannedAt: new Date().toISOString(),
    classifier: classifiers.map((c) => c.name).join(','),
  };
}
