import { S3Client } from '@aws-sdk/client-s3';
import type { GraphNode, GraphEdge } from '../shared/types';
import { Logger } from '../shared/types';
import { scanBuckets } from './src/s3-sampler';
import { RegexClassifier } from './src/regex-classifier';
import { MacieClassifier } from './src/macie-classifier';
import { promoteClassification } from './src/classifier';

const logger = new Logger('dspm-scanner');

interface DspmEvent {
  accountId?: string;
  regions?: string[];
}

export const handler = async (
  event: DspmEvent = {}
): Promise<{ bucketsScanned: number; findingsWritten: number; errors: number }> => {
  logger.info('Starting DSPM scan', { accountId: event.accountId });

  const region = process.env.AWS_REGION || 'us-east-1';
  const scanMode = process.env.DSPM_SCAN_MODE || 'tagged-only';
  const macieEnabled = process.env.MACIE_ENABLED === 'true';

  const s3Client = new S3Client({ region });

  const classifiers = [new RegexClassifier()];
  const macieClassifier = macieEnabled ? new MacieClassifier() : undefined;

  const scanResults = await scanBuckets(s3Client, classifiers, scanMode, macieClassifier);

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  let findingsWritten = 0;
  let errors = 0;

  for (const result of scanResults) {
    if (result.error) {
      errors++;
      logger.warn('Bucket scan failed', { bucket: result.bucketName, error: result.error });
      continue;
    }

    if (!result.result || result.result.piiTypes.length === 0) continue;

    const findingArn = `${result.bucketArn}/dspm-finding/${Date.now()}`;
    const { classification, confidence } = promoteClassification(result.result);

    nodes.push({
      id: findingArn,
      label: 'DataClassificationFinding',
      properties: {
        id: findingArn,
        arn: findingArn,
        account_id: event.accountId || '',
        pii_types: JSON.stringify(result.result.piiTypes),
        secret_count: result.result.secretCount,
        sample_size: result.result.sampleSize,
        confidence,
        data_classification: classification,
        data_class_source: 'scanner',
        classifier: result.result.classifier,
        scanned_at: result.result.scannedAt,
      },
    });

    edges.push({
      from: findingArn,
      to: result.bucketArn,
      label: 'CLASSIFIES',
    });

    findingsWritten++;
  }

  logger.info(
    `DSPM scan complete: ${scanResults.length} buckets, ${findingsWritten} findings, ${errors} errors`
  );

  return {
    bucketsScanned: scanResults.length,
    findingsWritten,
    errors,
  };
};
