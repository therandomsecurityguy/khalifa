import { S3Client } from '@aws-sdk/client-s3';
import { LambdaClient } from '@aws-sdk/client-lambda';
import { NeptuneRuntimeClient } from '@khalifa/risk-engine';
import type { GraphNode, GraphEdge } from '../shared/types';
import { Logger } from '../shared/types';
import type { GraphSubmitter } from '../shared/graph-scan';
import { createHttpGraphWriter, invokeGraphWriter } from '../shared/graph-writer-client';
import { scanBuckets, scanObject, type ScanBudget, type BucketRef } from './src/s3-sampler';
import { listBucketsFromGraph } from './src/graph-inventory';
import { scanLambdaFunctions } from './src/lambda-sampler';
import { RegexClassifier } from './src/regex-classifier';
import { MacieClassifier } from './src/macie-classifier';
import { promoteClassification, type Classifier } from './src/classifier';

const logger = new Logger('dspm-scanner');

interface DspmEvent {
  accountId?: string;
}

export type DspmPersist = (
  mutations: { nodes: GraphNode[]; edges: GraphEdge[]; observedAt?: string },
  options?: { functionName?: string }
) => Promise<{ success: true; written: number; tombstoned?: number }>;

interface DspmDependencies {
  s3Client: S3Client;
  lambdaClient: LambdaClient;
  classifiers: Classifier[];
  macieClassifier?: MacieClassifier;
  scan: typeof scanBuckets;
  scanLambdas: typeof scanLambdaFunctions;
  persist: DspmPersist;
  graphClient?: GraphSubmitter;
}

function createScanBudget(environment: NodeJS.ProcessEnv): ScanBudget {
  const budgetMs = positiveInt(environment, 'DSPM_CLASSIFY_BUDGET_MS', 30_000, 600_000);
  return { deadlineAt: Date.now() + budgetMs };
}

export interface DspmResult {
  bucketsScanned: number;
  functionsScanned: number;
  findingsWritten: number;
  errors: number;
  /** Buckets that are neither Macie-covered nor tagged for regex sampling. */
  uncoveredBuckets: number;
}

const MIN_TOKEN_LENGTH = 16;

function validateGraphWriterToken(token: string): string {
  if (token !== token.trim() || token.length < MIN_TOKEN_LENGTH) {
    throw new Error('GRAPH_WRITER_TOKEN must be at least 16 characters without outer whitespace');
  }
  return token;
}

function positiveInt(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  maximum: number
): number {
  const value = environment[name];
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return parsed;
}

function resolvePersist(
  dependencyOverrides: Partial<DspmDependencies>,
  environment: NodeJS.ProcessEnv
): { persist: DspmPersist; functionName: string } {
  if (dependencyOverrides.persist) {
    return {
      persist: dependencyOverrides.persist,
      functionName: environment.GRAPH_WRITER_FUNCTION_NAME?.trim() || '',
    };
  }

  const functionName = environment.GRAPH_WRITER_FUNCTION_NAME?.trim();
  if (functionName) {
    return { persist: invokeGraphWriter, functionName };
  }

  const graphWriterUrl = environment.GRAPH_WRITER_URL?.trim();
  if (graphWriterUrl) {
    const token = validateGraphWriterToken(environment.GRAPH_WRITER_TOKEN ?? '');
    const timeoutMs = positiveInt(environment, 'GRAPH_WRITER_TIMEOUT_MS', 30_000, 300_000);
    const writer = createHttpGraphWriter(graphWriterUrl, timeoutMs, fetch, token);
    return {
      persist: (mutations) =>
        writer({ ...mutations, observedAt: mutations.observedAt ?? new Date().toISOString() }),
      functionName: '',
    };
  }

  throw new Error('GRAPH_WRITER_FUNCTION_NAME or GRAPH_WRITER_URL is required');
}

/**
 * Bucket inventory for the scan. The graph spans every collected account;
 * S3 ListBuckets only returns the account the scanner runs in, which would
 * miss the prod buckets the plan wants Macie to cover.
 */
async function bucketInventory(
  environment: NodeJS.ProcessEnv,
  region: string,
  scanMode: string,
  overrides: Partial<DspmDependencies>,
  macieClassifier?: MacieClassifier
): Promise<BucketRef[] | undefined> {
  if (scanMode === 'off') return undefined;

  // Macie knows exactly the enabled accounts' buckets — current and in-Region.
  // The graph spans every collected account and goes stale, so in tagged-only
  // mode it made the scanner read tags on unreachable/deleted buckets.
  if (macieClassifier) return macieClassifier.listBuckets();

  const endpoint = environment.NEPTUNE_ENDPOINT?.trim();
  if (!endpoint) return undefined;

  const ownsClient = !overrides.graphClient;
  const client = overrides.graphClient || new NeptuneRuntimeClient({ endpoint, region });
  try {
    return await listBucketsFromGraph(client);
  } finally {
    if (ownsClient) await (client as NeptuneRuntimeClient).close();
  }
}

function buildFinding(
  resourceArn: string,
  result: NonNullable<Awaited<ReturnType<typeof scanBuckets>>[number]['result']>,
  accountId: string | undefined
): { node: GraphNode; edge: GraphEdge } {
  const findingArn = `${resourceArn}/dspm-finding`;
  const { classification, confidence } = promoteClassification(result);
  const node: GraphNode = {
    id: findingArn,
    label: 'DataClassificationFinding',
    observedAt: result.scannedAt,
    properties: {
      id: findingArn,
      arn: findingArn,
      account_id: accountId || '',
      pii_types: JSON.stringify(result.piiTypes),
      secret_count: result.secretCount,
      sample_size: result.sampleSize,
      skipped_kms: result.skippedKms,
      confidence,
      data_classification: classification,
      data_class_source: 'scanner',
      classifier: result.classifier,
      scanned_at: result.scannedAt,
    },
  };
  const edge: GraphEdge = {
    from: findingArn,
    to: resourceArn,
    label: 'CLASSIFIES',
    observedAt: result.scannedAt,
  };
  return { node, edge };
}

export async function runDspmScan(
  event: DspmEvent = {},
  dependencyOverrides: Partial<DspmDependencies> = {},
  environment: NodeJS.ProcessEnv = process.env
): Promise<DspmResult> {
  logger.info('Starting DSPM scan', { accountId: event.accountId });

  const { persist, functionName } = resolvePersist(dependencyOverrides, environment);

  const region = environment.AWS_REGION || 'us-east-1';
  const scanMode = environment.DSPM_SCAN_MODE || 'tagged-only';
  const macieEnabled = environment.MACIE_ENABLED === 'true';
  const budget = createScanBudget(environment);

  const dependencies: DspmDependencies = {
    s3Client: dependencyOverrides.s3Client || new S3Client({ region }),
    lambdaClient: dependencyOverrides.lambdaClient || new LambdaClient({ region }),
    classifiers: dependencyOverrides.classifiers || [new RegexClassifier()],
    macieClassifier:
      dependencyOverrides.macieClassifier || (macieEnabled ? new MacieClassifier() : undefined),
    scan: dependencyOverrides.scan || scanBuckets,
    scanLambdas: dependencyOverrides.scanLambdas || scanLambdaFunctions,
    persist,
  };

  const scanResults = await dependencies.scan(
    dependencies.s3Client,
    dependencies.classifiers,
    scanMode,
    dependencies.macieClassifier,
    budget,
    await bucketInventory(
      environment,
      region,
      scanMode,
      dependencyOverrides,
      dependencies.macieClassifier
    )
  );

  // Guard against the one values edit that silently reintroduces prod object
  // reads: a bucket that Macie already covers must never also be tagged for
  // regex sampling. Fail loudly rather than scan it.
  const bothMacieAndTagged = scanResults.filter((r) => r.macieCovered && r.optedIn);
  if (bothMacieAndTagged.length > 0) {
    throw new Error(
      `DSPM misconfiguration: ${bothMacieAndTagged.length} bucket(s) are both Macie-covered and tagged dspm-scan ` +
        `(prod buckets must not be in the regex allowlist): ${bothMacieAndTagged
          .map((r) => r.bucketName)
          .join(', ')}`
    );
  }

  // Report buckets that no engine covers, so an unlisted bucket is visible
  // instead of silently assumed safe.
  const uncovered = scanResults
    .filter((r) => r.engine === 'none' && !r.error)
    .map((r) => r.bucketName);
  if (scanMode !== 'off' && uncovered.length > 0) {
    logger.warn(
      `DSPM coverage gap: ${uncovered.length} bucket(s) neither Macie-covered nor tagged`,
      {
        buckets: uncovered.slice(0, 20),
      }
    );
  }

  const lambdaResults = await dependencies.scanLambdas(
    dependencies.lambdaClient,
    dependencies.classifiers
  );

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const scanErrors: { bucketName: string; error: string }[] = [];

  for (const result of scanResults) {
    if (result.error) {
      scanErrors.push({ bucketName: result.bucketName, error: result.error });
      logger.warn('Bucket scan failed', { bucket: result.bucketName, error: result.error });
      continue;
    }

    if (!result.result || result.result.piiTypes.length === 0) continue;

    const { node, edge } = buildFinding(
      result.bucketArn,
      result.result,
      result.accountId || event.accountId
    );
    nodes.push(node);
    edges.push(edge);
  }

  let findingsWritten = 0;
  if (nodes.length > 0) {
    await dependencies.persist({ nodes, edges }, { functionName });
    findingsWritten = nodes.length;
  }

  let lambdaErrors = 0;
  const lambdaNodes: GraphNode[] = [];
  const lambdaEdges: GraphEdge[] = [];
  for (const result of lambdaResults) {
    if (result.error) {
      lambdaErrors += 1;
      logger.warn('Lambda env scan failed', { function: result.functionName, error: result.error });
      continue;
    }
    if (!result.result || result.result.piiTypes.length === 0) continue;

    const { node, edge } = buildFinding(result.functionArn, result.result, event.accountId);
    lambdaNodes.push(node);
    lambdaEdges.push(edge);
  }

  if (lambdaNodes.length > 0) {
    try {
      await dependencies.persist({ nodes: lambdaNodes, edges: lambdaEdges }, { functionName });
      findingsWritten += lambdaNodes.length;
    } catch (e) {
      // Lambda env findings degrade to a warning so an uncollected function
      // vertex (missing CLASSIFIES endpoint) cannot fail the whole scan.
      lambdaErrors += 1;
      logger.warn('Lambda env findings persist failed', {
        findings: lambdaNodes.length,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  if (scanErrors.length > 0) {
    const details = scanErrors
      .slice(0, 10)
      .map(({ bucketName, error }) => `${bucketName}: ${error}`)
      .join('; ');
    const omitted = scanErrors.length > 10 ? `; ${scanErrors.length - 10} more` : '';
    const message = `DSPM scan completed with ${scanErrors.length} bucket failure(s): ${details}${omitted}`;
    logger.error(message, {
      bucketsScanned: scanResults.length,
      functionsScanned: lambdaResults.length,
      findingsWritten,
      errors: scanErrors.length,
    });
    throw new Error(message);
  }

  logger.info(
    `DSPM scan complete: ${scanResults.length} buckets, ${lambdaResults.length} functions, ${findingsWritten} findings, ${lambdaErrors} lambda error(s)`
  );

  return {
    bucketsScanned: scanResults.length,
    functionsScanned: lambdaResults.length,
    findingsWritten,
    errors: lambdaErrors,
    uncoveredBuckets: uncovered.length,
  };
}

export const handler = async (event: DspmEvent = {}): Promise<DspmResult> => runDspmScan(event);

export interface SqsS3Event {
  Records: Array<{ body: string }>;
}

export interface SqsScanResult {
  objectsScanned: number;
  findingsWritten: number;
}

export async function handleSqsEvent(
  event: SqsS3Event,
  dependencyOverrides: Partial<DspmDependencies> = {},
  environment: NodeJS.ProcessEnv = process.env
): Promise<SqsScanResult> {
  const { persist, functionName } = resolvePersist(dependencyOverrides, environment);

  const region = environment.AWS_REGION || 'us-east-1';
  const s3Client = dependencyOverrides.s3Client || new S3Client({ region });
  const classifiers = dependencyOverrides.classifiers || [new RegexClassifier()];

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  let objectsScanned = 0;

  for (const record of event.Records || []) {
    let s3Event: {
      Records?: Array<{
        s3?: { bucket?: { name?: string }; object?: { key?: string; size?: number } };
      }>;
    };
    try {
      s3Event = JSON.parse(record.body);
    } catch {
      continue;
    }

    for (const s3Record of s3Event.Records || []) {
      const bucket = s3Record.s3?.bucket?.name;
      const key = s3Record.s3?.object?.key;
      const size = s3Record.s3?.object?.size ?? 0;
      if (!bucket || !key) continue;

      const result = await scanObject(s3Client, bucket, key, size, classifiers);
      objectsScanned += 1;
      if (!result || result.piiTypes.length === 0) continue;

      const { node, edge } = buildFinding(`arn:aws:s3:::${bucket}`, result, undefined);
      nodes.push(node);
      edges.push(edge);
    }
  }

  let findingsWritten = 0;
  if (nodes.length > 0) {
    await persist({ nodes, edges }, { functionName });
    findingsWritten = nodes.length;
  }

  return { objectsScanned, findingsWritten };
}

export const sqsHandler = async (event: SqsS3Event): Promise<SqsScanResult> =>
  handleSqsEvent(event);
