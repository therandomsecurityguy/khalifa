import {
  AthenaClient,
  StartQueryExecutionCommand,
  GetQueryExecutionCommand,
  GetQueryResultsCommand,
  type Row,
} from '@aws-sdk/client-athena';
import { DynamoDBClient, BatchWriteItemCommand, type WriteRequest } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import { randomUUID } from 'crypto';
import type { GraphNode, GraphReconcile } from '../shared/types';
import { Logger } from '../shared/types';
import {
  assertAthenaDatabase,
  buildAnomalyQueries,
  buildAnomalyNodes,
  parseAnomalyRow,
  parseCanaryPrincipalArns,
  partitionWindow,
  reconcileAnomalies,
} from './src/anomalies';
import { detectDeniedSpikes, parseDeniedCountRow } from './src/baseline';

const logger = new Logger('cloudtrail-analyzer');
const defaultAthenaClient = new AthenaClient({
  region: process.env.AWS_REGION || 'us-east-1',
});
const defaultDynamoClient = new DynamoDBClient({
  region: process.env.AWS_REGION || 'us-east-1',
});

const MAX_ANALYSIS_DAYS = 365;
const BATCH_SIZE = 25;
const MAX_BATCH_WRITE_ATTEMPTS = 5;
const BATCH_WRITE_BASE_DELAY_MS = 100;

interface AnalyzerEvent {
  days?: number;
}

interface AnalyzerConfig {
  athenaDatabase: string;
  athenaWorkgroup: string;
  athenaResultsLocation: string;
  accessAnalyzerTable: string;
  analysisDays: number;
  graphWriterFunctionName: string;
  graphWriterUrl: string;
  canaryPrincipalArns: string[];
}

interface AnomalyBatch {
  nodes: GraphNode[];
  reconcile?: GraphReconcile;
  observedAt: string;
}

interface AnalyzerDependencies {
  athenaClient: AthenaClient;
  dynamoClient: DynamoDBClient;
  sleep: (milliseconds: number) => Promise<void>;
  now: () => Date;
  writeAnomalies: (batch: AnomalyBatch) => Promise<{ written: number }>;
  signal?: AbortSignal;
}

export interface CloudTrailUsageRecord {
  principalArn: string;
  eventSource: string;
  eventName: string;
  eventCount: number;
  lastUsed: string;
}

const defaultDependencies: AnalyzerDependencies = {
  athenaClient: defaultAthenaClient,
  dynamoClient: defaultDynamoClient,
  sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  now: () => new Date(),
  writeAnomalies: (batch) => invokeGraphWriterForAnomalies(batch),
};

async function invokeGraphWriterForAnomalies(batch: AnomalyBatch): Promise<{ written: number }> {
  const { invokeGraphWriter } = await import('../shared/graph-writer-client');
  const result = await invokeGraphWriter({
    nodes: batch.nodes,
    edges: [],
    observedAt: batch.observedAt,
    reconcile: batch.reconcile,
  });
  return { written: result.written };
}

export interface AnalyzeResult {
  recordsProcessed: number;
  queryExecutionId: string;
  anomalies: number;
}

export async function analyzeCloudTrail(
  event: AnalyzerEvent = {},
  dependencyOverrides: Partial<AnalyzerDependencies> = {},
  environment: NodeJS.ProcessEnv = process.env
): Promise<AnalyzeResult> {
  const dependencies = { ...defaultDependencies, ...dependencyOverrides };
  const config = loadConfig(environment);
  const days = validateAnalysisDays(event.days ?? config.analysisDays, 'days');
  logger.info(`Starting CloudTrail analysis for last ${days} days`);

  const queryExecutionId = await executeAthenaQuery(
    buildUsageQuery(days, config.athenaDatabase),
    config,
    dependencies.athenaClient
  );
  logger.info(`Athena query started: ${queryExecutionId}`);

  await waitForQueryCompletion(
    queryExecutionId,
    dependencies.athenaClient,
    dependencies.sleep,
    dependencies.signal
  );

  const results = await fetchQueryResults(queryExecutionId, dependencies.athenaClient);
  logger.info(`Query returned ${results.length} records`);

  const recordsProcessed = await writeResultsToDynamo(
    results,
    config.accessAnalyzerTable,
    dependencies.dynamoClient,
    dependencies.sleep,
    dependencies.now
  );

  const anomalies = await detectAnomalies(days, config, dependencies);

  return { recordsProcessed, queryExecutionId, anomalies };
}

export const handler = async (
  event: AnalyzerEvent = {}
): Promise<{ recordsProcessed: number; queryExecutionId: string }> => analyzeCloudTrail(event);

export function normalizeAthenaResultsLocation(value: string | undefined): string {
  const location = value?.trim();
  if (!location) {
    throw new Error('ATHENA_RESULTS_S3_LOCATION is required');
  }

  let parsed: URL;
  try {
    parsed = new URL(location);
  } catch {
    throw new Error('ATHENA_RESULTS_S3_LOCATION must be a valid s3:// URI');
  }

  if (
    parsed.protocol !== 's3:' ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error('ATHENA_RESULTS_S3_LOCATION must be a valid s3:// URI');
  }

  const path = parsed.pathname.replace(/\/+$/, '');
  return `s3://${parsed.hostname}${path}/`;
}

export function validateAnalysisDays(value: unknown, name = 'days'): number {
  const parsed =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && /^\d+$/.test(value.trim())
        ? Number(value)
        : Number.NaN;

  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_ANALYSIS_DAYS) {
    throw new Error(`${name} must be an integer between 1 and ${MAX_ANALYSIS_DAYS}`);
  }

  return parsed;
}

function loadConfig(environment: NodeJS.ProcessEnv): AnalyzerConfig {
  return {
    athenaDatabase: validateAthenaDatabase(environment.ATHENA_DATABASE || 'khalifa_cloudtrail_db'),
    athenaWorkgroup: environment.ATHENA_WORKGROUP || 'khalifa-cloudtrail-analysis',
    athenaResultsLocation: normalizeAthenaResultsLocation(environment.ATHENA_RESULTS_S3_LOCATION),
    accessAnalyzerTable: environment.ACCESS_ANALYZER_TABLE || 'AccessAnalyzerCache',
    analysisDays: validateAnalysisDays(environment.ANALYSIS_DAYS || '90', 'ANALYSIS_DAYS'),
    graphWriterFunctionName: environment.GRAPH_WRITER_FUNCTION_NAME || '',
    graphWriterUrl: environment.GRAPH_WRITER_URL?.trim() || '',
    canaryPrincipalArns: parseCanaryPrincipalArns(environment.CANARY_PRINCIPAL_ARNS),
  };
}

export function validateAthenaDatabase(value: string): string {
  return assertAthenaDatabase(value.trim());
}

function buildUsageQuery(days: number, database: string): string {
  return `
    SELECT
      useridentity.arn AS principal_arn,
      eventsource,
      eventname,
      COUNT(*) AS event_count,
      MAX(eventtime) AS last_used
    FROM ${database}.cloudtrail_logs
    WHERE ${partitionWindow(days)}
      AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${days}' day
      AND useridentity.arn IS NOT NULL
      AND useridentity.arn != ''
      AND eventsource NOT IN (
        'elasticloadbalancing.amazonaws.com',
        'monitoring.amazonaws.com',
        'logs.amazonaws.com'
      )
    GROUP BY useridentity.arn, eventsource, eventname
    ORDER BY event_count DESC
  `;
}

async function executeAthenaQuery(
  query: string,
  config: AnalyzerConfig,
  athenaClient: AthenaClient
): Promise<string> {
  const result = await athenaClient.send(
    new StartQueryExecutionCommand({
      QueryString: query,
      ResultConfiguration: {
        OutputLocation: config.athenaResultsLocation,
      },
      WorkGroup: config.athenaWorkgroup,
    })
  );

  if (!result.QueryExecutionId) {
    throw new Error('Failed to start Athena query: response did not include a query execution ID');
  }

  return result.QueryExecutionId;
}

async function waitForQueryCompletion(
  executionId: string,
  athenaClient: AthenaClient,
  sleep: (milliseconds: number) => Promise<void>,
  signal?: AbortSignal
): Promise<void> {
  const maxAttempts = 50;
  const delayMs = 5000;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const result = await athenaClient.send(
      new GetQueryExecutionCommand({ QueryExecutionId: executionId })
    );

    if (signal?.aborted) {
      throw new Error('CloudTrail analysis aborted');
    }

    const state = result.QueryExecution?.Status?.State;
    if (state === 'SUCCEEDED') return;
    if (state === 'FAILED' || state === 'CANCELLED') {
      throw new Error(`Athena query ${state}: ${result.QueryExecution?.Status?.StateChangeReason}`);
    }
    if (state !== 'QUEUED' && state !== 'RUNNING') {
      throw new Error(`Athena query returned unexpected state: ${state || 'missing'}`);
    }

    await sleep(delayMs);
  }

  throw new Error('Athena query timed out');
}

async function fetchQueryResults(
  executionId: string,
  athenaClient: AthenaClient
): Promise<CloudTrailUsageRecord[]> {
  const rows = await fetchRawRows(executionId, athenaClient);
  return rows.map((row, index) => parseResultRow(row, index + 2));
}

async function fetchRawRows(executionId: string, athenaClient: AthenaClient): Promise<Row[]> {
  const rows: Row[] = [];
  let nextToken: string | undefined;
  let isFirstRow = true;

  do {
    const response = await athenaClient.send(
      new GetQueryResultsCommand({
        QueryExecutionId: executionId,
        NextToken: nextToken,
      })
    );

    for (const row of (response.ResultSet?.Rows || []) as Row[]) {
      if (isFirstRow) {
        isFirstRow = false;
        continue;
      }
      rows.push({ Data: row.Data || [] });
    }

    nextToken = response.NextToken;
  } while (nextToken);

  return rows;
}

async function detectAnomalies(
  days: number,
  config: AnalyzerConfig,
  dependencies: AnalyzerDependencies
): Promise<number> {
  if (!config.graphWriterFunctionName.trim() && !config.graphWriterUrl.trim()) {
    logger.warn(
      'GRAPH_WRITER_FUNCTION_NAME and GRAPH_WRITER_URL are unset; skipping anomaly persistence'
    );
    return 0;
  }

  const observedAt = dependencies.now().toISOString();
  const runId = randomUUID();
  let written = 0;

  for (const anomalyQuery of buildAnomalyQueries(
    config.athenaDatabase,
    days,
    config.canaryPrincipalArns
  )) {
    const executionId = await executeAthenaQuery(
      anomalyQuery.sql,
      config,
      dependencies.athenaClient
    );
    await waitForQueryCompletion(
      executionId,
      dependencies.athenaClient,
      dependencies.sleep,
      dependencies.signal
    );
    const rows = await fetchRawRows(executionId, dependencies.athenaClient);
    // The denied-spike query returns daily counts, not finished anomalies:
    // the deviation decision (baseline mean and spread, floor, cold-start
    // fallback) runs here so it is testable against historical windows.
    const records =
      anomalyQuery.type === 'ACCESS_DENIED_SPIKE'
        ? detectDeniedSpikes(
            rows.map((row, index) => parseDeniedCountRow(row.Data || [], index + 2)),
            new Date(observedAt)
          )
        : rows.map((row, index) => parseAnomalyRow(anomalyQuery.type, row.Data || [], index + 2));
    logger.info(`Anomaly query ${anomalyQuery.type} returned ${records.length} records`);
    if (records.length === 0) continue;

    const batch: AnomalyBatch = {
      nodes: buildAnomalyNodes(records, runId, observedAt),
      observedAt,
    };
    const result = await dependencies.writeAnomalies(batch);
    written += result.written;
  }

  await dependencies.writeAnomalies({
    nodes: [],
    reconcile: reconcileAnomalies(runId, observedAt),
    observedAt,
  });

  return written;
}

export function parseResultRow(row: Row, rowNumber: number): CloudTrailUsageRecord {
  const columns = row.Data;
  if (!columns || columns.length !== 5) {
    throw new Error(`Invalid Athena result row ${rowNumber}: expected 5 columns`);
  }

  const principalArn = requiredColumn(columns[0].VarCharValue, 'principal_arn', rowNumber);
  const eventSource = requiredColumn(columns[1].VarCharValue, 'eventsource', rowNumber);
  const eventName = requiredColumn(columns[2].VarCharValue, 'eventname', rowNumber);
  const rawEventCount = requiredColumn(columns[3].VarCharValue, 'event_count', rowNumber);
  const lastUsed = requiredColumn(columns[4].VarCharValue, 'last_used', rowNumber);

  if (!/^\d+$/.test(rawEventCount)) {
    throw new Error(`Invalid Athena result row ${rowNumber}: event_count must be an integer`);
  }
  const eventCount = Number(rawEventCount);
  if (!Number.isSafeInteger(eventCount) || eventCount < 1) {
    throw new Error(`Invalid Athena result row ${rowNumber}: event_count must be positive`);
  }
  if (Number.isNaN(Date.parse(lastUsed))) {
    throw new Error(`Invalid Athena result row ${rowNumber}: last_used must be a timestamp`);
  }

  return { principalArn, eventSource, eventName, eventCount, lastUsed };
}

function requiredColumn(value: string | undefined, name: string, rowNumber: number): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`Invalid Athena result row ${rowNumber}: ${name} is required`);
  }
  return normalized;
}

async function writeResultsToDynamo(
  results: CloudTrailUsageRecord[],
  tableName: string,
  dynamoClient: DynamoDBClient,
  sleep: (milliseconds: number) => Promise<void>,
  now: () => Date
): Promise<number> {
  const timestamp = now();
  const ttl = Math.floor(timestamp.getTime() / 1000) + 90 * 86400;
  const updatedAt = timestamp.toISOString();

  for (let i = 0; i < results.length; i += BATCH_SIZE) {
    const requests = results.slice(i, i + BATCH_SIZE).map<WriteRequest>((row) => ({
      PutRequest: {
        Item: marshall({
          principalArn: row.principalArn,
          eventSourceEventName: `${row.eventSource}#${row.eventName}`,
          eventSource: row.eventSource,
          eventName: row.eventName,
          lastUsed: row.lastUsed,
          eventCount: row.eventCount,
          ttl,
          updatedAt,
        }),
      },
    }));

    await writeBatchWithRetry(requests, tableName, dynamoClient, sleep);
  }

  return results.length;
}

async function writeBatchWithRetry(
  requests: WriteRequest[],
  tableName: string,
  dynamoClient: DynamoDBClient,
  sleep: (milliseconds: number) => Promise<void>
): Promise<void> {
  let pending = requests;

  for (let attempt = 1; attempt <= MAX_BATCH_WRITE_ATTEMPTS; attempt++) {
    const response = await dynamoClient.send(
      new BatchWriteItemCommand({
        RequestItems: {
          [tableName]: pending,
        },
      })
    );
    pending = response.UnprocessedItems?.[tableName] || [];

    if (pending.length === 0) return;
    if (attempt === MAX_BATCH_WRITE_ATTEMPTS) break;

    await sleep(BATCH_WRITE_BASE_DELAY_MS * 2 ** (attempt - 1));
  }

  throw new Error(
    `DynamoDB batch write exhausted ${MAX_BATCH_WRITE_ATTEMPTS} attempts with ${pending.length} unprocessed item(s)`
  );
}
