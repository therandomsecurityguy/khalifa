import {
  AthenaClient,
  GetQueryExecutionCommand,
  GetQueryResultsCommand,
  StartQueryExecutionCommand,
} from '@aws-sdk/client-athena';
import { DynamoDBClient, BatchWriteItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import type { AttributeValue } from '@aws-sdk/client-dynamodb';
import { Logger } from '../shared/types';
import {
  buildTrafficQuery,
  DEFAULT_OBSERVATION_DAYS,
  MAX_OBSERVATIONS,
  parseTrafficRow,
  validateObservationDays,
  type TrafficObservation,
} from './src/queries';

// Observed reachability: VPC flow logs (ACCEPT flows) per network interface,
// written to a DynamoDB cache the collector reads when it collects instances.
// Reachability confidence becomes observed AND configured: configured exposure
// says where an attacker could reach, an accepted flow says where traffic
// actually went. Optional and cost-gated — the Glue table and the CronJob only
// exist when the operator points them at a flow-log bucket (suspend: true by
// default).
const logger = new Logger('flow-log-analyzer');
const defaultAthenaClient = new AthenaClient({
  region: process.env.AWS_REGION || 'us-east-1',
});
const defaultDynamoClient = new DynamoDBClient({
  region: process.env.AWS_REGION || 'us-east-1',
});

// Stale observations expire: the collector never reads one older than the TTL
// because the row is gone.
export const OBSERVATION_TTL_DAYS = 30;
const BATCH_SIZE = 25;
const MAX_BATCH_ATTEMPTS = 5;
const BATCH_BASE_DELAY_MS = 100;

interface AnalyzerEvent {
  days?: number;
}

interface AnalyzerConfig {
  athenaDatabase: string;
  athenaWorkgroup: string;
  athenaResultsLocation: string;
  trafficObservationsTable: string;
  observationDays: number;
}

interface Row {
  Data?: { VarCharValue?: string }[];
}

interface AnalyzerDependencies {
  athenaClient: AthenaClient;
  dynamoClient: DynamoDBClient;
  sleep: (milliseconds: number) => Promise<void>;
  now: () => Date;
  signal?: AbortSignal;
}

export interface FlowLogAnalysisResult {
  observations: number;
  truncated: boolean;
  queryExecutionId: string;
}

export function normalizeAthenaResultsLocation(value: string | undefined): string {
  const location = value?.trim();
  if (!location) throw new Error('ATHENA_RESULTS_S3_LOCATION is required');
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
  return `s3://${parsed.hostname}${parsed.pathname.replace(/\/+$/, '')}/`;
}

function loadConfig(environment: NodeJS.ProcessEnv): AnalyzerConfig {
  return {
    athenaDatabase: (environment.ATHENA_DATABASE || 'khalifa_cloudtrail_db').trim(),
    athenaWorkgroup: environment.ATHENA_WORKGROUP || 'khalifa-cloudtrail-analysis',
    athenaResultsLocation: normalizeAthenaResultsLocation(environment.ATHENA_RESULTS_S3_LOCATION),
    trafficObservationsTable: environment.TRAFFIC_OBSERVATIONS_TABLE || 'TrafficObservations',
    observationDays: validateObservationDays(
      environment.FLOW_LOG_DAYS ?? DEFAULT_OBSERVATION_DAYS,
      'FLOW_LOG_DAYS'
    ),
  };
}

export async function analyzeFlowLogs(
  event: AnalyzerEvent = {},
  dependencyOverrides: Partial<AnalyzerDependencies> = {},
  environment: NodeJS.ProcessEnv = process.env
): Promise<FlowLogAnalysisResult> {
  const dependencies: AnalyzerDependencies = {
    athenaClient: defaultAthenaClient,
    dynamoClient: defaultDynamoClient,
    sleep: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
    now: () => new Date(),
    ...dependencyOverrides,
  };
  const config = loadConfig(environment);
  const days = validateObservationDays(event.days ?? config.observationDays);
  logger.info(`Starting flow-log analysis for last ${days} days`);

  const queryExecutionId = await startQuery(
    buildTrafficQuery(config.athenaDatabase, days),
    config,
    dependencies.athenaClient
  );
  await waitForQuery(
    queryExecutionId,
    dependencies.athenaClient,
    dependencies.sleep,
    dependencies.signal
  );
  const rows = await fetchRawRows(queryExecutionId, dependencies.athenaClient);
  const parsed = rows.map((row, index) => parseTrafficRow(row.Data || [], index + 2));
  const truncated = parsed.length > MAX_OBSERVATIONS;
  if (truncated) {
    logger.warn('Traffic observations truncated', { limit: MAX_OBSERVATIONS, rows: parsed.length });
  }
  const observations = parsed.slice(0, MAX_OBSERVATIONS);

  await writeObservations(
    observations,
    days,
    config.trafficObservationsTable,
    dependencies.dynamoClient,
    dependencies.sleep,
    dependencies.now()
  );
  logger.info(`Wrote ${observations.length} traffic observations`);
  return { observations: observations.length, truncated, queryExecutionId };
}

export const handler = async (event: AnalyzerEvent = {}): Promise<FlowLogAnalysisResult> =>
  analyzeFlowLogs(event);

export function observationItems(
  observations: TrafficObservation[],
  windowDays: number,
  observedAt: Date
): Record<string, AttributeValue>[] {
  const nowSeconds = Math.floor(observedAt.getTime() / 1000);
  return observations.map(
    (observation) =>
      marshall({
        interface_id: observation.interfaceId,
        account_id: observation.accountId,
        region: observation.region,
        packets: observation.packets,
        bytes: observation.bytes,
        flows: observation.flows,
        first_seen: observation.firstSeen,
        last_seen: observation.lastSeen,
        window_days: windowDays,
        observed_at: observedAt.toISOString(),
        expires_at: nowSeconds + OBSERVATION_TTL_DAYS * 86_400,
      }) as Record<string, AttributeValue>
  );
}

async function writeObservations(
  observations: TrafficObservation[],
  windowDays: number,
  tableName: string,
  dynamoClient: DynamoDBClient,
  sleep: (milliseconds: number) => Promise<void>,
  observedAt: Date
): Promise<void> {
  const items = observationItems(observations, windowDays, observedAt);
  for (let index = 0; index < items.length; index += BATCH_SIZE) {
    const batch = items.slice(index, index + BATCH_SIZE);
    let attempt = 0;
    for (;;) {
      attempt += 1;
      try {
        const result = await dynamoClient.send(
          new BatchWriteItemCommand({
            RequestItems: {
              [tableName]: batch.map((Item) => ({ PutRequest: { Item } })),
            },
          })
        );
        const unprocessed = result.UnprocessedItems?.[tableName] ?? [];
        if (unprocessed.length === 0) break;
        if (attempt >= MAX_BATCH_ATTEMPTS) {
          throw new Error(
            `DynamoDB left ${unprocessed.length} traffic observations unprocessed after ${attempt} attempts`
          );
        }
        await sleep(BATCH_BASE_DELAY_MS * 2 ** (attempt - 1));
      } catch (error) {
        if (attempt >= MAX_BATCH_ATTEMPTS) throw error;
        await sleep(BATCH_BASE_DELAY_MS * 2 ** (attempt - 1));
      }
    }
  }
}

async function startQuery(
  query: string,
  config: AnalyzerConfig,
  athenaClient: AthenaClient
): Promise<string> {
  const result = await athenaClient.send(
    new StartQueryExecutionCommand({
      QueryString: query,
      ResultConfiguration: { OutputLocation: config.athenaResultsLocation },
      WorkGroup: config.athenaWorkgroup,
    })
  );
  if (!result.QueryExecutionId) {
    throw new Error('Failed to start Athena query: response did not include a query execution ID');
  }
  return result.QueryExecutionId;
}

async function waitForQuery(
  executionId: string,
  athenaClient: AthenaClient,
  sleep: (milliseconds: number) => Promise<void>,
  signal?: AbortSignal
): Promise<void> {
  const maxAttempts = 50;
  const delayMs = 5000;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (signal?.aborted) throw new Error('Flow-log analysis aborted');
    const result = await athenaClient.send(
      new GetQueryExecutionCommand({ QueryExecutionId: executionId })
    );
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

async function fetchRawRows(executionId: string, athenaClient: AthenaClient): Promise<Row[]> {
  const rows: Row[] = [];
  let nextToken: string | undefined;
  let isFirstRow = true;
  do {
    const response = await athenaClient.send(
      new GetQueryResultsCommand({ QueryExecutionId: executionId, NextToken: nextToken })
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
