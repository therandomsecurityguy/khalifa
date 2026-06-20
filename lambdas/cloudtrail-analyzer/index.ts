import {
  AthenaClient,
  StartQueryExecutionCommand,
  GetQueryExecutionCommand,
  GetQueryResultsCommand,
} from '@aws-sdk/client-athena';
import { DynamoDBClient, BatchWriteItemCommand } from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import { Logger } from '../shared/types';

const logger = new Logger('cloudtrail-analyzer');
const athenaClient = new AthenaClient({ region: process.env.AWS_REGION || 'us-east-1' });
const dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });

const ATHENA_DATABASE = process.env.ATHENA_DATABASE || 'khalifa_cloudtrail_db';
const ATHENA_WORKGROUP = process.env.ATHENA_WORKGROUP || 'khalifa-cloudtrail-analysis';
const CLOUDTRAIL_S3_LOCATION = process.env.CLOUDTRAIL_S3_LOCATION || '';
const ACCESS_ANALYZER_TABLE = process.env.ACCESS_ANALYZER_TABLE || 'AccessAnalyzerCache';
const ANALYSIS_DAYS = parseInt(process.env.ANALYSIS_DAYS || '90', 10);

interface AnalyzerEvent {
  days?: number;
}

export const handler = async (
  event: AnalyzerEvent = {}
): Promise<{ recordsProcessed: number; queryExecutionId: string }> => {
  const days = event.days || ANALYSIS_DAYS;
  logger.info(`Starting CloudTrail analysis for last ${days} days`);

  const queryExecutionId = await executeAthenaQuery(days);
  logger.info(`Athena query started: ${queryExecutionId}`);

  await waitForQueryCompletion(queryExecutionId);

  const results = await fetchQueryResults(queryExecutionId);
  logger.info(`Query returned ${results.length} records`);

  await writeResultsToDynamo(results);

  return { recordsProcessed: results.length, queryExecutionId };
};

async function executeAthenaQuery(days: number): Promise<string> {
  const query = `
    SELECT
      useridentity.arn AS principal_arn,
      eventsource,
      eventname,
      COUNT(*) AS event_count,
      MAX(eventtime) AS last_used
    FROM ${ATHENA_DATABASE}.cloudtrail_logs
    WHERE from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${days}' day
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

  const result = await athenaClient.send(
    new StartQueryExecutionCommand({
      QueryString: query,
      ResultConfiguration: {
        OutputLocation: `s3://${CLOUDTRAIL_S3_LOCATION}athena-results/`,
      },
      WorkGroup: ATHENA_WORKGROUP,
    })
  );

  if (!result.QueryExecutionId) {
    throw new Error('Failed to start Athena query');
  }

  return result.QueryExecutionId;
}

async function waitForQueryCompletion(executionId: string): Promise<void> {
  const maxAttempts = 60;
  const delayMs = 5000;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const result = await athenaClient.send(
      new GetQueryExecutionCommand({ QueryExecutionId: executionId })
    );

    const state = result.QueryExecution?.Status?.State;
    if (state === 'SUCCEEDED') return;
    if (state === 'FAILED' || state === 'CANCELLED') {
      throw new Error(`Athena query ${state}: ${result.QueryExecution?.Status?.StateChangeReason}`);
    }

    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }

  throw new Error('Athena query timed out');
}

async function fetchQueryResults(executionId: string): Promise<any[]> {
  const results: any[] = [];
  let nextToken: string | undefined;

  do {
    const response = await athenaClient.send(
      new GetQueryResultsCommand({
        QueryExecutionId: executionId,
        NextToken: nextToken,
      })
    );

    const rows = response.ResultSet?.Rows || [];
    if (results.length === 0 && rows.length > 0) {
      // Skip header row
    } else {
      for (const row of rows) {
        const cols = row.Data || [];
        if (cols.length >= 5) {
          results.push({
            principalArn: cols[0].VarCharValue || '',
            eventSource: cols[1].VarCharValue || '',
            eventName: cols[2].VarCharValue || '',
            eventCount: parseInt(cols[3].VarCharValue || '0', 10),
            lastUsed: cols[4].VarCharValue || '',
          });
        }
      }
    }

    nextToken = response.NextToken;
  } while (nextToken);

  return results.slice(1); // Skip header
}

async function writeResultsToDynamo(results: any[]): Promise<void> {
  const BATCH_SIZE = 25;

  for (let i = 0; i < results.length; i += BATCH_SIZE) {
    const batch = results.slice(i, i + BATCH_SIZE);

    const writeRequests = batch.map((row) => ({
      PutRequest: {
        Item: marshall({
          principalArn: row.principalArn,
          eventSourceEventName: `${row.eventSource}#${row.eventName}`,
          eventSource: row.eventSource,
          eventName: row.eventName,
          lastUsed: row.lastUsed,
          eventCount: row.eventCount,
          ttl: Math.floor(Date.now() / 1000) + 90 * 86400,
          updatedAt: new Date().toISOString(),
        }),
      },
    }));

    await dynamoClient.send(
      new BatchWriteItemCommand({
        RequestItems: {
          [ACCESS_ANALYZER_TABLE]: writeRequests,
        },
      })
    );
  }
}
