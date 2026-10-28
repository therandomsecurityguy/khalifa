import {
  DynamoDBClient,
  PutItemCommand,
  QueryCommand,
  UpdateItemCommand,
} from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import type { AttributeValue } from '@aws-sdk/client-dynamodb';

export type TrendMetric =
  | 'openIssuesBySeverity'
  | 'publicBuckets'
  | 'usersWithoutMfa'
  | 'crossAccountTrusts'
  | 'issuesCreated'
  | 'issuesResolved'
  | 'openRiskScore'
  | 'mttrHours'
  | 'adminPrincipals'
  | 'sloBurning'
  | 'exposedByType';

export interface PostureTrendPoint {
  metric: string;
  date: string;
  value: number;
  accountIds?: string[];
  sample?: Record<string, unknown>;
  recordedAt: string;
}

export class PostureTrendStore {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string = process.env.POSTURE_TRENDS_TABLE || 'PostureTrends') {
    const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  async record(
    metric: TrendMetric,
    value: number,
    accountIds?: string[],
    sample?: Record<string, unknown>
  ): Promise<void> {
    const date = new Date().toISOString().slice(0, 10);
    await this.docClient.send(
      new PutItemCommand({
        TableName: this.tableName,
        Item: marshall({
          metric,
          date,
          value,
          accountIds: accountIds || [],
          sample: sample || {},
          recordedAt: new Date().toISOString(),
        }) as Record<string, AttributeValue>,
      })
    );
  }

  async recordMany(
    points: {
      metric: TrendMetric;
      value: number;
      accountIds?: string[];
      sample?: Record<string, unknown>;
    }[]
  ): Promise<void> {
    for (const point of points) {
      await this.record(point.metric, point.value, point.accountIds, point.sample);
    }
  }

  // One row per metric per day, and the runner runs several times a day, so a
  // put would keep only the last run. ADD sums every run into the day's row.
  async increment(metric: TrendMetric, amount: number): Promise<void> {
    const date = new Date().toISOString().slice(0, 10);
    await this.docClient.send(
      new UpdateItemCommand({
        TableName: this.tableName,
        Key: marshall({ metric, date }) as Record<string, AttributeValue>,
        UpdateExpression:
          'ADD #value :amount SET recordedAt = :recordedAt, accountIds = if_not_exists(accountIds, :noAccounts)',
        ExpressionAttributeNames: { '#value': 'value' },
        ExpressionAttributeValues: marshall({
          ':amount': amount,
          ':recordedAt': new Date().toISOString(),
          ':noAccounts': [],
        }) as Record<string, AttributeValue>,
      })
    );
  }

  // The newest row for a metric; recordedAt is when the last run wrote it.
  async getLatest(metric: TrendMetric): Promise<PostureTrendPoint | null> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: '#metric = :metric',
        ExpressionAttributeNames: { '#metric': 'metric' },
        ExpressionAttributeValues: { ':metric': { S: metric } },
        ScanIndexForward: false,
        Limit: 1,
      })
    );
    const item = result.Items?.[0];
    return item ? (unmarshall(item) as PostureTrendPoint) : null;
  }

  async getSeries(metric: TrendMetric, days = 90): Promise<PostureTrendPoint[]> {
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: '#metric = :metric AND #date >= :startDate',
        ExpressionAttributeNames: {
          '#metric': 'metric',
          '#date': 'date',
        },
        ExpressionAttributeValues: {
          ':metric': { S: metric },
          ':startDate': { S: startDate },
        },
        ScanIndexForward: true,
      })
    );

    if (!result.Items) return [];
    return result.Items.map((item) => unmarshall(item) as PostureTrendPoint);
  }
}
