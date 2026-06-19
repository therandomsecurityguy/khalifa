import type { AttributeValue } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
  ScanCommand,
} from '@aws-sdk/client-dynamodb';
import type { QueryCommandInput, ScanCommandInput } from '@aws-sdk/lib-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import type { Issue, IssueListQuery, IssueListResponse, Severity } from '../types';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 1000;

export class IssueStore {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string = process.env.ISSUES_TABLE || 'SecurityIssues') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  async getIssue(id: string): Promise<Issue | null> {
    const result = await this.docClient.send(
      new GetItemCommand({
        TableName: this.tableName,
        Key: { id: { S: id } } as Record<string, AttributeValue>,
      })
    );

    if (!result.Item) {
      return null;
    }

    return unmarshall(result.Item) as Issue;
  }

  async listIssues(query: IssueListQuery): Promise<IssueListResponse> {
    const { severity, team, status, ruleId, limit = DEFAULT_LIMIT, nextToken } = query;

    let scanOrQuery: QueryCommandInput | ScanCommandInput;

    if (ruleId) {
      scanOrQuery = {
        TableName: this.tableName,
        IndexName: 'RuleIdIndex',
        KeyConditionExpression: 'ruleId = :ruleId',
        ExpressionAttributeValues: {
          ':ruleId': { S: ruleId } as AttributeValue,
        },
        Limit: Math.min(limit, MAX_LIMIT),
        ExclusiveStartKey: nextToken ? this.decodeToken(nextToken) : undefined,
      };
    } else {
      scanOrQuery = {
        TableName: this.tableName,
        Limit: Math.min(limit, MAX_LIMIT),
        ExclusiveStartKey: nextToken ? this.decodeToken(nextToken) : undefined,
      };
    }

    const filterExpressions: string[] = [];
    const expressionAttrValues: Record<string, AttributeValue> = {};

    if (severity && severity.length > 0) {
      const severityPlaceholders = severity.map((_, i) => `:severity${i}`).join(', ');
      filterExpressions.push(`severity IN (${severityPlaceholders})`);
      severity.forEach((s, i) => {
        expressionAttrValues[`:severity${i}`] = { S: s };
      });
    }

    if (team && team.length > 0) {
      const teamPlaceholders = team.map((_, i) => `:team${i}`).join(', ');
      filterExpressions.push(`owningTeam IN (${teamPlaceholders})`);
      team.forEach((t, i) => {
        expressionAttrValues[`:team${i}`] = { S: t };
      });
    }

    if (status && status.length > 0) {
      const statusPlaceholders = status.map((_, i) => `:status${i}`).join(', ');
      filterExpressions.push(`#status IN (${statusPlaceholders})`);
      status.forEach((s, i) => {
        expressionAttrValues[`:status${i}`] = { S: s };
      });
    }

    if (filterExpressions.length > 0) {
      const filterExpr = filterExpressions.join(' AND ');
      const isQuery = 'KeyConditionExpression' in scanOrQuery;

      if (isQuery) {
        (scanOrQuery as QueryCommandInput).FilterExpression = filterExpr;
        (scanOrQuery as QueryCommandInput).ExpressionAttributeValues = {
          ...(scanOrQuery as QueryCommandInput).ExpressionAttributeValues,
          ...expressionAttrValues,
        };
      } else {
        scanOrQuery.FilterExpression = filterExpr;
        scanOrQuery.ExpressionAttributeValues = expressionAttrValues;
      }
    }

    if ('KeyConditionExpression' in scanOrQuery) {
      const result = await this.docClient.send(new QueryCommand(scanOrQuery));
      return this.formatQueryResponse(result);
    } else {
      const result = await this.docClient.send(new ScanCommand(scanOrQuery));
      return this.formatScanResponse(result);
    }
  }

  async getIssuesByRule(ruleId: string): Promise<Issue[]> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        IndexName: 'RuleIdIndex',
        KeyConditionExpression: 'ruleId = :ruleId',
        ExpressionAttributeValues: {
          ':ruleId': { S: ruleId } as AttributeValue,
        },
      })
    );

    if (!result.Items) {
      return [];
    }

    return result.Items.map((item: Record<string, AttributeValue>) => unmarshall(item) as Issue);
  }

  async getOpenIssuesByResourceArn(arn: string): Promise<Issue[]> {
    const result = await this.docClient.send(
      new ScanCommand({
        TableName: this.tableName,
        FilterExpression: 'contains(resourcesInvolved, :arn) AND #status = :status',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: {
          ':arn': { S: arn } as AttributeValue,
          ':status': { S: 'open' } as AttributeValue,
        },
      })
    );

    if (!result.Items) {
      return [];
    }

    return result.Items.map((item: Record<string, AttributeValue>) => unmarshall(item) as Issue);
  }

  async getTotalCounts(): Promise<Record<Severity, number>> {
    const counts: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    for (const severity of Object.keys(counts) as Severity[]) {
      const result = await this.docClient.send(
        new ScanCommand({
          TableName: this.tableName,
          FilterExpression: '#severity = :severity AND #status = :status',
          ExpressionAttributeNames: {
            '#severity': 'severity',
            '#status': 'status',
          },
          ExpressionAttributeValues: {
            ':severity': { S: severity } as AttributeValue,
            ':status': { S: 'open' } as AttributeValue,
          },
          Select: 'COUNT',
        })
      );

      counts[severity] = result.Count || 0;
    }

    return counts;
  }

  private formatQueryResponse(result: {
    Items?: Record<string, AttributeValue>[];
    LastEvaluatedKey?: Record<string, AttributeValue>;
  }): IssueListResponse {
    const items = result.Items?.map((item) => unmarshall(item) as Issue) || [];

    return {
      items,
      nextToken: result.LastEvaluatedKey ? this.encodeToken(result.LastEvaluatedKey) : undefined,
      totalCount: items.length,
    };
  }

  private formatScanResponse(result: {
    Items?: Record<string, AttributeValue>[];
    LastEvaluatedKey?: Record<string, AttributeValue>;
    ScannedCount?: number;
  }): IssueListResponse {
    const items = result.Items?.map((item) => unmarshall(item) as Issue) || [];

    return {
      items,
      nextToken: result.LastEvaluatedKey ? this.encodeToken(result.LastEvaluatedKey) : undefined,
      totalCount: result.ScannedCount || items.length,
    };
  }

  private encodeToken(key: Record<string, AttributeValue>): string {
    return Buffer.from(JSON.stringify(key)).toString('base64');
  }

  private decodeToken(token: string): Record<string, AttributeValue> {
    return JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
  }
}
