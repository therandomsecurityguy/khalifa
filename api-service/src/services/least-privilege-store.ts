import type { AttributeValue } from '@aws-sdk/client-dynamodb';
import { DynamoDBClient, QueryCommand, ScanCommand } from '@aws-sdk/client-dynamodb';
import type { QueryCommandInput, ScanCommandInput } from '@aws-sdk/lib-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import type {
  LeastPrivilegeFinding,
  LeastPrivilegeListResponse,
  LeastPrivilegeSummary,
  IamPolicyStatement,
} from '../types';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 1000;

interface FindingRecord {
  accountId?: string;
  principalArn?: string;
  principalType?: string;
  allowedActionCount?: number;
  removedActionCount?: number;
  keptActionCount?: number;
  removedActions?: string[];
  keptActions?: string[];
  recommendedPolicyJson?: string;
  riskLevel?: string;
  confidence?: number;
  isAdmin?: boolean;
  blastRadius?: number;
  lastSweptAt?: string;
}

export function parseRecommendedPolicy(json: string | undefined): IamPolicyStatement[] {
  if (!json) return [];
  try {
    return JSON.parse(json) as IamPolicyStatement[];
  } catch {
    return [];
  }
}

export function mapFindingRecord(record: FindingRecord): LeastPrivilegeFinding {
  return {
    accountId: record.accountId || '',
    principalArn: record.principalArn || '',
    principalType: record.principalType === 'user' ? 'user' : 'role',
    allowedActionCount: record.allowedActionCount || 0,
    removedActionCount: record.removedActionCount || 0,
    keptActionCount: record.keptActionCount || 0,
    removedActions: record.removedActions || [],
    keptActions: record.keptActions || [],
    recommendedPolicy: parseRecommendedPolicy(record.recommendedPolicyJson),
    riskLevel: (record.riskLevel as 'low' | 'medium' | 'high') || 'low',
    confidence: record.confidence || 0,
    isAdmin: record.isAdmin === true,
    blastRadius: record.blastRadius || 0,
    lastSweptAt: record.lastSweptAt || '',
  };
}

export class LeastPrivilegeStore {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string = process.env.LEAST_PRIVILEGE_TABLE || 'LeastPrivilegeFindings') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  async listFindings(query: {
    accountId?: string;
    riskLevel?: string;
    principalType?: string;
    limit?: number;
    nextToken?: string;
  }): Promise<LeastPrivilegeListResponse> {
    const { accountId, riskLevel, principalType, limit = DEFAULT_LIMIT, nextToken } = query;

    let scanOrQuery: QueryCommandInput | ScanCommandInput;

    if (accountId) {
      scanOrQuery = {
        TableName: this.tableName,
        KeyConditionExpression: 'accountId = :accountId',
        ExpressionAttributeValues: {
          ':accountId': { S: accountId } as AttributeValue,
        },
        Limit: Math.min(limit, MAX_LIMIT),
        ExclusiveStartKey: nextToken ? this.decodeToken(nextToken) : undefined,
      };
    } else if (riskLevel) {
      scanOrQuery = {
        TableName: this.tableName,
        IndexName: 'RiskLevelIndex',
        KeyConditionExpression: 'riskLevel = :riskLevel',
        ExpressionAttributeValues: {
          ':riskLevel': { S: riskLevel } as AttributeValue,
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

    if (principalType) {
      const filterExpr = 'principalType = :principalType';
      const values: Record<string, AttributeValue> = {
        ':principalType': { S: principalType },
      };

      if ('KeyConditionExpression' in scanOrQuery) {
        (scanOrQuery as QueryCommandInput).FilterExpression = filterExpr;
        (scanOrQuery as QueryCommandInput).ExpressionAttributeValues = {
          ...(scanOrQuery as QueryCommandInput).ExpressionAttributeValues,
          ...values,
        };
      } else {
        scanOrQuery.FilterExpression = filterExpr;
        scanOrQuery.ExpressionAttributeValues = values;
      }
    }

    if ('KeyConditionExpression' in scanOrQuery) {
      const result = await this.docClient.send(new QueryCommand(scanOrQuery));
      return this.formatResponse(result.Items, result.LastEvaluatedKey);
    } else {
      const result = await this.docClient.send(new ScanCommand(scanOrQuery));
      return this.formatResponse(result.Items, result.LastEvaluatedKey);
    }
  }

  async getFinding(accountId: string, principalArn: string): Promise<LeastPrivilegeFinding | null> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: 'accountId = :accountId AND principalArn = :principalArn',
        ExpressionAttributeValues: {
          ':accountId': { S: accountId } as AttributeValue,
          ':principalArn': { S: principalArn } as AttributeValue,
        },
      })
    );

    if (!result.Items || result.Items.length === 0) return null;
    return this.toFinding(unmarshall(result.Items[0]) as FindingRecord);
  }

  async getSummary(): Promise<LeastPrivilegeSummary> {
    const accounts = new Set<string>();
    let principalsSwept = 0;
    let totalRemovedActions = 0;
    let lastSweptAt: string | null = null;
    const byRiskLevel: Record<'low' | 'medium' | 'high', number> = {
      low: 0,
      medium: 0,
      high: 0,
    };

    let lastEvaluatedKey: Record<string, AttributeValue> | undefined;
    do {
      const result = await this.docClient.send(
        new ScanCommand({
          TableName: this.tableName,
          ExclusiveStartKey: lastEvaluatedKey,
        })
      );

      for (const item of result.Items || []) {
        const record = unmarshall(item) as FindingRecord;
        if (record.accountId) accounts.add(record.accountId);
        principalsSwept++;
        totalRemovedActions += record.removedActionCount || 0;
        if (record.lastSweptAt && (!lastSweptAt || record.lastSweptAt > lastSweptAt)) {
          lastSweptAt = record.lastSweptAt;
        }
        const level = record.riskLevel as 'low' | 'medium' | 'high';
        if (level && byRiskLevel[level] !== undefined) byRiskLevel[level]++;
      }

      lastEvaluatedKey = result.LastEvaluatedKey;
    } while (lastEvaluatedKey);

    return {
      accountsSwept: accounts.size,
      principalsSwept,
      byRiskLevel,
      totalRemovedActions,
      lastSweptAt,
    };
  }

  private formatResponse(
    items: Record<string, AttributeValue>[] | undefined,
    lastEvaluatedKey: Record<string, AttributeValue> | undefined
  ): LeastPrivilegeListResponse {
    const findings = (items || []).map((item) => this.toFinding(unmarshall(item) as FindingRecord));

    return {
      items: findings,
      nextToken: lastEvaluatedKey ? this.encodeToken(lastEvaluatedKey) : undefined,
      totalCount: findings.length,
    };
  }

  private toFinding(record: FindingRecord): LeastPrivilegeFinding {
    return mapFindingRecord(record);
  }

  private encodeToken(key: Record<string, AttributeValue>): string {
    return Buffer.from(JSON.stringify(key)).toString('base64');
  }

  private decodeToken(token: string): Record<string, AttributeValue> {
    return JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
  }
}
