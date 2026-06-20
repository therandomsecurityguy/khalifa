import type { AttributeValue } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
  QueryCommand,
} from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import { riskRules, getEnabledRules } from './rules';
import { computeRiskScore, getRemediationHint } from './scoring';
import type {
  RiskRule,
  Issue,
  IssueStatus,
  RuleExecutionResult,
  RiskScoreInput,
  GraphVertex,
} from './types';

const MAX_PAGINATION_BATCH = 100;
const ISSUES_TABLE = process.env.ISSUES_TABLE || 'SecurityIssues';

interface NeptuneClient {
  connect(): Promise<void>;
  close(): Promise<void>;
  executeQuery(query: string, bindings?: Record<string, any>): Promise<any[]>;
}

class GremlinNeptuneClient implements NeptuneClient {
  private client: any;
  private endpoint: string;

  constructor(endpoint: string) {
    this.endpoint = endpoint;
  }

  async connect(): Promise<void> {
    const Gremlin = await import('gremlin');
    this.client = new Gremlin.driver.DriverRemoteConnection(`wss://${this.endpoint}/gremlin`, {
      traversalSource: 'g',
    });
  }

  async close(): Promise<void> {
    if (this.client) {
      await this.client.close();
    }
  }

  async executeQuery(query: string, bindings: Record<string, any> = {}): Promise<any[]> {
    const results: any[] = [];
    let hasMore = true;

    while (hasMore) {
      const cursor = await this.client.submit(query, bindings);
      const batch: any[] = [];

      // eslint-disable-next-line no-constant-condition
      while (true) {
        const item = await cursor.next();
        if (!item) break;
        batch.push(item);
      }

      results.push(...batch);

      if (batch.length < MAX_PAGINATION_BATCH) {
        hasMore = false;
      }
    }

    return results;
  }
}

class DynamoDBIssueStore {
  private docClient: DynamoDBDocumentClient;

  constructor() {
    const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
    this.docClient = DynamoDBDocumentClient.from(client);
  }

  generateIssueId(ruleId: string, resourceIds: string[]): string {
    const resourceSet = resourceIds.slice(0, 3).sort().join('|');
    const hash = Buffer.from(`${ruleId}:${resourceSet}`).toString('base64').slice(0, 16);
    return `${ruleId}-${hash}`;
  }

  async getIssue(issueId: string): Promise<Issue | null> {
    const result = await this.docClient.send(
      new GetItemCommand({
        TableName: ISSUES_TABLE,
        Key: { id: { S: issueId } } as Record<string, AttributeValue>,
      })
    );

    if (!result.Item) return null;
    return unmarshall(result.Item) as Issue;
  }

  async getIssueByRuleAndResources(ruleId: string, resourceIds: string[]): Promise<Issue | null> {
    const issueId = this.generateIssueId(ruleId, resourceIds);
    return this.getIssue(issueId);
  }

  async upsertIssue(issue: Issue): Promise<void> {
    await this.docClient.send(
      new PutItemCommand({
        TableName: ISSUES_TABLE,
        Item: marshall(issue) as Record<string, AttributeValue>,
        ConditionExpression: 'attribute_not_exists(id)',
      })
    );
  }

  async updateIssueStatus(issueId: string, status: IssueStatus): Promise<void> {
    await this.docClient.send(
      new UpdateItemCommand({
        TableName: ISSUES_TABLE,
        Key: { id: { S: issueId } } as Record<string, AttributeValue>,
        UpdateExpression: 'SET #status = :status, updatedAt = :updatedAt',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':status': { S: status },
          ':updatedAt': { S: new Date().toISOString() },
        },
      })
    );
  }

  async getOpenIssuesByRule(ruleId: string): Promise<Issue[]> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: ISSUES_TABLE,
        IndexName: 'RuleIdIndex',
        KeyConditionExpression: 'ruleId = :ruleId',
        FilterExpression: '#status = :status',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':ruleId': { S: ruleId },
          ':status': { S: 'open' },
        },
      })
    );

    if (!result.Items) return [];
    return result.Items.map((item) => unmarshall(item) as Issue);
  }
}

export class RiskRuleRunner {
  private neptuneClient: NeptuneClient;
  private issueStore: DynamoDBIssueStore;

  constructor(neptuneEndpoint: string) {
    this.neptuneClient = new GremlinNeptuneClient(neptuneEndpoint);
    this.issueStore = new DynamoDBIssueStore();
  }

  async initialize(): Promise<void> {
    await this.neptuneClient.connect();
  }

  async shutdown(): Promise<void> {
    await this.neptuneClient.close();
  }

  async runRule(rule: RiskRule): Promise<RuleExecutionResult> {
    const startTime = Date.now();
    const errors: string[] = [];
    let issuesCreated = 0;
    let issuesResolved = 0;

    try {
      const results = await this.neptuneClient.executeQuery(rule.gremlinQueryTemplate);

      const activeIssueIds = new Set<string>();

      for (const match of results) {
        const path = this.extractPathFromMatch(match);
        const resources = this.extractResourcesFromPath(path);

        if (resources.length === 0) continue;

        const existingIssue = await this.issueStore.getIssueByRuleAndResources(
          rule.id,
          resources.map((r) => r.resourceId)
        );

        if (existingIssue) {
          activeIssueIds.add(existingIssue.id);
        } else {
          const issue = await this.createIssueFromMatch(rule, path, resources);
          await this.issueStore.upsertIssue(issue);
          issuesCreated++;
          activeIssueIds.add(issue.id);
        }
      }

      const openIssues = await this.issueStore.getOpenIssuesByRule(rule.id);
      for (const issue of openIssues) {
        if (!activeIssueIds.has(issue.id)) {
          await this.issueStore.updateIssueStatus(issue.id, 'resolved');
          issuesResolved++;
        }
      }
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }

    return {
      ruleId: rule.id,
      executionTime: Date.now() - startTime,
      matches: [],
      issuesCreated,
      issuesResolved,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  async runAllRules(): Promise<RuleExecutionResult[]> {
    const rules = getEnabledRules();
    const results: RuleExecutionResult[] = [];

    for (const rule of rules) {
      const result = await this.runRule(rule);
      results.push(result);
    }

    return results;
  }

  private extractPathFromMatch(match: any): GraphVertex[] {
    if (match.objects) {
      return match.objects.map((obj: any) => ({
        id: obj.id?.value || obj.id,
        label: obj.label,
        properties: this.extractProperties(obj),
      }));
    }

    if (Array.isArray(match)) {
      return match.map((item: any) => ({
        id: item?.id?.value || item?.id,
        label: item?.label || 'unknown',
        properties: this.extractProperties(item),
      }));
    }

    return [];
  }

  private extractProperties(obj: any): Record<string, any> {
    if (!obj) return {};

    const properties: Record<string, any> = {};
    for (const [key, value] of Object.entries(obj)) {
      if (key !== 'id' && key !== 'label') {
        const val = value as any;
        properties[key] = val?.value ?? val;
      }
    }
    return properties;
  }

  private extractResourcesFromPath(
    path: GraphVertex[]
  ): { resourceId: string; resourceType: string; resourceName?: string }[] {
    return path
      .filter((v) => v.label && !['Internet', 'IAMRole', 'IAMPolicy'].includes(v.label))
      .map((v) => ({
        resourceId: v.id,
        resourceType: v.label,
        resourceName: v.properties?.name || v.properties?.Name,
      }));
  }

  private async createIssueFromMatch(
    rule: RiskRule,
    path: GraphVertex[],
    resources: { resourceId: string; resourceType: string; resourceName?: string }[]
  ): Promise<Issue> {
    const now = new Date().toISOString();

    const riskInput = this.buildRiskInput(rule, path, resources);
    const scoreResult = computeRiskScore(riskInput);

    const pathSegments = path.slice(0, -1).map((from, i) => ({
      from: from.id,
      to: path[i + 1].id,
      edgeType: path[i + 1].label,
    }));

    return {
      id: this.issueStore.generateIssueId(
        rule.id,
        resources.map((r) => r.resourceId)
      ),
      ruleId: rule.id,
      resourcesInvolved: resources.map((r) => ({
        resourceId: r.resourceId,
        resourceType: r.resourceType,
        resourceName: r.resourceName,
      })),
      pathSummary: pathSegments,
      riskScore: scoreResult.score,
      severity: scoreResult.severity,
      status: 'open',
      createdAt: now,
      updatedAt: now,
      owningTeam: rule.ownerTeam,
      remediationHint: getRemediationHint(rule.id, {}),
      metadata: {
        scoringFactors: scoreResult.factors,
        ruleName: rule.name,
      },
    };
  }

  private buildRiskInput(
    rule: RiskRule,
    path: GraphVertex[],
    resources: { resourceId: string; resourceType: string }[]
  ): RiskScoreInput {
    let exposureLevel: 'internet' | 'cross-account' | 'internal' = 'internal';
    let dataClassification: 'public' | 'internal' | 'restricted' | 'secret' = 'public';
    let environment: 'prod' | 'staging' | 'dev' = 'dev';
    let isCrownJewel = false;
    const attackPathLength = path.length;

    for (const v of path) {
      if (v.properties?.isInternetExposed === true) {
        exposureLevel = 'internet';
      }
      if (
        v.properties?.data_classification === 'restricted' ||
        v.properties?.data_classification === 'secret'
      ) {
        dataClassification = v.properties.data_classification;
      }
      if (v.properties?.crown_jewel === true) {
        isCrownJewel = true;
      }
      if (v.properties?.env === 'prod') {
        environment = 'prod';
      } else if (v.properties?.env === 'staging' && environment !== 'prod') {
        environment = 'staging';
      }
    }

    return {
      exposureLevel,
      dataClassification,
      environment,
      isCrownJewel,
      attackPathLength,
    };
  }
}

export async function resolveStaleIssues(neptuneEndpoint: string): Promise<number> {
  const runner = new RiskRuleRunner(neptuneEndpoint);
  await runner.initialize();

  let resolvedCount = 0;

  try {
    for (const rule of getEnabledRules()) {
      const result = await runner.runRule(rule);
      resolvedCount += result.issuesResolved;
    }
  } finally {
    await runner.shutdown();
  }

  return resolvedCount;
}
