import { createHash } from 'node:crypto';
import type { RuleStatusCounts } from './rule-quality';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  ScanCommand,
  UpdateCommand,
  type QueryCommandInput,
  type ScanCommandInput,
} from '@aws-sdk/lib-dynamodb';
import type { Environment, ExternalRef, Issue, IssueStatus, Severity, StatusChange } from './types';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 1000;
// Items read per DynamoDB request while filling a page, and requests per page.
const LIST_READ_SIZE = 500;
const MAX_LIST_READS = 20;
const ISSUE_ID_VERSION = 'v2';
// Keeps a flapping issue's history well under DynamoDB's 400 KB item limit.
export const STATUS_HISTORY_LIMIT = 50;
export const SYSTEM_ACTOR = 'khalifa';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const ISSUE_STATUSES: IssueStatus[] = ['open', 'suppressed', 'resolved'];

export type SeverityStatusCounts = Record<Severity, Record<IssueStatus, number>>;

export interface StatusChangeInput {
  by: string;
  reason: string;
}

export interface SuppressionInput extends StatusChangeInput {
  until: string;
}

export interface IssueKey {
  id: string;
  ruleId: string;
}

export interface IssueListQuery {
  severity?: Severity[];
  team?: string[];
  env?: Environment[];
  status?: IssueStatus[];
  ruleId?: string;
  // Several rules cannot use the rule index, so they filter a scan instead.
  ruleIds?: string[];
  // Orders by createdAt through StatusCreatedIndex; unset keeps index order.
  order?: IssueOrder;
  limit?: number;
  nextToken?: string;
}

export type IssueOrder = 'asc' | 'desc';

type CreatedKey = { id: string; ruleId: string; status: IssueStatus; createdAt: string };
// Per status: the key to resume after, null to start, or 'done'.
type CreatedCursor = Partial<Record<IssueStatus, CreatedKey | null | 'done'>>;

export interface IssueListResponse {
  items: Issue[];
  nextToken?: string;
  totalCount: number;
}

export interface IssueRepositoryOptions {
  tableName?: string;
  client?: DynamoDBDocumentClient;
  now?: () => Date;
}

export class DynamoDBIssueRepository {
  private readonly docClient: DynamoDBDocumentClient;
  private readonly tableName: string;
  private readonly now: () => Date;

  constructor(options: IssueRepositoryOptions = {}) {
    this.tableName = options.tableName || process.env.ISSUES_TABLE || 'SecurityIssues';
    this.docClient =
      options.client ||
      DynamoDBDocumentClient.from(
        new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' }),
        { marshallOptions: { removeUndefinedValues: true } }
      );
    this.now = options.now || (() => new Date());
  }

  generateIssueId(ruleId: string, resourceIds: string[]): string {
    const resources = canonicalValues(resourceIds);
    if (!ruleId.trim() || resources.length === 0) {
      throw new Error('Issue identity requires a rule ID and at least one resource ID');
    }
    const hash = createHash('sha256')
      .update(JSON.stringify([ISSUE_ID_VERSION, ruleId.trim(), resources]))
      .digest('hex')
      .slice(0, 32);
    return `${ruleId.trim()}-${ISSUE_ID_VERSION}-${hash}`;
  }

  async getIssue(key: IssueKey): Promise<Issue | null> {
    const result = await this.docClient.send(
      new GetCommand({
        TableName: this.tableName,
        Key: key,
        ConsistentRead: true,
      })
    );
    return result.Item ? this.normalizeIssue(result.Item) : null;
  }

  async getIssueById(id: string): Promise<Issue | null> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: '#id = :id',
        ExpressionAttributeNames: { '#id': 'id' },
        ExpressionAttributeValues: { ':id': id },
        ConsistentRead: true,
        Limit: 2,
      })
    );
    const items = result.Items || [];
    if (items.length > 1) {
      throw new Error(`Issue ID is not unique: ${id}`);
    }
    return items.length === 1 ? this.normalizeIssue(items[0]) : null;
  }

  async getIssueByRuleAndResources(ruleId: string, resourceIds: string[]): Promise<Issue | null> {
    const current = await this.getIssue({
      id: this.generateIssueId(ruleId, resourceIds),
      ruleId,
    });
    if (current) return current;

    const wanted = canonicalValues(resourceIds);
    const legacy = (
      await this.queryAll({
        TableName: this.tableName,
        IndexName: 'RuleIdIndex',
        KeyConditionExpression: '#ruleId = :ruleId',
        ExpressionAttributeNames: { '#ruleId': 'ruleId' },
        ExpressionAttributeValues: { ':ruleId': ruleId },
      })
    ).filter((issue) =>
      sameValues(
        canonicalValues(issue.resourcesInvolved.map((resource) => resource.resourceId)),
        wanted
      )
    );
    if (legacy.length > 1) throw new Error(`Issue identity is ambiguous for rule: ${ruleId}`);
    return legacy[0] || null;
  }

  async createIssue(issue: Issue): Promise<boolean> {
    try {
      await this.docClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: issue,
          ConditionExpression: 'attribute_not_exists(#id) AND attribute_not_exists(#ruleId)',
          ExpressionAttributeNames: { '#id': 'id', '#ruleId': 'ruleId' },
        })
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) return false;
      throw error;
    }
  }

  async updateIssue(issue: Issue): Promise<boolean> {
    try {
      await this.docClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: this.keyFor(issue),
          UpdateExpression:
            'SET #resources = :resources, #riskScore = :riskScore, #severity = :severity, ' +
            '#pathSummary = :pathSummary, #metadata = :metadata, #updatedAt = :updatedAt, ' +
            '#externalRefs = :externalRefs, #owningTeam = :owningTeam, #remediationHint = :remediationHint',
          ConditionExpression:
            'attribute_exists(#id) AND attribute_exists(#ruleId) AND #status <> :resolved',
          ExpressionAttributeNames: {
            '#id': 'id',
            '#ruleId': 'ruleId',
            '#resources': 'resourcesInvolved',
            '#riskScore': 'riskScore',
            '#severity': 'severity',
            '#pathSummary': 'pathSummary',
            '#metadata': 'metadata',
            '#updatedAt': 'updatedAt',
            '#externalRefs': 'externalRefs',
            '#owningTeam': 'owningTeam',
            '#remediationHint': 'remediationHint',
            '#status': 'status',
          },
          ExpressionAttributeValues: {
            ':resources': issue.resourcesInvolved,
            ':riskScore': issue.riskScore,
            ':severity': issue.severity,
            ':pathSummary': issue.pathSummary,
            ':metadata': issue.metadata,
            ':updatedAt': issue.updatedAt,
            ':externalRefs': issue.externalRefs || [],
            ':owningTeam': issue.owningTeam,
            ':remediationHint': issue.remediationHint,
            ':resolved': 'resolved',
          },
        })
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) return false;
      throw error;
    }
  }

  async updateExternalRefs(key: IssueKey, refs: ExternalRef[]): Promise<boolean> {
    return this.updateExisting(
      key,
      'SET #externalRefs = :externalRefs, #updatedAt = :updatedAt',
      { '#externalRefs': 'externalRefs', '#updatedAt': 'updatedAt' },
      { ':externalRefs': refs, ':updatedAt': this.now().toISOString() }
    );
  }

  async suppressIssue(issue: Issue, change: SuppressionInput): Promise<boolean> {
    const at = this.now().toISOString();
    return this.transition(issue, 'suppressed', ['open'], change, at, {
      set: {
        suppression: {
          by: change.by,
          at,
          reason: change.reason,
          until: change.until,
          severity: issue.severity,
        },
      },
      remove: ['resolvedAt', 'resolvedReason'],
    });
  }

  async reopenIssue(issue: Issue, change: StatusChangeInput): Promise<boolean> {
    return this.transition(
      issue,
      'open',
      ['suppressed', 'resolved'],
      change,
      this.now().toISOString(),
      {
        remove: ['suppression', 'resolvedAt', 'resolvedReason'],
      }
    );
  }

  async resolveIssue(issue: Issue, change: StatusChangeInput): Promise<boolean> {
    const at = this.now().toISOString();
    return this.transition(issue, 'resolved', ['open', 'suppressed'], change, at, {
      set: { resolvedAt: at, resolvedReason: change.reason },
      remove: ['suppression'],
    });
  }

  // DynamoDB applies Limit before FilterExpression, so one read of `limit` items
  // can return few or no matches. Keep reading until the page is full, and
  // resume after the last issue returned rather than the last item read.
  async listIssues(query: IssueListQuery): Promise<IssueListResponse> {
    if (query.order) {
      try {
        return await this.listIssuesByCreated(query, query.order);
      } catch (error) {
        // Until StatusCreatedIndex is built, the first page falls back to index order.
        if (query.nextToken || !isMissingIndex(error)) throw error;
        return this.listIssues({ ...query, order: undefined });
      }
    }
    const limit = pageLimit(query.limit);
    const status = query.status?.length === 1 ? query.status[0] : undefined;
    const index = query.ruleId ? 'rule' : status ? 'status' : 'table';
    const request: QueryCommandInput | ScanCommandInput =
      index === 'rule'
        ? {
            TableName: this.tableName,
            IndexName: 'RuleIdIndex',
            KeyConditionExpression: '#ruleId = :ruleId',
            ExpressionAttributeNames: { '#ruleId': 'ruleId' },
            ExpressionAttributeValues: { ':ruleId': query.ruleId },
            ScanIndexForward: false,
          }
        : index === 'status'
          ? {
              TableName: this.tableName,
              IndexName: 'StatusIndex',
              KeyConditionExpression: '#status = :statusKey',
              ExpressionAttributeNames: { '#status': 'status' },
              ExpressionAttributeValues: { ':statusKey': status },
              ScanIndexForward: false,
            }
          : { TableName: this.tableName };
    this.addListFilters(request, index === 'status' ? { ...query, status: undefined } : query);

    // A resume token is the key of the last issue returned, in the shape the
    // chosen index expects.
    const keyOf = (issue: Issue): Record<string, unknown> => ({
      id: issue.id,
      ruleId: issue.ruleId,
      ...(index === 'table' ? {} : { updatedAt: issue.updatedAt }),
      ...(index === 'status' ? { status: issue.status } : {}),
    });

    const items: Issue[] = [];
    let startKey = query.nextToken ? this.decodeToken(query.nextToken) : undefined;
    for (let reads = 0; reads < MAX_LIST_READS; reads++) {
      const page = { ...request, Limit: LIST_READ_SIZE, ExclusiveStartKey: startKey };
      const result =
        index === 'table'
          ? await this.docClient.send(new ScanCommand(page as ScanCommandInput))
          : await this.docClient.send(new QueryCommand(page as QueryCommandInput));
      for (const raw of result.Items || []) {
        items.push(this.normalizeIssue(raw));
        if (items.length === limit) {
          return { items, nextToken: this.encodeToken(keyOf(items[limit - 1])), totalCount: limit };
        }
      }
      startKey = result.LastEvaluatedKey;
      if (!startKey) break;
    }
    // Stopped short of a full page: either the end, or the read budget ran out
    // and the caller can continue from where reading stopped.
    return {
      items,
      nextToken: startKey ? this.encodeToken(startKey) : undefined,
      totalCount: items.length,
    };
  }

  // Each status is its own index partition. Reading them in createdAt order and
  // merging their heads keeps one order across statuses and across pages.
  private async listIssuesByCreated(
    query: IssueListQuery,
    order: IssueOrder
  ): Promise<IssueListResponse> {
    const limit = pageLimit(query.limit);
    const statuses = ISSUE_STATUSES.filter(
      (status) => !query.status?.length || query.status.includes(status)
    );
    const cursor = query.nextToken ? decodeCreatedToken(query.nextToken, order, statuses) : {};
    const filters: IssueListQuery = {
      ...query,
      status: undefined,
      ruleId: undefined,
      ruleIds: query.ruleId ? [query.ruleId] : query.ruleIds,
    };
    const lanes = statuses
      .filter((status) => cursor[status] !== 'done')
      .map((status) => {
        const start = cursor[status] || undefined;
        return {
          status,
          start,
          next: start as Record<string, unknown> | undefined,
          buffer: [] as Issue[],
          exhausted: false,
          last: undefined as CreatedKey | undefined,
        };
      });

    const items: Issue[] = [];
    let reads = 0;
    while (items.length < limit) {
      const empty = lanes.find((lane) => lane.buffer.length === 0 && !lane.exhausted);
      if (empty) {
        if (reads === MAX_LIST_READS) break;
        reads += 1;
        const request: QueryCommandInput = {
          TableName: this.tableName,
          IndexName: 'StatusCreatedIndex',
          KeyConditionExpression: '#status = :statusKey',
          ExpressionAttributeNames: { '#status': 'status' },
          ExpressionAttributeValues: { ':statusKey': empty.status },
          ScanIndexForward: order === 'asc',
          Limit: LIST_READ_SIZE,
          ExclusiveStartKey: empty.next,
        };
        this.addListFilters(request, filters);
        const result = await this.docClient.send(new QueryCommand(request));
        for (const raw of result.Items || []) empty.buffer.push(this.normalizeIssue(raw));
        empty.next = result.LastEvaluatedKey;
        empty.exhausted = !empty.next;
        continue;
      }
      const ready = lanes.filter((lane) => lane.buffer.length > 0);
      if (ready.length === 0) break;
      const lane = ready.reduce((best, candidate) =>
        (
          order === 'asc'
            ? candidate.buffer[0].createdAt < best.buffer[0].createdAt
            : candidate.buffer[0].createdAt > best.buffer[0].createdAt
        )
          ? candidate
          : best
      );
      const issue = lane.buffer.shift()!;
      lane.last = createdKey(issue);
      items.push(issue);
    }

    // A lane resumes after its last returned issue; an emptied lane resumes
    // where reading stopped, so filtered-out reads are not repeated.
    const next: CreatedCursor = Object.fromEntries(
      statuses.filter((status) => cursor[status] === 'done').map((status) => [status, 'done'])
    );
    for (const lane of lanes) {
      next[lane.status] =
        lane.buffer.length > 0
          ? lane.last || lane.start || null
          : lane.exhausted
            ? 'done'
            : lane.next
              ? createdKey(lane.next)
              : null;
    }
    const more = Object.values(next).some((position) => position !== 'done');
    return {
      items,
      nextToken: more ? this.encodeToken({ o: order, c: next }) : undefined,
      totalCount: items.length,
    };
  }

  async getOpenIssuesByRule(ruleId: string): Promise<Issue[]> {
    return this.queryAll({
      TableName: this.tableName,
      IndexName: 'RuleIdIndex',
      KeyConditionExpression: '#ruleId = :ruleId',
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: { '#ruleId': 'ruleId', '#status': 'status' },
      ExpressionAttributeValues: { ':ruleId': ruleId, ':status': 'open' },
    });
  }

  async getActiveIssuesByRule(ruleId: string): Promise<Issue[]> {
    return this.queryAll({
      TableName: this.tableName,
      IndexName: 'RuleIdIndex',
      KeyConditionExpression: '#ruleId = :ruleId',
      FilterExpression: '#status IN (:open, :suppressed)',
      ExpressionAttributeNames: { '#ruleId': 'ruleId', '#status': 'status' },
      ExpressionAttributeValues: {
        ':ruleId': ruleId,
        ':open': 'open',
        ':suppressed': 'suppressed',
      },
    });
  }

  async getOpenIssues(): Promise<Issue[]> {
    return this.queryAll({
      TableName: this.tableName,
      IndexName: 'StatusIndex',
      KeyConditionExpression: '#status = :status',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':status': 'open' },
    });
  }

  async getOpenIssuesByResourceArn(arn: string): Promise<Issue[]> {
    const issues = await this.scanAll({
      TableName: this.tableName,
      FilterExpression: '#status = :status',
      ExpressionAttributeNames: { '#status': 'status' },
      ExpressionAttributeValues: { ':status': 'open' },
    });
    return issues.filter((issue) =>
      issue.resourcesInvolved.some((resource) => resource.resourceId === arn)
    );
  }

  // Reads only `severity` through the status index, one partition per status.
  // Per-rule open/suppressed/resolved counts from the same bounded StatusIndex
  // reads the severity summary uses, projecting ruleId instead of severity —
  // plus the independent-detector label the runner records on each issue
  // (metadata.independentFinding), so the quality report can publish
  // corroboration beside the dismissal rate.
  async getRuleStatusCounts(): Promise<Record<string, RuleStatusCounts>> {
    const counts: Record<string, RuleStatusCounts> = {};
    for (const status of ISSUE_STATUSES) {
      let exclusiveStartKey: Record<string, unknown> | undefined;
      do {
        const result = await this.docClient.send(
          new QueryCommand({
            TableName: this.tableName,
            IndexName: 'StatusIndex',
            KeyConditionExpression: '#status = :status',
            ProjectionExpression: '#rule_id, #meta.#ind',
            ExpressionAttributeNames: {
              '#status': 'status',
              '#rule_id': 'ruleId',
              '#meta': 'metadata',
              '#ind': 'independentFinding',
            },
            ExpressionAttributeValues: { ':status': status },
            ExclusiveStartKey: exclusiveStartKey,
          })
        );
        for (const item of result.Items || []) {
          const ruleId = item.ruleId as string;
          if (!ruleId) continue;
          counts[ruleId] ??= { open: 0, suppressed: 0, resolved: 0, corroborated: 0, labeled: 0 };
          counts[ruleId][status] += 1;
          const label = (item.metadata as { independentFinding?: unknown } | undefined)
            ?.independentFinding;
          if (label === true) {
            counts[ruleId].corroborated = (counts[ruleId].corroborated ?? 0) + 1;
            counts[ruleId].labeled = (counts[ruleId].labeled ?? 0) + 1;
          } else if (label === false) {
            counts[ruleId].labeled = (counts[ruleId].labeled ?? 0) + 1;
          }
        }
        exclusiveStartKey = result.LastEvaluatedKey;
      } while (exclusiveStartKey);
    }
    return counts;
  }

  async getSeverityStatusCounts(): Promise<SeverityStatusCounts> {
    const counts = Object.fromEntries(
      SEVERITIES.map((severity) => [severity, { open: 0, suppressed: 0, resolved: 0 }])
    ) as SeverityStatusCounts;
    for (const status of ISSUE_STATUSES) {
      let exclusiveStartKey: Record<string, unknown> | undefined;
      do {
        const result = await this.docClient.send(
          new QueryCommand({
            TableName: this.tableName,
            IndexName: 'StatusIndex',
            KeyConditionExpression: '#status = :status',
            ProjectionExpression: '#severity',
            ExpressionAttributeNames: { '#status': 'status', '#severity': 'severity' },
            ExpressionAttributeValues: { ':status': status },
            ExclusiveStartKey: exclusiveStartKey,
          })
        );
        for (const item of result.Items || []) {
          const severity = item.severity as Severity;
          if (counts[severity]) counts[severity][status] += 1;
        }
        exclusiveStartKey = result.LastEvaluatedKey;
      } while (exclusiveStartKey);
    }
    return counts;
  }

  async getTotalCounts(): Promise<Record<Severity, number>> {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    const openIssues = await this.getOpenIssues();
    for (const issue of openIssues) counts[issue.severity]++;
    return counts;
  }

  private keyFor(issue: Pick<Issue, 'id' | 'ruleId'>): IssueKey {
    return { id: issue.id, ruleId: issue.ruleId };
  }

  // The condition pins the status the caller read, so the history entry's
  // `from` is exactly what was replaced and a lost race writes nothing.
  private async transition(
    issue: Issue,
    to: IssueStatus,
    allowedFrom: IssueStatus[],
    change: StatusChangeInput,
    at: string,
    fields: { set?: Record<string, unknown>; remove?: string[] }
  ): Promise<boolean> {
    if (!allowedFrom.includes(issue.status)) return false;

    const entry: StatusChange = {
      from: issue.status,
      to,
      at,
      by: change.by,
      reason: change.reason,
    };
    const names: Record<string, string> = {
      '#id': 'id',
      '#ruleId': 'ruleId',
      '#status': 'status',
      '#updatedAt': 'updatedAt',
      '#statusHistory': 'statusHistory',
    };
    const values: Record<string, unknown> = {
      ':status': to,
      ':from': issue.status,
      ':updatedAt': at,
      ':statusHistory': [...(issue.statusHistory ?? []), entry].slice(-STATUS_HISTORY_LIMIT),
    };
    const sets = [
      '#status = :status',
      '#updatedAt = :updatedAt',
      '#statusHistory = :statusHistory',
    ];
    for (const [field, value] of Object.entries(fields.set ?? {})) {
      names[`#${field}`] = field;
      values[`:${field}`] = value;
      sets.push(`#${field} = :${field}`);
    }
    const removes = (fields.remove ?? []).map((field) => {
      names[`#${field}`] = field;
      return `#${field}`;
    });

    try {
      await this.docClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: this.keyFor(issue),
          UpdateExpression:
            `SET ${sets.join(', ')}` + (removes.length ? ` REMOVE ${removes.join(', ')}` : ''),
          ConditionExpression:
            'attribute_exists(#id) AND attribute_exists(#ruleId) AND #status = :from',
          ExpressionAttributeNames: names,
          ExpressionAttributeValues: values,
        })
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) return false;
      throw error;
    }
  }

  private async updateExisting(
    key: IssueKey,
    updateExpression: string,
    expressionAttributeNames: Record<string, string>,
    expressionAttributeValues: Record<string, unknown>
  ): Promise<boolean> {
    try {
      await this.docClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: key,
          UpdateExpression: updateExpression,
          ConditionExpression: 'attribute_exists(#id) AND attribute_exists(#ruleId)',
          ExpressionAttributeNames: {
            '#id': 'id',
            '#ruleId': 'ruleId',
            ...expressionAttributeNames,
          },
          ExpressionAttributeValues: expressionAttributeValues,
        })
      );
      return true;
    } catch (error) {
      if (isConditionalCheckFailure(error)) return false;
      throw error;
    }
  }

  private addListFilters(
    request: QueryCommandInput | ScanCommandInput,
    query: IssueListQuery
  ): void {
    const filters: string[] = [];
    const names = request.ExpressionAttributeNames || {};
    const values = request.ExpressionAttributeValues || {};

    this.addInFilter(filters, values, '#severity', 'severity', query.severity);
    this.addInFilter(filters, values, '#team', 'team', query.team);
    this.addInFilter(filters, values, '#status', 'status', query.status);
    this.addInFilter(filters, values, '#metadata.#environment', 'environment', query.env);
    this.addInFilter(filters, values, '#ruleId', 'ruleIdFilter', query.ruleIds);

    if (query.severity?.length) names['#severity'] = 'severity';
    if (query.team?.length) names['#team'] = 'owningTeam';
    if (query.status?.length) names['#status'] = 'status';
    if (query.ruleIds?.length) names['#ruleId'] = 'ruleId';
    if (query.env?.length) {
      names['#metadata'] = 'metadata';
      names['#environment'] = 'environment';
    }

    if (filters.length > 0) request.FilterExpression = filters.join(' AND ');
    if (Object.keys(names).length > 0) request.ExpressionAttributeNames = names;
    if (Object.keys(values).length > 0) request.ExpressionAttributeValues = values;
  }

  private addInFilter<T extends string>(
    filters: string[],
    values: Record<string, unknown>,
    attribute: string,
    prefix: string,
    requested: T[] | undefined
  ): void {
    if (!requested?.length) return;
    const placeholders = requested.map((value, index) => {
      const placeholder = `:${prefix}${index}`;
      values[placeholder] = value;
      return placeholder;
    });
    filters.push(`${attribute} IN (${placeholders.join(', ')})`);
  }

  private async queryAll(input: QueryCommandInput): Promise<Issue[]> {
    const items: Issue[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const result = await this.docClient.send(
        new QueryCommand({ ...input, ExclusiveStartKey: exclusiveStartKey })
      );
      items.push(...(result.Items || []).map((item) => this.normalizeIssue(item)));
      exclusiveStartKey = result.LastEvaluatedKey;
    } while (exclusiveStartKey);
    return items;
  }

  private async scanAll(input: ScanCommandInput): Promise<Issue[]> {
    const items: Issue[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const result = await this.docClient.send(
        new ScanCommand({ ...input, ExclusiveStartKey: exclusiveStartKey })
      );
      items.push(...(result.Items || []).map((item) => this.normalizeIssue(item)));
      exclusiveStartKey = result.LastEvaluatedKey;
    } while (exclusiveStartKey);
    return items;
  }

  private normalizeIssue(item: Record<string, unknown>): Issue {
    if (typeof item.id !== 'string' || typeof item.ruleId !== 'string') {
      throw new Error('Stored issue is missing its id or ruleId');
    }
    return {
      ...(item as unknown as Issue),
      resourcesInvolved: this.parseStructured(item.resourcesInvolved, []),
      pathSummary: this.parseStructured(item.pathSummary, []),
      metadata: this.parseStructured(item.metadata, {}),
      externalRefs: this.parseStructured(item.externalRefs, []),
    };
  }

  private parseStructured<T>(value: unknown, fallback: T): T {
    if (typeof value !== 'string') return (value ?? fallback) as T;
    try {
      return JSON.parse(value) as T;
    } catch {
      throw new Error('Stored issue contains malformed structured data');
    }
  }

  private encodeToken(key: Record<string, unknown>): string {
    return Buffer.from(JSON.stringify(key)).toString('base64url');
  }

  private decodeToken(token: string): Record<string, unknown> {
    try {
      const value = JSON.parse(Buffer.from(token, 'base64url').toString('utf8')) as unknown;
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
      return value as Record<string, unknown>;
    } catch {
      throw new Error('Invalid issue pagination token');
    }
  }
}

function pageLimit(requested: number | undefined): number {
  const limit = Number.isSafeInteger(requested) ? requested : DEFAULT_LIMIT;
  return Math.max(1, Math.min(limit || DEFAULT_LIMIT, MAX_LIMIT));
}

function createdKey(item: Record<string, unknown> | Issue): CreatedKey {
  return {
    id: String(item.id),
    ruleId: String(item.ruleId),
    status: item.status as IssueStatus,
    createdAt: String(item.createdAt),
  };
}

// The token becomes ExclusiveStartKey, so accept only the exact key shape for
// a status this query reads, in the order it was issued for.
function decodeCreatedToken(
  token: string,
  order: IssueOrder,
  statuses: IssueStatus[]
): CreatedCursor {
  const invalid = new Error('Invalid issue pagination token');
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(token, 'base64url').toString('utf8'));
  } catch {
    throw invalid;
  }
  if (!isRecord(value) || value.o !== order || !isRecord(value.c)) throw invalid;
  const cursor: CreatedCursor = {};
  for (const [key, position] of Object.entries(value.c)) {
    const status = statuses.find((candidate) => candidate === key);
    if (!status) throw invalid;
    if (position === null || position === 'done') {
      cursor[status] = position;
      continue;
    }
    if (
      !isRecord(position) ||
      Object.keys(position).length !== 4 ||
      position.status !== status ||
      !['id', 'ruleId', 'createdAt'].every(
        (field) =>
          typeof position[field] === 'string' &&
          (position[field] as string).length > 0 &&
          (position[field] as string).length <= 512
      )
    ) {
      throw invalid;
    }
    cursor[status] = createdKey(position);
  }
  return cursor;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isMissingIndex(error: unknown): boolean {
  return (
    error instanceof Error &&
    error.name === 'ValidationException' &&
    error.message.includes('specified index')
  );
}

function isConditionalCheckFailure(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    'name' in error &&
    error.name === 'ConditionalCheckFailedException'
  );
}

function canonicalValues(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))].sort();
}

function sameValues(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
