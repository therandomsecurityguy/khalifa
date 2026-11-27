import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  DeleteCommand,
  GetCommand,
  PutCommand,
  ScanCommand,
} from '@aws-sdk/lib-dynamodb';
import { slugify } from './ai-use-case-store';

// Access reviews: campaigns over IAM users and roles from the graph. A
// campaign lists the principals it covers, reviewers record one decision per
// principal while the campaign is active, and completing it stores an evidence
// snapshot of what each principal looked like at that moment (read from the
// graph in one bounded batch) plus decision counts — the audit trail lives in
// the campaign record itself, not in the compliance evidence table, which the
// API can only read. Post-campaign re-evaluation against later graph states is
// a follow-up; the snapshot is what makes it possible.

export type AccessReviewStatus = 'draft' | 'active' | 'completed';
export type ReviewDecisionKind = 'approve' | 'revoke' | 'abstain';

export interface ReviewDecision {
  principalArn: string;
  decision: ReviewDecisionKind;
  note: string;
  decidedBy: string;
  decidedAt: string;
}

export interface ReviewSnapshotEntry {
  principalArn: string;
  exists: boolean;
  label: string;
  isAdmin: boolean | null;
}

export interface ReviewSummary {
  generatedAt: string;
  generatedBy: string;
  decisions: { approve: number; revoke: number; abstain: number; pending: number };
  snapshotted: number;
}

export interface AccessReviewRecord {
  id: string;
  name: string;
  description: string;
  status: AccessReviewStatus;
  dueAt: string | null;
  principals: string[];
  decisions: ReviewDecision[];
  snapshot: ReviewSnapshotEntry[] | null;
  summary: ReviewSummary | null;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
}

export type AccessReviewFields = Pick<
  AccessReviewRecord,
  'name' | 'description' | 'status' | 'dueAt' | 'principals'
>;

// Derived on read: how far the review has progressed.
export interface AccessReviewEntry extends AccessReviewRecord {
  decided: number;
  pending: number;
}

const MAX_NAME = 200;
const MAX_DESCRIPTION = 2_000;
const MAX_PRINCIPALS = 200;
const MAX_NOTE = 500;
const MAX_ARN = 512;
const MAX_REVIEWS = 200;

export const REVIEW_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const PRINCIPAL_ARN_PATTERN = /^arn:aws[\w-]*:[\w-]+:[a-z0-9-]*:[0-9]{12}:.+/;

const STATUSES: AccessReviewStatus[] = ['draft', 'active', 'completed'];
const DECISIONS: ReviewDecisionKind[] = ['approve', 'revoke', 'abstain'];

export function toAccessReviewEntry(record: AccessReviewRecord): AccessReviewEntry {
  const decided = record.decisions.length;
  return { ...record, decided, pending: Math.max(0, record.principals.length - decided) };
}

function trimmed(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  return text.length <= max ? text : null;
}

export function parseAccessReviewFields(
  body: Record<string, unknown>
): { fields: AccessReviewFields } | { error: string } {
  const name = trimmed(body.name, MAX_NAME);
  if (!name) return { error: `name is required (1-${MAX_NAME} characters)` };

  const description =
    body.description === undefined ? '' : trimmed(body.description, MAX_DESCRIPTION);
  if (description === null) {
    return { error: `description must be a string of at most ${MAX_DESCRIPTION} characters` };
  }

  const status = body.status === undefined ? 'draft' : body.status;
  if (!STATUSES.includes(status as AccessReviewStatus)) {
    return { error: `status must be one of: ${STATUSES.join(', ')}` };
  }

  let dueAt: string | null = null;
  if (body.dueAt !== undefined && body.dueAt !== null) {
    const parsed = typeof body.dueAt === 'string' ? Date.parse(body.dueAt) : Number.NaN;
    if (!Number.isFinite(parsed)) {
      return { error: 'dueAt must be an ISO timestamp or null' };
    }
    dueAt = new Date(parsed).toISOString();
  }

  const raw = body.principals;
  if (raw === undefined || raw === null) {
    return { error: 'principals must list the IAM user or role ARNs the review covers' };
  }
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_PRINCIPALS) {
    return { error: `principals must be 1-${MAX_PRINCIPALS} ARNs` };
  }
  const principals = raw
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
  if (principals.length !== raw.length) {
    return { error: `principals must be 1-${MAX_PRINCIPALS} ARNs` };
  }
  const invalid = principals.find(
    (arn) => arn.length > MAX_ARN || !PRINCIPAL_ARN_PATTERN.test(arn)
  );
  if (invalid !== undefined) {
    return {
      error: `principals entries must be IAM user or role ARNs (got: ${invalid.slice(0, 64)})`,
    };
  }

  return {
    fields: {
      name,
      description,
      status: status as AccessReviewStatus,
      dueAt,
      principals: [...new Set(principals)],
    },
  };
}

export function parseReviewDecision(
  body: Record<string, unknown>
):
  | { decision: { principalArn: string; decision: ReviewDecisionKind; note: string } }
  | { error: string } {
  const principalArn = typeof body.principalArn === 'string' ? body.principalArn.trim() : undefined;
  if (!principalArn || principalArn.length > MAX_ARN || !PRINCIPAL_ARN_PATTERN.test(principalArn)) {
    return { error: 'principalArn must be an IAM user or role ARN' };
  }
  const decision = body.decision;
  if (!DECISIONS.includes(decision as ReviewDecisionKind)) {
    return { error: `decision must be one of: ${DECISIONS.join(', ')}` };
  }
  const note = body.note === undefined ? '' : trimmed(body.note, MAX_NOTE);
  if (note === null) {
    return { error: `note must be a string of at most ${MAX_NOTE} characters` };
  }
  return { decision: { principalArn, decision: decision as ReviewDecisionKind, note } };
}

// The completion snapshot: per covered principal, what the graph held at the
// moment the review closed (`exists` false means the principal is gone from
// the graph), plus decision counts. Pure so the route stays thin and the
// shape is testable without Neptune.
export function summarizeCompletion(
  principals: string[],
  decisions: ReviewDecision[],
  vertices: Array<{ id: string; label: string; properties: Record<string, unknown> }>,
  actor: string,
  at: string
): { snapshot: ReviewSnapshotEntry[]; summary: ReviewSummary } {
  const byId = new Map(vertices.map((vertex) => [vertex.id, vertex]));
  const snapshot = principals.map((principalArn): ReviewSnapshotEntry => {
    const vertex = byId.get(principalArn);
    const isAdmin = vertex?.properties?.is_admin;
    return {
      principalArn,
      exists: Boolean(vertex),
      label: vertex?.label ?? '',
      isAdmin: typeof isAdmin === 'boolean' ? isAdmin : null,
    };
  });
  const counts = { approve: 0, revoke: 0, abstain: 0, pending: 0 };
  const decided = new Set<string>();
  for (const decision of decisions) {
    counts[decision.decision] += 1;
    decided.add(decision.principalArn);
  }
  counts.pending = Math.max(0, principals.length - decided.size);
  return {
    snapshot,
    summary: {
      generatedAt: at,
      generatedBy: actor,
      decisions: counts,
      snapshotted: snapshot.length,
    },
  };
}

// Records come back from DynamoDB, not from this process, so every field is
// re-validated on read; a malformed row degrades to safe defaults rather than
// reaching a response.
export function mapAccessReviewRecord(record: Record<string, unknown>): AccessReviewRecord {
  const text = (value: unknown, max: number): string =>
    typeof value === 'string' ? value.slice(0, max) : '';
  const principals = Array.isArray(record.principals)
    ? record.principals
        .filter((item): item is string => typeof item === 'string')
        .map((item) => item.slice(0, MAX_ARN))
        .slice(0, MAX_PRINCIPALS)
    : [];
  const decisions: ReviewDecision[] = Array.isArray(record.decisions)
    ? record.decisions
        .filter(
          (item): item is Record<string, unknown> =>
            Boolean(item) && typeof item === 'object' && !Array.isArray(item)
        )
        .map((item) => ({
          principalArn: text(item.principalArn, MAX_ARN),
          decision: DECISIONS.includes(item.decision as ReviewDecisionKind)
            ? (item.decision as ReviewDecisionKind)
            : 'abstain',
          note: text(item.note, MAX_NOTE),
          decidedBy: text(item.decidedBy, 320),
          decidedAt: text(item.decidedAt, 40),
        }))
        .filter((item) => item.principalArn)
        .slice(0, MAX_PRINCIPALS)
    : [];
  const snapshot = Array.isArray(record.snapshot)
    ? record.snapshot
        .filter(
          (item): item is Record<string, unknown> =>
            Boolean(item) && typeof item === 'object' && !Array.isArray(item)
        )
        .map((item) => ({
          principalArn: text(item.principalArn, MAX_ARN),
          exists: item.exists === true,
          label: text(item.label, 64),
          isAdmin: typeof item.isAdmin === 'boolean' ? item.isAdmin : null,
        }))
        .filter((item) => item.principalArn)
        .slice(0, MAX_PRINCIPALS)
    : null;
  const summaryRaw =
    record.summary && typeof record.summary === 'object' && !Array.isArray(record.summary)
      ? (record.summary as Record<string, unknown>)
      : null;
  const summaryDecisionsRaw =
    summaryRaw?.decisions && typeof summaryRaw.decisions === 'object'
      ? (summaryRaw.decisions as Record<string, unknown>)
      : null;
  const count = (value: unknown): number =>
    Number.isSafeInteger(value) && (value as number) >= 0 ? (value as number) : 0;
  return {
    id: text(record.id, 64),
    name: text(record.name, MAX_NAME),
    description: text(record.description, MAX_DESCRIPTION),
    status: STATUSES.includes(record.status as AccessReviewStatus)
      ? (record.status as AccessReviewStatus)
      : 'draft',
    dueAt: typeof record.dueAt === 'string' ? record.dueAt.slice(0, 40) : null,
    principals,
    decisions,
    snapshot,
    summary: summaryRaw
      ? {
          generatedAt: text(summaryRaw.generatedAt, 40),
          generatedBy: text(summaryRaw.generatedBy, 320),
          decisions: {
            approve: count(summaryDecisionsRaw?.approve),
            revoke: count(summaryDecisionsRaw?.revoke),
            abstain: count(summaryDecisionsRaw?.abstain),
            pending: count(summaryDecisionsRaw?.pending),
          },
          snapshotted: count(summaryRaw.snapshotted),
        }
      : null,
    createdAt: text(record.createdAt, 40),
    createdBy: text(record.createdBy, 320),
    updatedAt: text(record.updatedAt, 40),
    updatedBy: text(record.updatedBy, 320),
  };
}

function isConditionalFailure(error: unknown): boolean {
  return error instanceof Error && error.name === 'ConditionalCheckFailedException';
}

export { slugify };

export class AccessReviewStore {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string = process.env.ACCESS_REVIEWS_TABLE || 'AccessReviews') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  async listReviews(): Promise<{ items: AccessReviewEntry[]; truncated: boolean }> {
    const result = await this.docClient.send(
      new ScanCommand({ TableName: this.tableName, Limit: MAX_REVIEWS + 1 })
    );
    const records = (result.Items || []) as Record<string, unknown>[];
    const items = records
      .slice(0, MAX_REVIEWS)
      .map(mapAccessReviewRecord)
      .filter((item) => item.id)
      .sort((a, b) => a.id.localeCompare(b.id, 'en'))
      .map(toAccessReviewEntry);
    return { items, truncated: records.length > MAX_REVIEWS };
  }

  async getReview(id: string): Promise<AccessReviewEntry | null> {
    const result = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id } })
    );
    return result.Item
      ? toAccessReviewEntry(mapAccessReviewRecord(result.Item as Record<string, unknown>))
      : null;
  }

  /** null means the id already exists. */
  async createReview(
    id: string,
    fields: AccessReviewFields,
    actor: string
  ): Promise<AccessReviewEntry | null> {
    const now = new Date().toISOString();
    const item: AccessReviewRecord = {
      id,
      ...fields,
      decisions: [],
      snapshot: null,
      summary: null,
      createdAt: now,
      createdBy: actor,
      updatedAt: now,
      updatedBy: actor,
    };
    try {
      await this.docClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: item,
          ConditionExpression: 'attribute_not_exists(id)',
        })
      );
      return toAccessReviewEntry(item);
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /** null means the id no longer exists. */
  async updateReview(
    id: string,
    fields: AccessReviewFields,
    actor: string,
    completion?: { snapshot: ReviewSnapshotEntry[]; summary: ReviewSummary }
  ): Promise<AccessReviewEntry | null> {
    const existing = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id } })
    );
    if (!existing.Item) return null;
    const current = mapAccessReviewRecord(existing.Item as Record<string, unknown>);
    const item: AccessReviewRecord = {
      ...current,
      ...fields,
      // Decisions made against principals no longer covered are dropped rather
      // than kept as phantom history the review does not cover.
      decisions: current.decisions.filter((decision) =>
        fields.principals.includes(decision.principalArn)
      ),
      snapshot: completion ? completion.snapshot : current.snapshot,
      summary: completion ? completion.summary : current.summary,
      updatedAt: new Date().toISOString(),
      updatedBy: actor,
    };
    try {
      await this.docClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: item,
          ConditionExpression: 'attribute_exists(id)',
        })
      );
      return toAccessReviewEntry(item);
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /**
   * Upserts one decision. The caller has already checked existence, status,
   * and coverage; this writes the merged record and re-checks existence.
   */
  async recordDecision(
    id: string,
    decision: { principalArn: string; decision: ReviewDecisionKind; note: string },
    actor: string
  ): Promise<AccessReviewEntry | null> {
    const existing = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id } })
    );
    if (!existing.Item) return null;
    const current = mapAccessReviewRecord(existing.Item as Record<string, unknown>);
    const decisions = [
      ...current.decisions.filter((entry) => entry.principalArn !== decision.principalArn),
      {
        principalArn: decision.principalArn,
        decision: decision.decision,
        note: decision.note,
        decidedBy: actor,
        decidedAt: new Date().toISOString(),
      },
    ];
    const item: AccessReviewRecord = {
      ...current,
      decisions,
      updatedAt: new Date().toISOString(),
      updatedBy: actor,
    };
    try {
      await this.docClient.send(
        new PutCommand({
          TableName: this.tableName,
          Item: item,
          ConditionExpression: 'attribute_exists(id)',
        })
      );
      return toAccessReviewEntry(item);
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /** false means the id does not exist. */
  async deleteReview(id: string): Promise<boolean> {
    try {
      await this.docClient.send(
        new DeleteCommand({
          TableName: this.tableName,
          Key: { id },
          ConditionExpression: 'attribute_exists(id)',
        })
      );
      return true;
    } catch (error) {
      if (isConditionalFailure(error)) return false;
      throw error;
    }
  }
}
