import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  DeleteCommand,
  GetCommand,
  PutCommand,
  ScanCommand,
} from '@aws-sdk/lib-dynamodb';
import { slugify } from './ai-use-case-store';

// The risk register: workflow objects over the collected estate. Inherent and
// residual risk are stored as 1-5 likelihood/impact ratings; the score and
// level are derived on read so the arithmetic lives in one place. An accepted
// risk must carry an expiry — acceptance that never lapses is how a register
// rots — and every linked control must exist in the canonical catalogue
// (validated against the set the caller passes in).

export type RiskCategory = 'security' | 'compliance' | 'privacy' | 'operational' | 'ai';
export type RiskStatus = 'open' | 'monitoring' | 'accepted' | 'closed';
export type RiskTreatment = 'mitigate' | 'accept' | 'transfer' | 'avoid';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface RiskRating {
  likelihood: number;
  impact: number;
}

export interface RiskRecord {
  id: string;
  title: string;
  description: string;
  category: RiskCategory;
  owner: string;
  status: RiskStatus;
  inherent: RiskRating;
  residual: RiskRating | null;
  treatment: RiskTreatment;
  acceptanceExpiry: string | null;
  reviewCadenceDays: number;
  lastReviewedAt: string | null;
  linkedIssueIds: string[];
  linkedControls: string[];
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
}

export type RiskFields = Omit<
  RiskRecord,
  'id' | 'createdAt' | 'createdBy' | 'updatedAt' | 'updatedBy'
>;

// Derived on read: the stored record plus its scores, levels, and the next
// review date the cadence implies.
export interface RiskRegisterEntry extends RiskRecord {
  inherentScore: number;
  inherentLevel: RiskLevel;
  residualScore: number | null;
  residualLevel: RiskLevel | null;
  nextReviewAt: string | null;
}

const MAX_TITLE = 200;
const MAX_DESCRIPTION = 2_000;
const MAX_OWNER = 120;
const MAX_LIST_ITEMS = 20;
const MAX_ISSUE_ID = 64;
const MAX_CONTROL_ID = 64;
const MAX_RISKS = 500;
const MAX_ACCEPTANCE_DAYS = 3_650;
const DAY_MS = 24 * 60 * 60 * 1000;

export const RISK_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

const CATEGORIES: RiskCategory[] = ['security', 'compliance', 'privacy', 'operational', 'ai'];
const STATUSES: RiskStatus[] = ['open', 'monitoring', 'accepted', 'closed'];
const TREATMENTS: RiskTreatment[] = ['mitigate', 'accept', 'transfer', 'avoid'];

/** Likelihood × impact on the 1-5 scale. */
export function riskScore(rating: RiskRating): number {
  return rating.likelihood * rating.impact;
}

export function riskLevel(score: number): RiskLevel {
  if (score <= 4) return 'low';
  if (score <= 9) return 'medium';
  if (score <= 16) return 'high';
  return 'critical';
}

export function toRiskEntry(record: RiskRecord): RiskRegisterEntry {
  const inherentScore = riskScore(record.inherent);
  const residualScore = record.residual ? riskScore(record.residual) : null;
  const basis = Date.parse(record.lastReviewedAt ?? record.createdAt);
  const nextReviewAt = Number.isFinite(basis)
    ? new Date(basis + record.reviewCadenceDays * DAY_MS).toISOString()
    : null;
  return {
    ...record,
    inherentScore,
    inherentLevel: riskLevel(inherentScore),
    residualScore,
    residualLevel: residualScore === null ? null : riskLevel(residualScore),
    nextReviewAt,
  };
}

function trimmed(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  return text && text.length <= max ? text : null;
}

function stringList(value: unknown, maxItems: number, maxLength: number): string[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > maxItems) return null;
  const items = value
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
  if (items.length !== value.length || items.some((item) => item.length > maxLength)) return null;
  return [...new Set(items)];
}

function parseRating(value: unknown, name: string): RiskRating | { error: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { error: `${name} must be an object with likelihood and impact (1-5)` };
  }
  const body = value as Record<string, unknown>;
  for (const field of ['likelihood', 'impact'] as const) {
    const rating = body[field];
    if (!Number.isSafeInteger(rating) || (rating as number) < 1 || (rating as number) > 5) {
      return { error: `${name}.${field} must be an integer between 1 and 5` };
    }
  }
  return { likelihood: body.likelihood as number, impact: body.impact as number };
}

export function parseRiskFields(
  body: Record<string, unknown>,
  fallbackOwner: string,
  knownControls: ReadonlySet<string>,
  now: Date = new Date()
): { fields: RiskFields } | { error: string } {
  const title = trimmed(body.title, MAX_TITLE);
  if (!title) return { error: `title is required (1-${MAX_TITLE} characters)` };

  const description =
    body.description === undefined ? '' : trimmed(body.description, MAX_DESCRIPTION);
  if (description === null) {
    return { error: `description must be a string of at most ${MAX_DESCRIPTION} characters` };
  }

  const category = body.category === undefined ? 'security' : body.category;
  if (!CATEGORIES.includes(category as RiskCategory)) {
    return { error: `category must be one of: ${CATEGORIES.join(', ')}` };
  }

  const owner = body.owner === undefined ? fallbackOwner : trimmed(body.owner, MAX_OWNER);
  if (!owner) return { error: `owner is required (1-${MAX_OWNER} characters)` };

  const status = body.status === undefined ? 'open' : body.status;
  if (!STATUSES.includes(status as RiskStatus)) {
    return { error: `status must be one of: ${STATUSES.join(', ')}` };
  }

  const inherent = parseRating(body.inherent, 'inherent');
  if ('error' in inherent) return inherent;

  let residual: RiskRating | null = null;
  if (body.residual !== undefined && body.residual !== null) {
    const parsed = parseRating(body.residual, 'residual');
    if ('error' in parsed) return parsed;
    residual = parsed;
  }

  const treatment = body.treatment === undefined ? 'mitigate' : body.treatment;
  if (!TREATMENTS.includes(treatment as RiskTreatment)) {
    return { error: `treatment must be one of: ${TREATMENTS.join(', ')}` };
  }

  let acceptanceExpiry: string | null = null;
  if (treatment === 'accept') {
    const raw = body.acceptanceExpiry;
    const parsed = typeof raw === 'string' ? Date.parse(raw) : Number.NaN;
    if (!Number.isFinite(parsed)) {
      return { error: 'acceptanceExpiry is required for an accepted risk (ISO timestamp)' };
    }
    if (parsed <= now.getTime()) {
      return { error: 'acceptanceExpiry must be in the future' };
    }
    if (parsed > now.getTime() + MAX_ACCEPTANCE_DAYS * DAY_MS) {
      return { error: `acceptanceExpiry must be within ${MAX_ACCEPTANCE_DAYS} days` };
    }
    acceptanceExpiry = new Date(parsed).toISOString();
  }

  const reviewCadenceDays = body.reviewCadenceDays === undefined ? 90 : body.reviewCadenceDays;
  if (
    !Number.isSafeInteger(reviewCadenceDays) ||
    (reviewCadenceDays as number) < 1 ||
    (reviewCadenceDays as number) > 365
  ) {
    return { error: 'reviewCadenceDays must be an integer between 1 and 365' };
  }

  let lastReviewedAt: string | null = null;
  if (body.lastReviewedAt !== undefined && body.lastReviewedAt !== null) {
    const parsed =
      typeof body.lastReviewedAt === 'string' ? Date.parse(body.lastReviewedAt) : Number.NaN;
    if (!Number.isFinite(parsed)) {
      return { error: 'lastReviewedAt must be an ISO timestamp or null' };
    }
    lastReviewedAt = new Date(parsed).toISOString();
  }

  const linkedIssueIds = stringList(body.linkedIssueIds, MAX_LIST_ITEMS, MAX_ISSUE_ID);
  if (linkedIssueIds === null) {
    return {
      error: `linkedIssueIds must be at most ${MAX_LIST_ITEMS} strings of at most ${MAX_ISSUE_ID} characters`,
    };
  }

  const linkedControls = stringList(body.linkedControls, MAX_LIST_ITEMS, MAX_CONTROL_ID);
  if (linkedControls === null) {
    return {
      error: `linkedControls must be at most ${MAX_LIST_ITEMS} strings of at most ${MAX_CONTROL_ID} characters`,
    };
  }
  const unknown = linkedControls.find((control) => !knownControls.has(control));
  if (unknown !== undefined) {
    return { error: `linkedControls must be canonical control ids (unknown: ${unknown})` };
  }

  return {
    fields: {
      title,
      description,
      category: category as RiskCategory,
      owner,
      status: status as RiskStatus,
      inherent,
      residual,
      treatment: treatment as RiskTreatment,
      acceptanceExpiry,
      reviewCadenceDays: reviewCadenceDays as number,
      lastReviewedAt,
      linkedIssueIds,
      linkedControls,
    },
  };
}

// Records come back from DynamoDB, not from this process, so every field is
// re-validated on read; a malformed row degrades to safe defaults rather than
// reaching a response.
export function mapRiskRecord(record: Record<string, unknown>): RiskRecord {
  const text = (value: unknown, max: number): string =>
    typeof value === 'string' ? value.slice(0, max) : '';
  const list = (value: unknown, maxItems: number, maxLength: number): string[] =>
    Array.isArray(value)
      ? value
          .filter((item): item is string => typeof item === 'string')
          .map((item) => item.slice(0, maxLength))
          .slice(0, maxItems)
      : [];
  const rating = (value: unknown): RiskRating | null => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const body = value as Record<string, unknown>;
    const likelihood = body.likelihood;
    const impact = body.impact;
    if (
      !Number.isSafeInteger(likelihood) ||
      (likelihood as number) < 1 ||
      (likelihood as number) > 5 ||
      !Number.isSafeInteger(impact) ||
      (impact as number) < 1 ||
      (impact as number) > 5
    ) {
      return null;
    }
    return { likelihood: likelihood as number, impact: impact as number };
  };
  return {
    id: text(record.id, 64),
    title: text(record.title, MAX_TITLE),
    description: text(record.description, MAX_DESCRIPTION),
    category: CATEGORIES.includes(record.category as RiskCategory)
      ? (record.category as RiskCategory)
      : 'security',
    owner: text(record.owner, MAX_OWNER),
    status: STATUSES.includes(record.status as RiskStatus) ? (record.status as RiskStatus) : 'open',
    inherent: rating(record.inherent) ?? { likelihood: 1, impact: 1 },
    residual: rating(record.residual),
    treatment: TREATMENTS.includes(record.treatment as RiskTreatment)
      ? (record.treatment as RiskTreatment)
      : 'mitigate',
    acceptanceExpiry:
      typeof record.acceptanceExpiry === 'string' ? record.acceptanceExpiry.slice(0, 40) : null,
    reviewCadenceDays:
      Number.isSafeInteger(record.reviewCadenceDays) &&
      (record.reviewCadenceDays as number) >= 1 &&
      (record.reviewCadenceDays as number) <= 365
        ? (record.reviewCadenceDays as number)
        : 90,
    lastReviewedAt:
      typeof record.lastReviewedAt === 'string' ? record.lastReviewedAt.slice(0, 40) : null,
    linkedIssueIds: list(record.linkedIssueIds, MAX_LIST_ITEMS, MAX_ISSUE_ID),
    linkedControls: list(record.linkedControls, MAX_LIST_ITEMS, MAX_CONTROL_ID),
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

export class RiskRegisterStore {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string = process.env.RISK_REGISTER_TABLE || 'RiskRegister') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  async listRisks(): Promise<{ items: RiskRegisterEntry[]; truncated: boolean }> {
    const result = await this.docClient.send(
      new ScanCommand({ TableName: this.tableName, Limit: MAX_RISKS + 1 })
    );
    const records = (result.Items || []) as Record<string, unknown>[];
    const items = records
      .slice(0, MAX_RISKS)
      .map(mapRiskRecord)
      .filter((item) => item.id)
      .sort((a, b) => a.id.localeCompare(b.id, 'en'))
      .map(toRiskEntry);
    return { items, truncated: records.length > MAX_RISKS };
  }

  async getRisk(id: string): Promise<RiskRegisterEntry | null> {
    const result = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id } })
    );
    return result.Item ? toRiskEntry(mapRiskRecord(result.Item as Record<string, unknown>)) : null;
  }

  /** null means the id already exists. */
  async createRisk(
    id: string,
    fields: RiskFields,
    actor: string
  ): Promise<RiskRegisterEntry | null> {
    const now = new Date().toISOString();
    const item: RiskRecord = {
      id,
      ...fields,
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
      return toRiskEntry(item);
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /** null means the id no longer exists. */
  async updateRisk(
    id: string,
    fields: RiskFields,
    actor: string
  ): Promise<RiskRegisterEntry | null> {
    const existing = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id } })
    );
    if (!existing.Item) return null;
    const item: RiskRecord = {
      ...mapRiskRecord(existing.Item as Record<string, unknown>),
      ...fields,
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
      return toRiskEntry(item);
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /** false means the id does not exist. */
  async deleteRisk(id: string): Promise<boolean> {
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
