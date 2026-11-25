import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  ScanCommand,
} from '@aws-sdk/lib-dynamodb';

// AI governance objects: the deployment-owned use-case registry and its lite
// impact assessment. The graph shows which AI assets exist; this is the
// hand-maintained record of who owns each use case, what it is for, which
// collected assets it covers, and what was assessed. Everything here is
// bounded and validated on the way in, so a registry entry can never become
// an arbitrary document store.

export type AiUseCaseStatus = 'draft' | 'approved' | 'retired';
export type AiAssessmentStatus = 'draft' | 'approved' | 'rejected';
export type AiRiskTier = 'low' | 'medium' | 'high';

export interface AiImpactAssessment {
  status: AiAssessmentStatus;
  riskTier: AiRiskTier;
  owner: string;
  humanOversight: string;
  impacts: string;
  notes: string;
  reviewedAt: string | null;
  updatedAt: string;
  updatedBy: string;
}

export interface AiUseCase {
  id: string;
  name: string;
  description: string;
  owner: string;
  status: AiUseCaseStatus;
  // Collected asset ARNs this use case covers (agents, endpoints, knowledge
  // bases, notebooks, domains, models).
  assets: string[];
  dataClasses: string[];
  assessment: AiImpactAssessment | null;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
}

/** The fields a caller can set; identity and timestamps are server-owned. */
export interface UseCaseFields {
  name: string;
  description: string;
  owner: string;
  status: AiUseCaseStatus;
  assets: string[];
  dataClasses: string[];
  assessment: Omit<AiImpactAssessment, 'updatedAt' | 'updatedBy'> | null;
}

export const USE_CASE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const MAX_NAME_LENGTH = 200;
const MAX_DESCRIPTION_LENGTH = 2000;
const MAX_OWNER_LENGTH = 120;
const MAX_TEXT_LENGTH = 2000;
const MAX_OVERSIGHT_LENGTH = 1000;
const MAX_ASSETS = 50;
const MAX_DATA_CLASSES = 20;
const MAX_DATA_CLASS_LENGTH = 64;
const MAX_ARN_LENGTH = 512;
// The registry is hand-maintained; a page this size is already generous, and
// the bound keeps a scan from ever streaming an unbounded table.
const MAX_USE_CASES = 500;

const USE_CASE_STATUSES: AiUseCaseStatus[] = ['draft', 'approved', 'retired'];
const ASSESSMENT_STATUSES: AiAssessmentStatus[] = ['draft', 'approved', 'rejected'];
const RISK_TIERS: AiRiskTier[] = ['low', 'medium', 'high'];

export function slugify(name: string): string {
  const slug = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
    .replace(/-+$/g, '');
  return USE_CASE_ID_PATTERN.test(slug) ? slug : '';
}

function trimmed(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  return text.length <= max ? text : null;
}

function stringList(value: unknown, maxItems: number, maxLength: number): string[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return null;
  if (value.length > maxItems) return null;
  const items = value.map((item) => trimmed(item, maxLength));
  if (items.some((item) => item === null)) return null;
  return [...new Set(items as string[])];
}

export function isAssetArn(value: string): boolean {
  return /^arn:aws[\w-]*:[a-z0-9-]+:/.test(value) && value.length <= MAX_ARN_LENGTH;
}

function parseAssessment(value: unknown): UseCaseFields['assessment'] | { error: string } {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'object' || Array.isArray(value)) {
    return { error: 'assessment must be an object or null' };
  }
  const body = value as Record<string, unknown>;
  const status = body.status === undefined ? 'draft' : body.status;
  if (!ASSESSMENT_STATUSES.includes(status as AiAssessmentStatus)) {
    return { error: `assessment.status must be one of: ${ASSESSMENT_STATUSES.join(', ')}` };
  }
  const riskTier = body.riskTier === undefined ? 'low' : body.riskTier;
  if (!RISK_TIERS.includes(riskTier as AiRiskTier)) {
    return { error: `assessment.riskTier must be one of: ${RISK_TIERS.join(', ')}` };
  }
  const owner = body.owner === undefined ? '' : trimmed(body.owner, MAX_OWNER_LENGTH);
  if (owner === null)
    return { error: `assessment.owner must be a string of at most ${MAX_OWNER_LENGTH} characters` };
  const humanOversight =
    body.humanOversight === undefined ? '' : trimmed(body.humanOversight, MAX_OVERSIGHT_LENGTH);
  if (humanOversight === null)
    return {
      error: `assessment.humanOversight must be a string of at most ${MAX_OVERSIGHT_LENGTH} characters`,
    };
  const impacts = body.impacts === undefined ? '' : trimmed(body.impacts, MAX_TEXT_LENGTH);
  if (impacts === null)
    return {
      error: `assessment.impacts must be a string of at most ${MAX_TEXT_LENGTH} characters`,
    };
  const notes = body.notes === undefined ? '' : trimmed(body.notes, MAX_TEXT_LENGTH);
  if (notes === null)
    return { error: `assessment.notes must be a string of at most ${MAX_TEXT_LENGTH} characters` };
  let reviewedAt: string | null = null;
  if (body.reviewedAt !== undefined && body.reviewedAt !== null) {
    if (typeof body.reviewedAt !== 'string' || Number.isNaN(Date.parse(body.reviewedAt))) {
      return { error: 'assessment.reviewedAt must be an ISO timestamp or null' };
    }
    reviewedAt = new Date(body.reviewedAt).toISOString();
  }
  return {
    status: status as AiAssessmentStatus,
    riskTier: riskTier as AiRiskTier,
    owner,
    humanOversight,
    impacts,
    notes,
    reviewedAt,
  };
}

/**
 * Validation for a create/update body. Returns the fields to store, or the
 * first problem found; messages name the field so the caller can fix it.
 */
export function parseUseCaseFields(
  body: Record<string, unknown>,
  fallbackOwner: string
): { fields: UseCaseFields } | { error: string } {
  const name = trimmed(body.name, MAX_NAME_LENGTH);
  if (!name) return { error: `name is required (1-${MAX_NAME_LENGTH} characters)` };
  const owner = body.owner === undefined ? fallbackOwner : trimmed(body.owner, MAX_OWNER_LENGTH);
  if (!owner) return { error: `owner is required (1-${MAX_OWNER_LENGTH} characters)` };
  const description =
    body.description === undefined ? '' : trimmed(body.description, MAX_DESCRIPTION_LENGTH);
  if (description === null)
    return {
      error: `description must be a string of at most ${MAX_DESCRIPTION_LENGTH} characters`,
    };
  const status = body.status === undefined ? 'draft' : body.status;
  if (!USE_CASE_STATUSES.includes(status as AiUseCaseStatus)) {
    return { error: `status must be one of: ${USE_CASE_STATUSES.join(', ')}` };
  }
  const assets = stringList(body.assets, MAX_ASSETS, MAX_ARN_LENGTH);
  if (assets === null) return { error: `assets must be at most ${MAX_ASSETS} ARN strings` };
  const invalidAsset = assets.find((asset) => !isAssetArn(asset));
  if (invalidAsset !== undefined)
    return { error: `assets entries must be ARNs (got: ${invalidAsset.slice(0, 64)})` };
  const dataClasses = stringList(body.dataClasses, MAX_DATA_CLASSES, MAX_DATA_CLASS_LENGTH);
  if (dataClasses === null)
    return {
      error: `dataClasses must be at most ${MAX_DATA_CLASSES} strings of at most ${MAX_DATA_CLASS_LENGTH} characters`,
    };
  const assessment = parseAssessment(body.assessment);
  if (assessment !== null && 'error' in assessment) return assessment;
  return {
    fields: {
      name,
      description,
      owner,
      status: status as AiUseCaseStatus,
      assets,
      dataClasses,
      assessment: assessment && !('error' in assessment) ? assessment : null,
    },
  };
}

// Records come back from DynamoDB, not from this process, so every field is
// re-validated on read; a malformed row degrades to safe defaults rather than
// reaching the API response.
export function mapUseCaseRecord(record: Record<string, unknown>): AiUseCase {
  const text = (value: unknown, max: number): string =>
    typeof value === 'string' ? value.slice(0, max) : '';
  const list = (value: unknown, maxItems: number): string[] =>
    Array.isArray(value)
      ? value.filter((item): item is string => typeof item === 'string').slice(0, maxItems)
      : [];
  const assessment = record.assessment as Record<string, unknown> | null | undefined;
  return {
    id: text(record.id, 64),
    name: text(record.name, MAX_NAME_LENGTH),
    description: text(record.description, MAX_DESCRIPTION_LENGTH),
    owner: text(record.owner, MAX_OWNER_LENGTH),
    status: USE_CASE_STATUSES.includes(record.status as AiUseCaseStatus)
      ? (record.status as AiUseCaseStatus)
      : 'draft',
    assets: list(record.assets, MAX_ASSETS),
    dataClasses: list(record.dataClasses, MAX_DATA_CLASSES),
    assessment:
      assessment && typeof assessment === 'object'
        ? {
            status: ASSESSMENT_STATUSES.includes(assessment.status as AiAssessmentStatus)
              ? (assessment.status as AiAssessmentStatus)
              : 'draft',
            riskTier: RISK_TIERS.includes(assessment.riskTier as AiRiskTier)
              ? (assessment.riskTier as AiRiskTier)
              : 'low',
            owner: text(assessment.owner, MAX_OWNER_LENGTH),
            humanOversight: text(assessment.humanOversight, MAX_OVERSIGHT_LENGTH),
            impacts: text(assessment.impacts, MAX_TEXT_LENGTH),
            notes: text(assessment.notes, MAX_TEXT_LENGTH),
            reviewedAt: typeof assessment.reviewedAt === 'string' ? assessment.reviewedAt : null,
            updatedAt: text(assessment.updatedAt, 40),
            updatedBy: text(assessment.updatedBy, 320),
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

export class AiUseCaseStore {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string = process.env.AI_USE_CASES_TABLE || 'AiUseCases') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  async listUseCases(): Promise<{ items: AiUseCase[]; truncated: boolean }> {
    const result = await this.docClient.send(
      new ScanCommand({ TableName: this.tableName, Limit: MAX_USE_CASES + 1 })
    );
    const records = (result.Items || []) as Record<string, unknown>[];
    const items = records
      .slice(0, MAX_USE_CASES)
      .map(mapUseCaseRecord)
      .filter((item) => item.id)
      .sort((a, b) => a.id.localeCompare(b.id, 'en'));
    return { items, truncated: records.length > MAX_USE_CASES };
  }

  async getUseCase(id: string): Promise<AiUseCase | null> {
    const result = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id } })
    );
    return result.Item ? mapUseCaseRecord(result.Item as Record<string, unknown>) : null;
  }

  /** null means the id already exists. */
  async createUseCase(id: string, fields: UseCaseFields, actor: string): Promise<AiUseCase | null> {
    const now = new Date().toISOString();
    const item: AiUseCase = {
      id,
      ...fields,
      assessment: fields.assessment
        ? { ...fields.assessment, updatedAt: now, updatedBy: actor }
        : null,
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
      return item;
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /** null means the id no longer exists. */
  async updateUseCase(id: string, fields: UseCaseFields, actor: string): Promise<AiUseCase | null> {
    const existing = await this.getUseCase(id);
    if (!existing) return null;
    const now = new Date().toISOString();
    const item: AiUseCase = {
      ...existing,
      ...fields,
      assessment: fields.assessment
        ? { ...fields.assessment, updatedAt: now, updatedBy: actor }
        : null,
      updatedAt: now,
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
      return item;
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /** false means the id did not exist. */
  async deleteUseCase(id: string): Promise<boolean> {
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
