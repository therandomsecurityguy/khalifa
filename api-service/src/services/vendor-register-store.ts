import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  DeleteCommand,
  GetCommand,
  PutCommand,
  ScanCommand,
} from '@aws-sdk/lib-dynamodb';
import { slugify } from './ai-use-case-store';

// The vendor register: third-party relationships maintained through the API.
// The subprocessor fields (purpose, location, dpaUrl) double as the trust
// center's subprocessor list, so flagging a vendor as a subprocessor requires
// them — a listing without a purpose and location is not a disclosure. Review
// cadence mirrors the risk register: a derived next-review date so an overdue
// vendor review is visible rather than implied.

export type VendorCategory = 'cloud' | 'ai' | 'security' | 'saas' | 'infrastructure' | 'other';
export type VendorStatus = 'active' | 'under-review' | 'terminated';

export interface VendorRecord {
  id: string;
  name: string;
  category: VendorCategory;
  purpose: string;
  location: string;
  dpaUrl: string | null;
  dataClasses: string[];
  owner: string;
  status: VendorStatus;
  subprocessor: boolean;
  renewalAt: string | null;
  reviewCadenceDays: number;
  lastReviewedAt: string | null;
  createdAt: string;
  createdBy: string;
  updatedAt: string;
  updatedBy: string;
}

export type VendorFields = Omit<
  VendorRecord,
  'id' | 'createdAt' | 'createdBy' | 'updatedAt' | 'updatedBy'
>;

export interface VendorRegisterEntry extends VendorRecord {
  nextReviewAt: string | null;
}

const MAX_NAME = 200;
const MAX_PURPOSE = 200;
const MAX_LOCATION = 120;
const MAX_URL = 512;
const MAX_OWNER = 120;
const MAX_DATA_CLASSES = 20;
const MAX_DATA_CLASS_LENGTH = 64;
const MAX_VENDORS = 500;
const DAY_MS = 24 * 60 * 60 * 1000;

export const VENDOR_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

const CATEGORIES: VendorCategory[] = ['cloud', 'ai', 'security', 'saas', 'infrastructure', 'other'];
const STATUSES: VendorStatus[] = ['active', 'under-review', 'terminated'];

export function toVendorEntry(record: VendorRecord): VendorRegisterEntry {
  const basis = Date.parse(record.lastReviewedAt ?? record.createdAt);
  const nextReviewAt = Number.isFinite(basis)
    ? new Date(basis + record.reviewCadenceDays * DAY_MS).toISOString()
    : null;
  return { ...record, nextReviewAt };
}

function trimmed(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const text = value.trim();
  return text.length <= max ? text : null;
}

function parseDpaUrl(value: unknown): string | null | { error: string } {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string' || value.length > MAX_URL) {
    return { error: `dpaUrl must be an https URL of at most ${MAX_URL} characters, or null` };
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return { error: 'dpaUrl must be a valid URL' };
  }
  if (parsed.protocol !== 'https:') {
    return { error: 'dpaUrl must use https' };
  }
  return parsed.toString();
}

function stringList(value: unknown): string[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > MAX_DATA_CLASSES) return null;
  const items = value
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
  if (items.length !== value.length || items.some((item) => item.length > MAX_DATA_CLASS_LENGTH)) {
    return null;
  }
  return [...new Set(items)];
}

export function parseVendorFields(
  body: Record<string, unknown>,
  fallbackOwner: string
): { fields: VendorFields } | { error: string } {
  const name = trimmed(body.name, MAX_NAME);
  if (!name) return { error: `name is required (1-${MAX_NAME} characters)` };

  const category = body.category === undefined ? 'other' : body.category;
  if (!CATEGORIES.includes(category as VendorCategory)) {
    return { error: `category must be one of: ${CATEGORIES.join(', ')}` };
  }

  const purpose = body.purpose === undefined ? '' : trimmed(body.purpose, MAX_PURPOSE);
  if (purpose === null) {
    return { error: `purpose must be a string of at most ${MAX_PURPOSE} characters` };
  }

  const location = body.location === undefined ? '' : trimmed(body.location, MAX_LOCATION);
  if (location === null) {
    return { error: `location must be a string of at most ${MAX_LOCATION} characters` };
  }

  const dpaUrl = parseDpaUrl(body.dpaUrl);
  if (dpaUrl !== null && typeof dpaUrl === 'object') return dpaUrl;

  const dataClasses = stringList(body.dataClasses);
  if (dataClasses === null) {
    return {
      error: `dataClasses must be at most ${MAX_DATA_CLASSES} strings of at most ${MAX_DATA_CLASS_LENGTH} characters`,
    };
  }

  const owner = body.owner === undefined ? fallbackOwner : trimmed(body.owner, MAX_OWNER);
  if (!owner) return { error: `owner is required (1-${MAX_OWNER} characters)` };

  const status = body.status === undefined ? 'active' : body.status;
  if (!STATUSES.includes(status as VendorStatus)) {
    return { error: `status must be one of: ${STATUSES.join(', ')}` };
  }

  const subprocessor = body.subprocessor === undefined ? false : body.subprocessor;
  if (typeof subprocessor !== 'boolean') {
    return { error: 'subprocessor must be a boolean' };
  }
  // A trust-center subprocessor listing needs its purpose and location; a
  // name-only entry is not a disclosure.
  if (subprocessor && (!purpose || !location)) {
    return { error: 'purpose and location are required for a subprocessor listing' };
  }

  let renewalAt: string | null = null;
  if (body.renewalAt !== undefined && body.renewalAt !== null) {
    const parsed = typeof body.renewalAt === 'string' ? Date.parse(body.renewalAt) : Number.NaN;
    if (!Number.isFinite(parsed)) {
      return { error: 'renewalAt must be an ISO timestamp or null' };
    }
    renewalAt = new Date(parsed).toISOString();
  }

  const reviewCadenceDays = body.reviewCadenceDays === undefined ? 365 : body.reviewCadenceDays;
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

  return {
    fields: {
      name,
      category: category as VendorCategory,
      purpose,
      location,
      dpaUrl,
      dataClasses,
      owner,
      status: status as VendorStatus,
      subprocessor,
      renewalAt,
      reviewCadenceDays: reviewCadenceDays as number,
      lastReviewedAt,
    },
  };
}

// Records come back from DynamoDB, not from this process, so every field is
// re-validated on read; a malformed row degrades to safe defaults rather than
// reaching a response.
export function mapVendorRecord(record: Record<string, unknown>): VendorRecord {
  const text = (value: unknown, max: number): string =>
    typeof value === 'string' ? value.slice(0, max) : '';
  const list = (value: unknown): string[] =>
    Array.isArray(value)
      ? value
          .filter((item): item is string => typeof item === 'string')
          .map((item) => item.slice(0, MAX_DATA_CLASS_LENGTH))
          .slice(0, MAX_DATA_CLASSES)
      : [];
  const url =
    typeof record.dpaUrl === 'string' && record.dpaUrl.startsWith('https://')
      ? record.dpaUrl.slice(0, MAX_URL)
      : null;
  return {
    id: text(record.id, 64),
    name: text(record.name, MAX_NAME),
    category: CATEGORIES.includes(record.category as VendorCategory)
      ? (record.category as VendorCategory)
      : 'other',
    purpose: text(record.purpose, MAX_PURPOSE),
    location: text(record.location, MAX_LOCATION),
    dpaUrl: url,
    dataClasses: list(record.dataClasses),
    owner: text(record.owner, MAX_OWNER),
    status: STATUSES.includes(record.status as VendorStatus)
      ? (record.status as VendorStatus)
      : 'active',
    subprocessor: record.subprocessor === true,
    renewalAt: typeof record.renewalAt === 'string' ? record.renewalAt.slice(0, 40) : null,
    reviewCadenceDays:
      Number.isSafeInteger(record.reviewCadenceDays) &&
      (record.reviewCadenceDays as number) >= 1 &&
      (record.reviewCadenceDays as number) <= 365
        ? (record.reviewCadenceDays as number)
        : 365,
    lastReviewedAt:
      typeof record.lastReviewedAt === 'string' ? record.lastReviewedAt.slice(0, 40) : null,
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

export class VendorRegisterStore {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string = process.env.VENDOR_REGISTER_TABLE || 'VendorRegister') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  async listVendors(): Promise<{ items: VendorRegisterEntry[]; truncated: boolean }> {
    const result = await this.docClient.send(
      new ScanCommand({ TableName: this.tableName, Limit: MAX_VENDORS + 1 })
    );
    const records = (result.Items || []) as Record<string, unknown>[];
    const items = records
      .slice(0, MAX_VENDORS)
      .map(mapVendorRecord)
      .filter((item) => item.id)
      .sort((a, b) => a.id.localeCompare(b.id, 'en'))
      .map(toVendorEntry);
    return { items, truncated: records.length > MAX_VENDORS };
  }

  async getVendor(id: string): Promise<VendorRegisterEntry | null> {
    const result = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id } })
    );
    return result.Item
      ? toVendorEntry(mapVendorRecord(result.Item as Record<string, unknown>))
      : null;
  }

  /** null means the id already exists. */
  async createVendor(
    id: string,
    fields: VendorFields,
    actor: string
  ): Promise<VendorRegisterEntry | null> {
    const now = new Date().toISOString();
    const item: VendorRecord = {
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
      return toVendorEntry(item);
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /** null means the id no longer exists. */
  async updateVendor(
    id: string,
    fields: VendorFields,
    actor: string
  ): Promise<VendorRegisterEntry | null> {
    const existing = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id } })
    );
    if (!existing.Item) return null;
    const item: VendorRecord = {
      ...mapVendorRecord(existing.Item as Record<string, unknown>),
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
      return toVendorEntry(item);
    } catch (error) {
      if (isConditionalFailure(error)) return null;
      throw error;
    }
  }

  /** false means the id does not exist. */
  async deleteVendor(id: string): Promise<boolean> {
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
