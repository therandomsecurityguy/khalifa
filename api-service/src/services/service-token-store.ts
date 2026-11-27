import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'crypto';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  ScanCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';

// Scoped service tokens: machine credentials for automation (CI, scripts,
// long-running MCP clients) that cannot hold a human Cognito session.
//
// Design: the token is `khalifa_<uuid>_<64 hex chars>`; only a SHA-256 hash of
// the secret half is stored, so a database read cannot reconstruct a token.
// A token carries ONE role — viewer or analyst, never admin: administrative
// actions stay human-only. Expiry is mandatory and bounded (1-90 days), and
// revocation is immediate (a revoked or expired record fails verification even
// while the row exists). Last use is recorded, throttled so a busy client
// cannot turn verification into a write on every request.

export type ServiceTokenRole = 'viewer' | 'analyst';

export interface ServiceTokenRecord {
  id: string;
  name: string;
  role: ServiceTokenRole;
  expiresAt: string;
  createdAt: string;
  createdBy: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

export interface ServiceTokenInput {
  name: string;
  role: ServiceTokenRole;
  expiresInDays: number;
}

export interface VerifiedServiceToken {
  id: string;
  name: string;
  role: ServiceTokenRole;
}

const TOKEN_PREFIX = 'khalifa_';
// UUID plus 64 hex characters; fixed-length classes only, so the pattern
// itself carries no backtracking risk.
const TOKEN_PATTERN =
  /^khalifa_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}_[0-9a-f]{64}$/;
const SECRET_BYTES = 32;
const MAX_NAME_LENGTH = 120;
const DEFAULT_EXPIRY_DAYS = 30;
const MAX_EXPIRY_DAYS = 90;
const LAST_USED_THROTTLE_MS = 5 * 60 * 1000;
// Hand-maintained automation credentials; a page this size is already
// generous, and the bound keeps a scan from streaming an unbounded table.
const MAX_TOKENS = 500;

const ROLES: ServiceTokenRole[] = ['viewer', 'analyst'];

export function parseServiceToken(token: string): { id: string; secret: string } | null {
  if (!TOKEN_PATTERN.test(token)) return null;
  const body = token.slice(TOKEN_PREFIX.length);
  const separator = body.indexOf('_');
  return { id: body.slice(0, separator), secret: body.slice(separator + 1) };
}

export function hashServiceSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

export function serviceSecretMatches(secret: string, storedHash: string): boolean {
  const candidate = Buffer.from(hashServiceSecret(secret), 'hex');
  const expected = Buffer.from(storedHash, 'hex');
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

export function parseServiceTokenInput(
  body: Record<string, unknown>
): { input: ServiceTokenInput } | { error: string } {
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (!name || name.length > MAX_NAME_LENGTH) {
    return { error: `name is required (1-${MAX_NAME_LENGTH} characters)` };
  }
  const role = body.role === undefined ? 'viewer' : body.role;
  if (!ROLES.includes(role as ServiceTokenRole)) {
    return { error: `role must be one of: ${ROLES.join(', ')}` };
  }
  const expiresInDays = body.expiresInDays === undefined ? DEFAULT_EXPIRY_DAYS : body.expiresInDays;
  if (
    typeof expiresInDays !== 'number' ||
    !Number.isSafeInteger(expiresInDays) ||
    expiresInDays < 1 ||
    expiresInDays > MAX_EXPIRY_DAYS
  ) {
    return { error: `expiresInDays must be an integer between 1 and ${MAX_EXPIRY_DAYS}` };
  }
  return { input: { name, role: role as ServiceTokenRole, expiresInDays } };
}

// Records come back from DynamoDB, not from this process, so every field is
// re-validated on read; a malformed row degrades to safe defaults rather than
// reaching a response.
export function mapServiceTokenRecord(record: Record<string, unknown>): ServiceTokenRecord {
  const text = (value: unknown, max: number): string =>
    typeof value === 'string' ? value.slice(0, max) : '';
  return {
    id: text(record.id, 36),
    name: text(record.name, MAX_NAME_LENGTH),
    role: ROLES.includes(record.role as ServiceTokenRole)
      ? (record.role as ServiceTokenRole)
      : 'viewer',
    expiresAt: text(record.expiresAt, 40),
    createdAt: text(record.createdAt, 40),
    createdBy: text(record.createdBy, 320),
    lastUsedAt: typeof record.lastUsedAt === 'string' ? record.lastUsedAt : null,
    revokedAt: typeof record.revokedAt === 'string' ? record.revokedAt : null,
  };
}

function isConditionalFailure(error: unknown): boolean {
  return error instanceof Error && error.name === 'ConditionalCheckFailedException';
}

// Expiry fails closed: a missing or malformed timestamp is treated as expired,
// never as a token that never expires.
export function isServiceTokenExpired(expiresAt: string, nowMs: number = Date.now()): boolean {
  const parsed = Date.parse(expiresAt);
  return !Number.isFinite(parsed) || parsed <= nowMs;
}

// Any non-null revocation marker counts, valid timestamp or not: a malformed
// record must not read as revoked-free.
export function isServiceTokenRevoked(revokedAt: unknown): boolean {
  return revokedAt !== undefined && revokedAt !== null;
}

export class ServiceTokenStore {
  private docClient: DynamoDBDocumentClient;
  private tableName: string;

  constructor(tableName: string = process.env.SERVICE_TOKENS_TABLE || 'ServiceTokens') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.docClient = DynamoDBDocumentClient.from(client);
    this.tableName = tableName;
  }

  /** The plaintext token is returned once and never stored. */
  async createToken(
    input: ServiceTokenInput,
    actor: string
  ): Promise<{ token: string; record: ServiceTokenRecord }> {
    const id = randomUUID();
    const secret = randomBytes(SECRET_BYTES).toString('hex');
    const now = new Date();
    const item = {
      id,
      name: input.name,
      role: input.role,
      secretHash: hashServiceSecret(secret),
      createdAt: now.toISOString(),
      createdBy: actor,
      expiresAt: new Date(now.getTime() + input.expiresInDays * 24 * 60 * 60 * 1000).toISOString(),
      lastUsedAt: null,
      revokedAt: null,
    };
    await this.docClient.send(
      new PutCommand({
        TableName: this.tableName,
        Item: item,
        ConditionExpression: 'attribute_not_exists(id)',
      })
    );
    return { token: `${TOKEN_PREFIX}${id}_${secret}`, record: mapServiceTokenRecord(item) };
  }

  async listTokens(): Promise<ServiceTokenRecord[]> {
    const result = await this.docClient.send(
      new ScanCommand({ TableName: this.tableName, Limit: MAX_TOKENS + 1 })
    );
    return ((result.Items || []) as Record<string, unknown>[])
      .slice(0, MAX_TOKENS)
      .map(mapServiceTokenRecord)
      .filter((record) => record.id)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt, 'en'));
  }

  /** false means the id does not exist or is already revoked. */
  async revokeToken(id: string): Promise<boolean> {
    try {
      await this.docClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { id },
          UpdateExpression: 'SET revokedAt = :revokedAt',
          ConditionExpression: 'attribute_exists(id) AND attribute_not_exists(revokedAt)',
          ExpressionAttributeValues: { ':revokedAt': new Date().toISOString() },
        })
      );
      return true;
    } catch (error) {
      if (isConditionalFailure(error)) return false;
      throw error;
    }
  }

  /**
   * Verifies a full token: shape, existence, revocation, expiry, and a
   * constant-time secret comparison against the stored hash. Never returns the
   * stored record — callers only get the identity fields they need.
   */
  async verifyToken(token: string): Promise<VerifiedServiceToken | null> {
    const parsed = parseServiceToken(token);
    if (!parsed) return null;

    const result = await this.docClient.send(
      new GetCommand({ TableName: this.tableName, Key: { id: parsed.id } })
    );
    const item = result.Item as Record<string, unknown> | undefined;
    if (!item) return null;

    const record = mapServiceTokenRecord(item);
    if (isServiceTokenRevoked(item.revokedAt)) return null;
    if (isServiceTokenExpired(record.expiresAt)) return null;
    const storedHash = typeof item.secretHash === 'string' ? item.secretHash : '';
    if (!storedHash || !serviceSecretMatches(parsed.secret, storedHash)) return null;

    await this.markUsed(record.id);
    return { id: record.id, name: record.name, role: record.role };
  }

  /** Throttled: updates lastUsedAt at most once per five minutes per token. */
  private async markUsed(id: string): Promise<void> {
    try {
      await this.docClient.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { id },
          UpdateExpression: 'SET lastUsedAt = :now',
          ConditionExpression: 'attribute_not_exists(lastUsedAt) OR lastUsedAt < :cutoff',
          ExpressionAttributeValues: {
            ':now': new Date().toISOString(),
            ':cutoff': new Date(Date.now() - LAST_USED_THROTTLE_MS).toISOString(),
          },
        })
      );
    } catch (error) {
      // The token is already verified; a lost usage stamp must never fail the
      // request. Conditional failures are the throttle working as designed.
      if (!isConditionalFailure(error)) {
        console.error('Failed to record service-token use:', error);
      }
    }
  }
}

// One shared store for the auth middleware; the DynamoDB client is built on
// first use, not at import.
let sharedStore: ServiceTokenStore | null = null;

export async function verifyServiceToken(token: string): Promise<VerifiedServiceToken | null> {
  sharedStore ??= new ServiceTokenStore();
  return sharedStore.verifyToken(token);
}
