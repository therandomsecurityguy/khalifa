import {
  BatchGetItemCommand,
  BatchWriteItemCommand,
  DynamoDBClient,
} from '@aws-sdk/client-dynamodb';
import { marshall } from '@aws-sdk/util-dynamodb';
import type { AttributeValue } from '@aws-sdk/client-dynamodb';
import { isIP } from 'node:net';

// Threat-intel indicators a customer supplies as plain lists (one indicator
// per line, '#' comments). AWS-native intelligence needs no import: GuardDuty
// applies AWS's managed reputation lists itself and the findings they drive
// already feed RULE-018/RULE-029 — this store adds the customer's own view
// ("is this IP or account on our list?") so matches can change ranking.
export type ThreatIndicatorType = 'ip' | 'account';

export interface ThreatIndicator {
  type: ThreatIndicatorType;
  value: string;
  /** Where the indicator came from, for the record (e.g. the list URI). */
  source: string;
}

export const THREAT_INDICATOR_MAX_LINES = 50_000;
export const THREAT_INDICATOR_DEFAULT_TTL_DAYS = 90;
const DAY_SECONDS = 86_400;
const MAX_LOOKUPS = 500;
const CHUNK_SIZE = 100;

export function indicatorKey(type: ThreatIndicatorType, value: string): string {
  return `${type}#${value}`;
}

export function isValidIndicator(type: ThreatIndicatorType, value: string): boolean {
  if (type === 'ip') return isIP(value) !== 0;
  return /^\d{12}$/.test(value);
}

export interface ParsedIndicatorList {
  indicators: ThreatIndicator[];
  /** Lines that were not valid for the type; skipped, not fatal. */
  invalid: number;
  truncated: boolean;
}

// Exact-value matching only: one indicator per line, whitespace trimmed,
// '#'-comments and blanks skipped, case-sensitive (IPs and account ids have
// no case). Duplicates collapse. The cap bounds the store and the log says
// when it bit.
export function parseIndicatorList(
  text: string,
  type: ThreatIndicatorType,
  source: string
): ParsedIndicatorList {
  const seen = new Set<string>();
  const indicators: ThreatIndicator[] = [];
  let invalid = 0;
  let truncated = false;
  for (const rawLine of text.split('\n')) {
    const line = rawLine.split('#')[0].trim();
    if (!line) continue;
    if (!isValidIndicator(type, line)) {
      invalid += 1;
      continue;
    }
    const key = indicatorKey(type, line);
    if (seen.has(key)) continue;
    seen.add(key);
    if (indicators.length >= THREAT_INDICATOR_MAX_LINES) {
      truncated = true;
      break;
    }
    indicators.push({ type, value: line, source });
  }
  return { indicators, invalid, truncated };
}

// Graph facts the matcher joins on: an anomaly's source IP and a trusted
// external account. Kept here (not in the runner) so the join is testable and
// shared with anything else that reads the store.
export function pathIndicators(path: {
  vertices: Array<{ label: string; properties: Record<string, unknown> }>;
}): Array<{ type: ThreatIndicatorType; value: string }> {
  const candidates = new Map<string, { type: ThreatIndicatorType; value: string }>();
  for (const vertex of path.vertices) {
    if (vertex.label === 'CloudTrailAnomaly') {
      const ip = vertex.properties.source_ip;
      if (typeof ip === 'string' && isValidIndicator('ip', ip)) {
        candidates.set(indicatorKey('ip', ip), { type: 'ip', value: ip });
      }
    }
    if (vertex.label === 'ExternalAccount') {
      const account = vertex.properties.account_id;
      if (typeof account === 'string' && isValidIndicator('account', account)) {
        candidates.set(indicatorKey('account', account), { type: 'account', value: account });
      }
    }
  }
  return [...candidates.values()];
}

export class ThreatIndicatorStore {
  private client: DynamoDBClient;

  constructor(
    private readonly tableName: string = process.env.THREAT_INDICATORS_TABLE || 'ThreatIndicators',
    client?: DynamoDBClient
  ) {
    this.client = client ?? new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
  }

  // One row per indicator, overwritten on every import; the TTL is what makes
  // an indicator stale (a list that stops including it drains itself).
  async put(
    indicators: ThreatIndicator[],
    ttlDays: number = THREAT_INDICATOR_DEFAULT_TTL_DAYS,
    now: Date = new Date()
  ): Promise<number> {
    const expiresAt = Math.floor(now.getTime() / 1000) + ttlDays * DAY_SECONDS;
    let written = 0;
    for (let index = 0; index < indicators.length; index += 25) {
      const chunk = indicators.slice(index, index + 25);
      const result = await this.client.send(
        new BatchWriteItemCommand({
          RequestItems: {
            [this.tableName]: chunk.map((indicator) => ({
              PutRequest: {
                Item: marshall({
                  indicator: indicatorKey(indicator.type, indicator.value),
                  type: indicator.type,
                  value: indicator.value,
                  source: indicator.source,
                  added_at: now.toISOString(),
                  expires_at: expiresAt,
                }) as Record<string, AttributeValue>,
              },
            })),
          },
        })
      );
      const unprocessed = result.UnprocessedItems?.[this.tableName] ?? [];
      written += chunk.length - unprocessed.length;
      if (unprocessed.length > 0) {
        throw new Error(
          `DynamoDB left ${unprocessed.length} threat indicators unprocessed; re-run the import`
        );
      }
    }
    return written;
  }

  // The stored indicators among these candidates; bounded like every other
  // read in the runner.
  async find(
    candidates: Array<{ type: ThreatIndicatorType; value: string }>
  ): Promise<ThreatIndicator[]> {
    const unique = [
      ...new Map(candidates.map((c) => [indicatorKey(c.type, c.value), c])).values(),
    ].slice(0, MAX_LOOKUPS);
    const found: ThreatIndicator[] = [];
    for (let index = 0; index < unique.length; index += CHUNK_SIZE) {
      const chunk = unique.slice(index, index + CHUNK_SIZE);
      const response = await this.client.send(
        new BatchGetItemCommand({
          RequestItems: {
            [this.tableName]: {
              Keys: chunk.map((candidate) => ({
                indicator: { S: indicatorKey(candidate.type, candidate.value) },
              })),
            },
          },
        })
      );
      for (const item of response.Responses?.[this.tableName] ?? []) {
        const type = item.type?.S as ThreatIndicatorType | undefined;
        const value = item.value?.S;
        if (!type || !value) continue;
        found.push({ type, value, source: item.source?.S ?? 'unknown' });
      }
    }
    return found;
  }
}
