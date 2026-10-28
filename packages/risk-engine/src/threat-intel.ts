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
// ("is this IP, account, or CVE on our list?") so matches can change ranking.
// `cve` carries known-exploited membership (e.g. an export of the CISA KEV
// catalogue's CVE ids); `epss` carries a score per CVE ("CVE-2024-1234,0.97")
// and feeds the exploitability factor directly.
export type ThreatIndicatorType = 'ip' | 'account' | 'cve' | 'epss';

export interface ThreatIndicator {
  type: ThreatIndicatorType;
  value: string;
  /** Where the indicator came from, for the record (e.g. the list URI). */
  source: string;
  /** EPSS-indicator only: the probability score (0..1). */
  score?: number;
}

export const THREAT_INDICATOR_MAX_LINES = 50_000;
export const THREAT_INDICATOR_DEFAULT_TTL_DAYS = 90;
const DAY_SECONDS = 86_400;
const MAX_LOOKUPS = 500;
const CHUNK_SIZE = 100;

export function indicatorKey(type: ThreatIndicatorType, value: string): string {
  return `${type}#${value}`;
}

const CVE_PATTERN = /^CVE-\d{4}-\d{4,}$/i;

export function isValidIndicator(type: ThreatIndicatorType, value: string): boolean {
  if (type === 'ip') return isIP(value) !== 0;
  if (type === 'cve' || type === 'epss') return CVE_PATTERN.test(value);
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
    const parsed = type === 'epss' ? parseEpssLine(line) : { value: line };
    if (!parsed || !isValidIndicator(type, parsed.value)) {
      invalid += 1;
      continue;
    }
    // CVE ids are case-insensitive identifiers; the store keeps one casing.
    const value = parsed.value.toUpperCase();
    const key = indicatorKey(type, value);
    if (seen.has(key)) continue;
    seen.add(key);
    if (indicators.length >= THREAT_INDICATOR_MAX_LINES) {
      truncated = true;
      break;
    }
    indicators.push({
      type,
      value,
      source,
      ...(parsed.score !== undefined ? { score: parsed.score } : {}),
    });
  }
  return { indicators, invalid, truncated };
}

// EPSS lines are "CVE-2024-1234,0.97" (a CSV's first two columns work as-is);
// a CVE without its score is not a usable EPSS indicator.
function parseEpssLine(line: string): { value: string; score?: number } | undefined {
  const [rawValue, rawScore] = line.split(',');
  const value = rawValue?.trim();
  if (!value || rawScore === undefined) return undefined;
  const score = Number(rawScore.trim());
  if (!Number.isFinite(score) || score < 0 || score > 1) return undefined;
  return { value, score };
}

// Graph facts the matcher joins on: an anomaly's source IP, a trusted
// external account, and a vulnerability's CVE id (candidate for both the
// known-exploited list and EPSS scores). Kept here (not in the runner) so the
// join is testable and shared with anything else that reads the store.
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
    if (vertex.label === 'Vulnerability') {
      const cve = vertex.properties.cve_id;
      if (typeof cve === 'string' && isValidIndicator('cve', cve)) {
        const value = cve.toUpperCase();
        candidates.set(indicatorKey('cve', value), { type: 'cve', value });
        candidates.set(indicatorKey('epss', value), { type: 'epss', value });
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
                  ...(indicator.score !== undefined ? { score: indicator.score } : {}),
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
        const score = Number(item.score?.N);
        found.push({
          type,
          value,
          source: item.source?.S ?? 'unknown',
          ...(item.score?.N !== undefined && Number.isFinite(score) ? { score } : {}),
        });
      }
    }
    return found;
  }
}
