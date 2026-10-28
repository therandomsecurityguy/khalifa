import { GetObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { Logger } from '../shared/types';
import {
  parseIndicatorList,
  THREAT_INDICATOR_DEFAULT_TTL_DAYS,
  ThreatIndicatorStore,
  type ThreatIndicatorType,
} from '@khalifa/risk-engine';

// Customer-supplied threat intelligence, imported from plain S3 lists (one
// indicator per line, '#' comments). AWS's own managed reputation lists need
// no import: GuardDuty applies them and the findings they drive already feed
// RULE-018/RULE-029. Nothing here calls the internet — the list lives in an
// account-owned bucket, so the deployment keeps its AWS-API-only posture.
const logger = new Logger('threat-intel-import');
const defaultS3Client = new S3Client({ region: process.env.AWS_REGION || 'us-east-1' });

interface ImportEvent {
  ttlDays?: number;
}

interface ImportConfig {
  tableName: string;
  ttlDays: number;
  lists: Array<{ type: ThreatIndicatorType; uri: string }>;
}

interface ImportDependencies {
  s3Client: S3Client;
  store: ThreatIndicatorStore;
  now: () => Date;
}

export interface ThreatIntelImportResult {
  written: number;
  lists: Array<{
    type: ThreatIndicatorType;
    uri: string;
    indicators: number;
    invalid: number;
    truncated: boolean;
  }>;
}

export function validateTtlDays(value: unknown, name = 'THREAT_INTEL_TTL_DAYS'): number {
  const parsed =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && /^\d+$/.test(value.trim())
        ? Number(value)
        : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 365) {
    throw new Error(`${name} must be an integer between 1 and 365`);
  }
  return parsed;
}

// s3://bucket/key; the key may be empty only for listing, which this importer
// never does, so both parts are required.
export function parseS3Uri(uri: string): { bucket: string; key: string } {
  const match = /^s3:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\/(.+)$/.exec(uri.trim());
  if (!match) {
    throw new Error(`Threat-intel list URI must be s3://bucket/key: ${uri}`);
  }
  return { bucket: match[1], key: match[2] };
}

function loadConfig(environment: NodeJS.ProcessEnv): ImportConfig {
  const lists: ImportConfig['lists'] = [];
  for (const [type, name] of [
    ['ip', 'THREAT_INTEL_IP_LIST_S3_URI'],
    ['account', 'THREAT_INTEL_ACCOUNT_LIST_S3_URI'],
    ['cve', 'THREAT_INTEL_CVE_LIST_S3_URI'],
    ['epss', 'THREAT_INTEL_EPSS_LIST_S3_URI'],
  ] as const) {
    const uri = environment[name]?.trim();
    if (uri) lists.push({ type, uri });
  }
  if (lists.length === 0) {
    throw new Error(
      'At least one of THREAT_INTEL_IP_LIST_S3_URI, THREAT_INTEL_ACCOUNT_LIST_S3_URI, THREAT_INTEL_CVE_LIST_S3_URI or THREAT_INTEL_EPSS_LIST_S3_URI is required'
    );
  }
  return {
    tableName: environment.THREAT_INDICATORS_TABLE || 'ThreatIndicators',
    ttlDays: validateTtlDays(
      environment.THREAT_INTEL_TTL_DAYS ?? THREAT_INDICATOR_DEFAULT_TTL_DAYS
    ),
    lists,
  };
}

export async function importThreatIntel(
  event: ImportEvent = {},
  dependencyOverrides: Partial<ImportDependencies> = {},
  environment: NodeJS.ProcessEnv = process.env
): Promise<ThreatIntelImportResult> {
  const config = loadConfig(environment);
  const dependencies: ImportDependencies = {
    s3Client: defaultS3Client,
    store: new ThreatIndicatorStore(config.tableName),
    now: () => new Date(),
    ...dependencyOverrides,
  };
  const ttlDays = validateTtlDays(event.ttlDays ?? config.ttlDays);

  const result: ThreatIntelImportResult = { written: 0, lists: [] };
  for (const list of config.lists) {
    const { bucket, key } = parseS3Uri(list.uri);
    const response = await dependencies.s3Client.send(
      new GetObjectCommand({ Bucket: bucket, Key: key })
    );
    const text = (await response.Body?.transformToString()) ?? '';
    const parsed = parseIndicatorList(text, list.type, list.uri);
    if (parsed.invalid > 0 || parsed.truncated) {
      logger.warn('Threat-intel list had invalid lines or was truncated', {
        uri: list.uri,
        invalid: parsed.invalid,
        truncated: parsed.truncated,
      });
    }
    const written = await dependencies.store.put(parsed.indicators, ttlDays, dependencies.now());
    result.written += written;
    result.lists.push({
      type: list.type,
      uri: list.uri,
      indicators: parsed.indicators.length,
      invalid: parsed.invalid,
      truncated: parsed.truncated,
    });
    logger.info(`Imported ${written} ${list.type} indicators from ${list.uri}`);
  }
  return result;
}

export const handler = async (event: ImportEvent = {}): Promise<ThreatIntelImportResult> =>
  importThreatIntel(event);
