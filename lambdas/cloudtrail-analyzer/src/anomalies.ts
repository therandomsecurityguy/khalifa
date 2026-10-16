import { createHash, randomUUID } from 'crypto';
import type { GraphNode } from '../../shared/types';

export type AnomalyType =
  'ROOT_USAGE' | 'SECRET_READ_NEW_SOURCE_IP' | 'ACCESS_DENIED_SPIKE' | 'CANARY_USED';

export interface AnomalyRecord {
  type: AnomalyType;
  principalArn: string;
  sourceIp: string;
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
}

export interface AnomalyQuery {
  type: AnomalyType;
  sql: string;
}

const EXCLUDED_EVENT_SOURCES = `'elasticloadbalancing.amazonaws.com', 'monitoring.amazonaws.com', 'logs.amazonaws.com'`;

export const SECRET_READ_NEW_IP_WINDOW_DAYS = 7;
export const SECRET_READ_BASELINE_MARGIN_DAYS = 30;
export const ACCESS_DENIED_SPIKE_THRESHOLD = 20;
const MAX_QUERY_DAYS = 365;

export function assertAthenaDatabase(value: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,254}$/.test(value.trim()) || value !== value.trim()) {
    throw new Error('ATHENA_DATABASE must be an unquoted Athena identifier');
  }
  return value;
}

// The cloudtrail_logs table projects account_id / region / log_date
// partitions (yyyy/MM/dd). Every windowed query bounds log_date so Athena reads
// only the days in the window instead of the whole trail.
export function partitionWindow(days: number): string {
  return `log_date >= date_format(current_date - interval '${assertAnomalyQueryDays(days)}' day, '%Y/%m/%d')`;
}

export function assertAnomalyQueryDays(days: number): number {
  if (!Number.isSafeInteger(days) || days < 1 || days > MAX_QUERY_DAYS) {
    throw new Error(`Anomaly query days must be an integer between 1 and ${MAX_QUERY_DAYS}`);
  }
  return days;
}

const CANARY_PRINCIPAL_PATTERN = /^arn:aws(?:-us-gov|-cn)?:iam::\d{12}:user\/[A-Za-z0-9+=,.@_/-]+$/;

export function parseCanaryPrincipalArns(value: string | undefined): string[] {
  if (!value?.trim()) return [];
  const arns = value
    .split(',')
    .map((arn) => arn.trim())
    .filter(Boolean);
  for (const arn of arns) {
    if (!CANARY_PRINCIPAL_PATTERN.test(arn)) {
      throw new Error(`CANARY_PRINCIPAL_ARNS contains an invalid IAM user ARN: ${arn}`);
    }
  }
  return arns;
}

export function buildAnomalyQueries(
  database: string,
  days: number,
  canaryPrincipalArns: string[] = []
): AnomalyQuery[] {
  assertAthenaDatabase(database);
  const lookbackDays = assertAnomalyQueryDays(days);
  const queries: AnomalyQuery[] = [
    {
      type: 'ROOT_USAGE',
      sql: `
    SELECT
      useridentity.arn AS principal_arn,
      sourceipaddress AS source_ip,
      COUNT(*) AS event_count,
      from_iso8601_timestamp(MIN(eventtime)) AS first_seen,
      from_iso8601_timestamp(MAX(eventtime)) AS last_seen
    FROM ${database}.cloudtrail_logs
    WHERE ${partitionWindow(lookbackDays)}
      AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${lookbackDays}' day
      AND useridentity.arn LIKE '%:root'
      AND sourceipaddress IS NOT NULL
      AND eventsource NOT IN (${EXCLUDED_EVENT_SOURCES})
    GROUP BY useridentity.arn, sourceipaddress
  `,
    },
    {
      type: 'SECRET_READ_NEW_SOURCE_IP',
      sql: `
    SELECT
      reads.principal_arn,
      reads.source_ip,
      reads.event_count,
      from_iso8601_timestamp(reads.first_seen) AS first_seen,
      from_iso8601_timestamp(reads.last_seen) AS last_seen
    FROM (
      SELECT
        useridentity.arn AS principal_arn,
        sourceipaddress AS source_ip,
        COUNT(*) AS event_count,
        MIN(eventtime) AS first_seen,
        MAX(eventtime) AS last_seen
      FROM ${database}.cloudtrail_logs
      WHERE ${partitionWindow(lookbackDays)}
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${lookbackDays}' day
        AND eventname IN ('GetSecretValue', 'BatchGetSecretValue')
        AND useridentity.arn IS NOT NULL
        AND useridentity.arn != ''
        AND sourceipaddress IS NOT NULL
      GROUP BY useridentity.arn, sourceipaddress
    ) reads
    JOIN (
      SELECT
        useridentity.arn AS principal_arn,
        MIN(from_iso8601_timestamp(eventtime)) AS principal_first_seen
      FROM ${database}.cloudtrail_logs
      WHERE useridentity.arn IS NOT NULL
        AND useridentity.arn != ''
      GROUP BY useridentity.arn
    ) baseline
      ON reads.principal_arn = baseline.principal_arn
    WHERE from_iso8601_timestamp(reads.first_seen) >= current_timestamp - interval '${SECRET_READ_NEW_IP_WINDOW_DAYS}' day
      AND baseline.principal_first_seen < from_iso8601_timestamp(reads.first_seen) - interval '${SECRET_READ_BASELINE_MARGIN_DAYS}' day
  `,
    },
    {
      type: 'ACCESS_DENIED_SPIKE',
      sql: `
    SELECT
      useridentity.arn AS principal_arn,
      sourceipaddress AS source_ip,
      COUNT(*) AS event_count,
      from_iso8601_timestamp(MIN(eventtime)) AS first_seen,
      from_iso8601_timestamp(MAX(eventtime)) AS last_seen
    FROM ${database}.cloudtrail_logs
    WHERE ${partitionWindow(lookbackDays)}
      AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${lookbackDays}' day
      AND errorcode = 'AccessDenied'
      AND useridentity.arn IS NOT NULL
      AND useridentity.arn != ''
      AND sourceipaddress IS NOT NULL
      AND eventsource NOT IN (${EXCLUDED_EVENT_SOURCES})
    GROUP BY useridentity.arn, sourceipaddress
    HAVING COUNT(*) >= ${ACCESS_DENIED_SPIKE_THRESHOLD}
  `,
    },
  ];

  if (canaryPrincipalArns.length > 0) {
    // ARNs are validated by CANARY_PRINCIPAL_PATTERN, which excludes quote characters.
    const canaryList = canaryPrincipalArns.map((arn) => `'${arn}'`).join(', ');
    queries.push({
      type: 'CANARY_USED',
      sql: `
    SELECT
      useridentity.arn AS principal_arn,
      sourceipaddress AS source_ip,
      COUNT(*) AS event_count,
      from_iso8601_timestamp(MIN(eventtime)) AS first_seen,
      from_iso8601_timestamp(MAX(eventtime)) AS last_seen
    FROM ${database}.cloudtrail_logs
    WHERE ${partitionWindow(lookbackDays)}
      AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${lookbackDays}' day
      AND useridentity.arn IN (${canaryList})
      AND sourceipaddress IS NOT NULL
    GROUP BY useridentity.arn, sourceipaddress
  `,
    });
  }

  return queries;
}

export function parseAnomalyRow(
  type: AnomalyType,
  data: { VarCharValue?: string }[],
  rowNumber: number
): AnomalyRecord {
  if (!data || data.length !== 5) {
    throw new Error(`Invalid Athena anomaly row ${rowNumber}: expected 5 columns`);
  }

  const principalArn = requiredColumn(data[0].VarCharValue, 'principal_arn', rowNumber);
  const sourceIp = requiredColumn(data[1].VarCharValue, 'source_ip', rowNumber);
  const rawEventCount = requiredColumn(data[2].VarCharValue, 'event_count', rowNumber);
  const firstSeen = requiredColumn(data[3].VarCharValue, 'first_seen', rowNumber);
  const lastSeen = requiredColumn(data[4].VarCharValue, 'last_seen', rowNumber);

  if (!/^\d+$/.test(rawEventCount)) {
    throw new Error(`Invalid Athena anomaly row ${rowNumber}: event_count must be an integer`);
  }
  const eventCount = Number(rawEventCount);
  if (!Number.isSafeInteger(eventCount) || eventCount < 1) {
    throw new Error(`Invalid Athena anomaly row ${rowNumber}: event_count must be positive`);
  }
  for (const [name, value] of [
    ['first_seen', firstSeen],
    ['last_seen', lastSeen],
  ] as const) {
    if (Number.isNaN(Date.parse(value))) {
      throw new Error(`Invalid Athena anomaly row ${rowNumber}: ${name} must be a timestamp`);
    }
  }

  return { type, principalArn, sourceIp, eventCount, firstSeen, lastSeen };
}

export function anomalyAccountId(principalArn: string): string {
  const match = principalArn.match(/arn:aws(?:-us-gov|-cn)?:(?:iam|sts)::(\d{12}):/);
  return match ? match[1] : 'unknown';
}

export function buildAnomalyNodes(
  records: AnomalyRecord[],
  runId: string = randomUUID(),
  observedAt: string = new Date().toISOString()
): GraphNode[] {
  return records.map((record) => {
    const account = anomalyAccountId(record.principalArn);
    const identity = createHash('sha256')
      .update(`${record.type}\0${record.principalArn}\0${record.sourceIp}`)
      .digest('hex')
      .slice(0, 24);
    const id = `arn:aws:khalifa:anomaly:${account}:cloudtrail-anomaly/${record.type}/${identity}`;
    return {
      id,
      label: 'CloudTrailAnomaly',
      observedAt,
      properties: {
        id: `${record.type}/${identity}`,
        arn: id,
        account_id: account,
        anomaly_type: record.type,
        principal_arn: record.principalArn,
        source_ip: record.sourceIp,
        event_count: record.eventCount,
        first_seen: record.firstSeen,
        last_seen: record.lastSeen,
        collection_scope: 'cloudtrail-anomalies',
        collection_run_id: runId,
        active: true,
      },
    };
  });
}

export function reconcileAnomalies(
  runId: string = randomUUID(),
  observedAt: string = new Date().toISOString()
): { scope: string; runId: string; observedAt: string } {
  return {
    scope: 'cloudtrail-anomalies',
    runId,
    observedAt,
  };
}

function requiredColumn(value: string | undefined, name: string, rowNumber: number): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`Invalid Athena anomaly row ${rowNumber}: ${name} is required`);
  }
  return normalized;
}
