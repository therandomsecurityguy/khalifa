import { createHash, randomUUID } from 'crypto';
import type { GraphNode } from '../../shared/types';
import {
  ACCESS_DENIED_BASELINE_DAYS,
  ACCESS_DENIED_EVAL_DAYS,
  ACCESS_DENIED_SPIKE_THRESHOLD,
} from './baseline';

// Re-exported from baseline.ts, where the detection threshold lives.
export { ACCESS_DENIED_SPIKE_THRESHOLD };

export type AnomalyType =
  | 'ROOT_USAGE'
  | 'SECRET_READ_NEW_SOURCE_IP'
  | 'ACCESS_DENIED_SPIKE'
  | 'CANARY_USED'
  | 'NEW_API_FOR_PRINCIPAL'
  | 'UNUSUAL_HOUR_ACTIVITY';

export interface AnomalyRecord {
  type: AnomalyType;
  principalArn: string;
  sourceIp: string;
  eventCount: number;
  firstSeen: string;
  lastSeen: string;
  /** ACCESS_DENIED_SPIKE only: the principal's own daily-count baseline. */
  baselineMean?: number;
  baselineStddev?: number;
  baselineDays?: number;
  basis?: 'baseline' | 'cold-start';
  /** How many baseline standard deviations above the mean the spike is. */
  deviation?: number;
  /**
   * The behaviour that made the record new, for the query types that carry it
   * (NEW_API_FOR_PRINCIPAL: the API calls absent from the baseline;
   * UNUSUAL_HOUR_ACTIVITY: the UTC hours the principal never used before).
   */
  detail?: string;
}

export interface AnomalyQuery {
  type: AnomalyType;
  sql: string;
}

const EXCLUDED_EVENT_SOURCES = `'elasticloadbalancing.amazonaws.com', 'monitoring.amazonaws.com', 'logs.amazonaws.com'`;

export const SECRET_READ_NEW_IP_WINDOW_DAYS = 7;
export const SECRET_READ_BASELINE_MARGIN_DAYS = 30;
// The behavioural-breadth queries (API mix, hour-of-day) share one window:
// seven days evaluated against the thirty before them.
export const UEBA_WINDOW_DAYS = 7;
export const UEBA_BASELINE_DAYS = 30;
export const MAX_ANOMALY_DETAIL = 200;
const QUERY_TYPES_WITH_DETAIL = new Set<AnomalyType>([
  'NEW_API_FOR_PRINCIPAL',
  'UNUSUAL_HOUR_ACTIVITY',
]);
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
      // Baseline deviation, not a principal-age proxy: the baseline is the
      // DISTINCT source IPs this principal used in the
      // SECRET_READ_BASELINE_MARGIN_DAYS before the evaluation window, and a
      // secret read from an IP absent from that set is a new source. An IP
      // dormant for the whole baseline window and used again counts as new.
      sql: `
    WITH baseline_ips AS (
      SELECT DISTINCT
        useridentity.arn AS principal_arn,
        sourceipaddress AS source_ip
      FROM ${database}.cloudtrail_logs
      WHERE ${partitionWindow(SECRET_READ_NEW_IP_WINDOW_DAYS + SECRET_READ_BASELINE_MARGIN_DAYS)}
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${SECRET_READ_NEW_IP_WINDOW_DAYS + SECRET_READ_BASELINE_MARGIN_DAYS}' day
        AND from_iso8601_timestamp(eventtime) < current_timestamp - interval '${SECRET_READ_NEW_IP_WINDOW_DAYS}' day
        AND useridentity.arn IS NOT NULL
        AND useridentity.arn != ''
        AND sourceipaddress IS NOT NULL
    )
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
      WHERE ${partitionWindow(SECRET_READ_NEW_IP_WINDOW_DAYS)}
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${SECRET_READ_NEW_IP_WINDOW_DAYS}' day
        AND eventname IN ('GetSecretValue', 'BatchGetSecretValue')
        AND useridentity.arn IS NOT NULL
        AND useridentity.arn != ''
        AND sourceipaddress IS NOT NULL
      GROUP BY useridentity.arn, sourceipaddress
    ) reads
    LEFT JOIN baseline_ips
      ON reads.principal_arn = baseline_ips.principal_arn
      AND reads.source_ip = baseline_ips.source_ip
    WHERE baseline_ips.principal_arn IS NULL
  `,
    },
    {
      type: 'NEW_API_FOR_PRINCIPAL',
      // API mix: calls this principal made in the evaluation window that it
      // never made in the baseline window. A service the principal never
      // touched shows through its API calls (all of them are new).
      sql: `
    WITH baseline_events AS (
      SELECT DISTINCT
        useridentity.arn AS principal_arn,
        eventname
      FROM ${database}.cloudtrail_logs
      WHERE ${partitionWindow(UEBA_WINDOW_DAYS + UEBA_BASELINE_DAYS)}
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${UEBA_WINDOW_DAYS + UEBA_BASELINE_DAYS}' day
        AND from_iso8601_timestamp(eventtime) < current_timestamp - interval '${UEBA_WINDOW_DAYS}' day
        AND useridentity.arn IS NOT NULL
        AND useridentity.arn != ''
    )
    SELECT
      reads.principal_arn,
      reads.source_ip,
      COUNT(*) AS event_count,
      from_iso8601_timestamp(MIN(reads.eventtime)) AS first_seen,
      from_iso8601_timestamp(MAX(reads.eventtime)) AS last_seen,
      array_join(array_agg(DISTINCT reads.eventname), ', ') AS detail
    FROM (
      SELECT
        useridentity.arn AS principal_arn,
        sourceipaddress AS source_ip,
        eventname,
        eventtime
      FROM ${database}.cloudtrail_logs
      WHERE ${partitionWindow(UEBA_WINDOW_DAYS)}
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${UEBA_WINDOW_DAYS}' day
        AND useridentity.arn IS NOT NULL
        AND useridentity.arn != ''
        AND sourceipaddress IS NOT NULL
        AND eventsource NOT IN (${EXCLUDED_EVENT_SOURCES})
    ) reads
    LEFT JOIN baseline_events
      ON reads.principal_arn = baseline_events.principal_arn
      AND reads.eventname = baseline_events.eventname
    WHERE baseline_events.principal_arn IS NULL
    GROUP BY reads.principal_arn, reads.source_ip
  `,
    },
    {
      type: 'UNUSUAL_HOUR_ACTIVITY',
      // Time of day: UTC hours in which the principal acted during the
      // evaluation window but never during the baseline window. A principal
      // running at 03:00 for the first time is either a human in a new
      // timezone or automation that is not the principal's own.
      sql: `
    WITH baseline_hours AS (
      SELECT DISTINCT
        useridentity.arn AS principal_arn,
        hour(from_iso8601_timestamp(eventtime)) AS activity_hour
      FROM ${database}.cloudtrail_logs
      WHERE ${partitionWindow(UEBA_WINDOW_DAYS + UEBA_BASELINE_DAYS)}
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${UEBA_WINDOW_DAYS + UEBA_BASELINE_DAYS}' day
        AND from_iso8601_timestamp(eventtime) < current_timestamp - interval '${UEBA_WINDOW_DAYS}' day
        AND useridentity.arn IS NOT NULL
        AND useridentity.arn != ''
    )
    SELECT
      reads.principal_arn,
      reads.source_ip,
      COUNT(*) AS event_count,
      from_iso8601_timestamp(MIN(reads.eventtime)) AS first_seen,
      from_iso8601_timestamp(MAX(reads.eventtime)) AS last_seen,
      array_join(array_agg(DISTINCT CAST(reads.activity_hour AS varchar)), ', ') AS detail
    FROM (
      SELECT
        useridentity.arn AS principal_arn,
        sourceipaddress AS source_ip,
        eventtime,
        hour(from_iso8601_timestamp(eventtime)) AS activity_hour
      FROM ${database}.cloudtrail_logs
      WHERE ${partitionWindow(UEBA_WINDOW_DAYS)}
        AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${UEBA_WINDOW_DAYS}' day
        AND useridentity.arn IS NOT NULL
        AND useridentity.arn != ''
        AND sourceipaddress IS NOT NULL
        AND eventsource NOT IN (${EXCLUDED_EVENT_SOURCES})
    ) reads
    LEFT JOIN baseline_hours
      ON reads.principal_arn = baseline_hours.principal_arn
      AND reads.activity_hour = baseline_hours.activity_hour
    WHERE baseline_hours.principal_arn IS NULL
    GROUP BY reads.principal_arn, reads.source_ip
  `,
    },
    {
      type: 'ACCESS_DENIED_SPIKE',
      // Per-principal-per-IP-per-DAY counts over the evaluation window plus the
      // baseline. The deviation decision lives in baseline.ts (mean + 3
      // standard deviations, floor, cold-start fallback) so it is testable
      // against historical windows, not encoded in SQL.
      sql: `
    SELECT
      useridentity.arn AS principal_arn,
      sourceipaddress AS source_ip,
      date_format(from_iso8601_timestamp(eventtime), '%Y-%m-%d') AS day,
      COUNT(*) AS event_count,
      from_iso8601_timestamp(MIN(eventtime)) AS first_seen,
      from_iso8601_timestamp(MAX(eventtime)) AS last_seen
    FROM ${database}.cloudtrail_logs
    WHERE ${partitionWindow(ACCESS_DENIED_EVAL_DAYS + ACCESS_DENIED_BASELINE_DAYS)}
      AND from_iso8601_timestamp(eventtime) >= current_timestamp - interval '${ACCESS_DENIED_EVAL_DAYS + ACCESS_DENIED_BASELINE_DAYS}' day
      AND errorcode = 'AccessDenied'
      AND useridentity.arn IS NOT NULL
      AND useridentity.arn != ''
      AND sourceipaddress IS NOT NULL
      AND eventsource NOT IN (${EXCLUDED_EVENT_SOURCES})
    GROUP BY
      useridentity.arn,
      sourceipaddress,
      date_format(from_iso8601_timestamp(eventtime), '%Y-%m-%d')
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
  const expectedColumns = QUERY_TYPES_WITH_DETAIL.has(type) ? 6 : 5;
  if (!data || data.length !== expectedColumns) {
    throw new Error(`Invalid Athena anomaly row ${rowNumber}: expected ${expectedColumns} columns`);
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

  let detail: string | undefined;
  if (QUERY_TYPES_WITH_DETAIL.has(type)) {
    const rawDetail = requiredColumn(data[5].VarCharValue, 'detail', rowNumber);
    detail =
      rawDetail.length > MAX_ANOMALY_DETAIL
        ? `${rawDetail.slice(0, MAX_ANOMALY_DETAIL - 1)}…`
        : rawDetail;
  }

  return {
    type,
    principalArn,
    sourceIp,
    eventCount,
    firstSeen,
    lastSeen,
    ...(detail ? { detail } : {}),
  };
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
        ...(record.baselineMean !== undefined ? { baseline_mean: record.baselineMean } : {}),
        ...(record.baselineStddev !== undefined ? { baseline_stddev: record.baselineStddev } : {}),
        ...(record.baselineDays !== undefined ? { baseline_days: record.baselineDays } : {}),
        ...(record.basis !== undefined ? { basis: record.basis } : {}),
        ...(record.deviation !== undefined ? { deviation: record.deviation } : {}),
        ...(record.detail !== undefined ? { detail: record.detail } : {}),
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
