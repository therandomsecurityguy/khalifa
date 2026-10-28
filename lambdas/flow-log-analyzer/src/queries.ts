export interface TrafficObservation {
  accountId: string;
  region: string;
  interfaceId: string;
  packets: number;
  bytes: number;
  flows: number;
  firstSeen: string;
  lastSeen: string;
}

export const DEFAULT_OBSERVATION_DAYS = 7;
export const MAX_OBSERVATION_DAYS = 31;
// One observation row per interface; an account with huge fan-out is capped
// rather than unbounded, and the truncation is logged.
export const MAX_OBSERVATIONS = 5000;

export function validateObservationDays(value: unknown, name = 'FLOW_LOG_DAYS'): number {
  const parsed =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && /^\d+$/.test(value.trim())
        ? Number(value)
        : Number.NaN;
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > MAX_OBSERVATION_DAYS) {
    throw new Error(`${name} must be an integer between 1 and ${MAX_OBSERVATION_DAYS}`);
  }
  return parsed;
}

export function assertAthenaDatabase(value: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,254}$/.test(value.trim()) || value !== value.trim()) {
    throw new Error('ATHENA_DATABASE must be an unquoted Athena identifier');
  }
  return value;
}

// The vpc_flow_logs Glue table (khalifa-data, athena.tf) projects
// account_id / region / log_date over the standard AWSLogs layout, so the
// log_date predicate reads only the window instead of every flow-log file.
export function buildTrafficQuery(database: string, days: number): string {
  assertAthenaDatabase(database);
  const window = validateObservationDays(days);
  return `
    SELECT
      account_id,
      region,
      interface_id,
      SUM(packets) AS packets,
      SUM(bytes) AS bytes,
      COUNT(*) AS flows,
      date_format(from_unixtime(MIN(start)), '%Y-%m-%dT%H:%i:%sZ') AS first_seen,
      date_format(from_unixtime(MAX(end)), '%Y-%m-%dT%H:%i:%sZ') AS last_seen
    FROM ${database}.vpc_flow_logs
    WHERE log_date >= date_format(current_date - interval '${window}' day, '%Y/%m/%d')
      AND action = 'ACCEPT'
      AND interface_id IS NOT NULL
      AND interface_id <> '-'
      AND from_unixtime(start) >= current_timestamp - interval '${window}' day
    GROUP BY account_id, region, interface_id
  `;
}

export function parseTrafficRow(
  data: { VarCharValue?: string }[],
  rowNumber: number
): TrafficObservation {
  if (!data || data.length !== 8) {
    throw new Error(`Invalid Athena traffic row ${rowNumber}: expected 8 columns`);
  }
  const accountId = required(data[0].VarCharValue, 'account_id', rowNumber);
  const region = required(data[1].VarCharValue, 'region', rowNumber);
  const interfaceId = required(data[2].VarCharValue, 'interface_id', rowNumber);
  const packets = safeCount(data[3].VarCharValue, 'packets', rowNumber);
  const bytes = safeCount(data[4].VarCharValue, 'bytes', rowNumber);
  const flows = safeCount(data[5].VarCharValue, 'flows', rowNumber);
  const firstSeen = timestamp(data[6].VarCharValue, 'first_seen', rowNumber);
  const lastSeen = timestamp(data[7].VarCharValue, 'last_seen', rowNumber);
  if (!/^\d{12}$/.test(accountId)) {
    throw new Error(`Invalid Athena traffic row ${rowNumber}: account_id must be 12 digits`);
  }
  return { accountId, region, interfaceId, packets, bytes, flows, firstSeen, lastSeen };
}

function required(value: string | undefined, name: string, rowNumber: number): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`Invalid Athena traffic row ${rowNumber}: ${name} is required`);
  }
  return normalized;
}

function safeCount(value: string | undefined, name: string, rowNumber: number): number {
  const normalized = required(value, name, rowNumber);
  if (!/^\d+$/.test(normalized)) {
    throw new Error(`Invalid Athena traffic row ${rowNumber}: ${name} must be an integer`);
  }
  const parsed = Number(normalized);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`Invalid Athena traffic row ${rowNumber}: ${name} is out of range`);
  }
  return parsed;
}

function timestamp(value: string | undefined, name: string, rowNumber: number): string {
  const normalized = required(value, name, rowNumber);
  if (Number.isNaN(Date.parse(normalized))) {
    throw new Error(`Invalid Athena traffic row ${rowNumber}: ${name} must be a timestamp`);
  }
  return normalized;
}

export interface TrafficEndpoint {
  accountId: string;
  region: string;
  interfaceId: string;
  remoteAddress: string;
  packets: number;
  bytes: number;
  flows: number;
  lastSeen: string;
}

// Cost bounds for the endpoint aggregation: one extra Athena query over the
// same window, top-N remote endpoints per interface (a window-function rank),
// and a row cap on what is parsed. The write stays one attribute list per
// interface, so the DynamoDB item size grows by a few hundred bytes at most.
export const ENDPOINTS_PER_INTERFACE = 5;
export const MAX_ENDPOINT_ROWS = 25_000;

export function validateEndpointsPerInterface(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 20) {
    throw new Error('ENDPOINTS_PER_INTERFACE must be an integer between 1 and 20');
  }
  return value;
}

// Which remote endpoints (srcaddr — the ingress source) actually sent accepted
// traffic to each interface, ranked by bytes and capped per interface. The
// endpoint evidence lets an attack path cite observed traffic on a hop, not
// just "this instance saw traffic somewhere".
export function buildEndpointQuery(
  database: string,
  days: number,
  perInterface: number = ENDPOINTS_PER_INTERFACE
): string {
  assertAthenaDatabase(database);
  const window = validateObservationDays(days);
  const rank = validateEndpointsPerInterface(perInterface);
  return `
    SELECT interface_id, account_id, region, srcaddr, packets, bytes, flows, last_seen
    FROM (
      SELECT
        account_id,
        region,
        interface_id,
        srcaddr,
        SUM(packets) AS packets,
        SUM(bytes) AS bytes,
        COUNT(*) AS flows,
        date_format(from_unixtime(MAX(end)), '%Y-%m-%dT%H:%i:%sZ') AS last_seen,
        ROW_NUMBER() OVER (PARTITION BY interface_id ORDER BY SUM(bytes) DESC, srcaddr ASC) AS endpoint_rank
      FROM ${database}.vpc_flow_logs
      WHERE log_date >= date_format(current_date - interval '${window}' day, '%Y/%m/%d')
        AND action = 'ACCEPT'
        AND interface_id IS NOT NULL
        AND interface_id <> '-'
        AND srcaddr IS NOT NULL
        AND srcaddr <> '-'
        AND from_unixtime(start) >= current_timestamp - interval '${window}' day
      GROUP BY account_id, region, interface_id, srcaddr
    )
    WHERE endpoint_rank <= ${rank}
    ORDER BY interface_id, endpoint_rank
  `;
}

export function parseEndpointRow(
  data: { VarCharValue?: string }[],
  rowNumber: number
): TrafficEndpoint {
  if (!data || data.length !== 8) {
    throw new Error(`Invalid Athena endpoint row ${rowNumber}: expected 8 columns`);
  }
  const interfaceId = required(data[0].VarCharValue, 'interface_id', rowNumber);
  const accountId = required(data[1].VarCharValue, 'account_id', rowNumber);
  const region = required(data[2].VarCharValue, 'region', rowNumber);
  const remoteAddress = required(data[3].VarCharValue, 'srcaddr', rowNumber);
  if (!/^[0-9A-Fa-f.:]{3,45}$/.test(remoteAddress)) {
    throw new Error(`Invalid Athena endpoint row ${rowNumber}: srcaddr must be an IP address`);
  }
  const packets = safeCount(data[4].VarCharValue, 'packets', rowNumber);
  const bytes = safeCount(data[5].VarCharValue, 'bytes', rowNumber);
  const flows = safeCount(data[6].VarCharValue, 'flows', rowNumber);
  const lastSeen = timestamp(data[7].VarCharValue, 'last_seen', rowNumber);
  if (!/^\d{12}$/.test(accountId)) {
    throw new Error(`Invalid Athena endpoint row ${rowNumber}: account_id must be 12 digits`);
  }
  return { accountId, region, interfaceId, remoteAddress, packets, bytes, flows, lastSeen };
}
