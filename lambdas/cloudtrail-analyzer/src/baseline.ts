import type { AnomalyRecord } from './anomalies';

// Per-principal behavioral baselines for the AccessDenied signal. The old rule
// was a fixed 20-per-lookback threshold: it false-positived on principals that
// legitimately deny a lot and missed a quiet principal jumping to 12. The
// baseline compares each day in the evaluation window against the principal's
// own daily-count mean and spread; the fixed threshold stays only for cold
// start, when there are too few baseline days to judge.
export const ACCESS_DENIED_EVAL_DAYS = 7;
export const ACCESS_DENIED_BASELINE_DAYS = 30;
export const ACCESS_DENIED_MIN_BASELINE_DAYS = 7;
export const ACCESS_DENIED_DEVIATIONS = 3;
export const ACCESS_DENIED_MIN_COUNT = 10;
// A perfectly steady baseline has zero spread; without slack every extra
// denied call would flag. The threshold treats 10% of the mean as the floor
// on the standard deviation, so a steady 25/day only flags well above 32.
export const ACCESS_DENIED_STDDEV_FLOOR_RATIO = 0.1;
// Cold start: without a baseline, keep the previous fixed threshold.
export const ACCESS_DENIED_SPIKE_THRESHOLD = 20;

const DAY_MS = 86_400_000;

export interface DailyDeniedCount {
  principalArn: string;
  sourceIp: string;
  /** yyyy-MM-dd, UTC. */
  day: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
}

const DAY_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

export function parseDeniedCountRow(
  data: { VarCharValue?: string }[],
  rowNumber: number
): DailyDeniedCount {
  if (!data || data.length !== 6) {
    throw new Error(`Invalid Athena denied-count row ${rowNumber}: expected 6 columns`);
  }
  const principalArn = required(data[0].VarCharValue, 'principal_arn', rowNumber);
  const sourceIp = required(data[1].VarCharValue, 'source_ip', rowNumber);
  const day = required(data[2].VarCharValue, 'day', rowNumber);
  const rawCount = required(data[3].VarCharValue, 'event_count', rowNumber);
  const firstSeen = required(data[4].VarCharValue, 'first_seen', rowNumber);
  const lastSeen = required(data[5].VarCharValue, 'last_seen', rowNumber);

  if (!DAY_PATTERN.test(day) || Number.isNaN(Date.parse(`${day}T00:00:00Z`))) {
    throw new Error(`Invalid Athena denied-count row ${rowNumber}: day must be yyyy-MM-dd`);
  }
  if (!/^\d+$/.test(rawCount)) {
    throw new Error(`Invalid Athena denied-count row ${rowNumber}: event_count must be an integer`);
  }
  const count = Number(rawCount);
  if (!Number.isSafeInteger(count) || count < 1) {
    throw new Error(`Invalid Athena denied-count row ${rowNumber}: event_count must be positive`);
  }
  for (const [name, value] of [
    ['first_seen', firstSeen],
    ['last_seen', lastSeen],
  ] as const) {
    if (Number.isNaN(Date.parse(value))) {
      throw new Error(`Invalid Athena denied-count row ${rowNumber}: ${name} must be a timestamp`);
    }
  }

  return { principalArn, sourceIp, day, count, firstSeen, lastSeen };
}

function utcDayStart(time: number): number {
  return Date.parse(`${new Date(time).toISOString().slice(0, 10)}T00:00:00Z`);
}

function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

// One record per principal+IP whose worst evaluation-window day crossed the
// threshold: the principal's baseline mean + ACCESS_DENIED_DEVIATIONS standard
// deviations (never below ACCESS_DENIED_MIN_COUNT), or the fixed threshold when
// the data does not cover ACCESS_DENIED_MIN_BASELINE_DAYS. Baseline days with
// no activity count as zero, so a sporadic principal's spread is real.
export function detectDeniedSpikes(
  rows: DailyDeniedCount[],
  now: Date = new Date()
): AnomalyRecord[] {
  if (rows.length === 0) return [];

  const evalStart = utcDayStart(now.getTime()) - (ACCESS_DENIED_EVAL_DAYS - 1) * DAY_MS;
  const baselineEnd = evalStart - DAY_MS;
  const earliest = Math.min(...rows.map((row) => Date.parse(`${row.day}T00:00:00Z`)));
  const baselineSpan = Math.max(
    0,
    Math.min(ACCESS_DENIED_BASELINE_DAYS, Math.floor((baselineEnd - earliest) / DAY_MS) + 1)
  );
  const coldStart = baselineSpan < ACCESS_DENIED_MIN_BASELINE_DAYS;

  const groups = new Map<string, DailyDeniedCount[]>();
  for (const row of rows) {
    const key = `${row.principalArn}\0${row.sourceIp}`;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }

  const records: AnomalyRecord[] = [];
  for (const group of groups.values()) {
    const dailyBaseline = new Map<number, number>();
    for (const row of group) {
      const dayMs = Date.parse(`${row.day}T00:00:00Z`);
      if (dayMs >= evalStart || dayMs < baselineEnd - (ACCESS_DENIED_BASELINE_DAYS - 1) * DAY_MS) {
        continue;
      }
      dailyBaseline.set(dayMs, (dailyBaseline.get(dayMs) ?? 0) + row.count);
    }
    const counts = Array.from({ length: ACCESS_DENIED_BASELINE_DAYS }, (_, index) => {
      return dailyBaseline.get(baselineEnd - index * DAY_MS) ?? 0;
    });
    const mean = counts.reduce((a, b) => a + b, 0) / counts.length;
    const variance = counts.reduce((sum, count) => sum + (count - mean) ** 2, 0) / counts.length;
    const stddev = Math.sqrt(variance);

    const evaluation = group.filter((row) => Date.parse(`${row.day}T00:00:00Z`) >= evalStart);
    if (evaluation.length === 0) continue;
    const worst = evaluation.reduce((best, row) => (row.count > best.count ? row : best));

    const effectiveStddev = Math.max(stddev, mean * ACCESS_DENIED_STDDEV_FLOOR_RATIO);
    const threshold = coldStart
      ? ACCESS_DENIED_SPIKE_THRESHOLD
      : Math.max(ACCESS_DENIED_MIN_COUNT, mean + ACCESS_DENIED_DEVIATIONS * effectiveStddev);
    if (worst.count < threshold) continue;

    records.push({
      type: 'ACCESS_DENIED_SPIKE',
      principalArn: worst.principalArn,
      sourceIp: worst.sourceIp,
      eventCount: worst.count,
      firstSeen: worst.firstSeen,
      lastSeen: worst.lastSeen,
      baselineMean: round2(mean),
      baselineStddev: round2(stddev),
      baselineDays: baselineSpan,
      basis: coldStart ? 'cold-start' : 'baseline',
      ...(stddev > 0 ? { deviation: round2((worst.count - mean) / stddev) } : {}),
    });
  }
  return records;
}

function required(value: string | undefined, name: string, rowNumber: number): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`Invalid Athena denied-count row ${rowNumber}: ${name} is required`);
  }
  return normalized;
}
