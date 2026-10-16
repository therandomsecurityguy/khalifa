import type { TrendPoint } from '@/types';

export interface TrendMetricCopy {
  id: string;
  label: string;
  unit: string;
  meaning: string;
  href: string;
  hrefLabel: string;
  lowerIsBetter: boolean;
}

export const TREND_METRICS: Record<string, TrendMetricCopy> = {
  openIssuesBySeverity: {
    id: 'openIssuesBySeverity',
    label: 'Open issues',
    unit: 'open findings',
    meaning: 'Every open risk-engine finding. This is the backlog, not a single rule.',
    href: '/issues',
    hrefLabel: 'Open issues',
    lowerIsBetter: true,
  },
  issuesCreated: {
    id: 'issuesCreated',
    label: 'Issues opened per day',
    unit: 'new findings',
    meaning:
      'New risk-engine findings opened that day, summed across every runner pass. Reopened issues are not counted.',
    href: '/issues',
    hrefLabel: 'Open issues',
    lowerIsBetter: true,
  },
  issuesResolved: {
    id: 'issuesResolved',
    label: 'Issues resolved per day',
    unit: 'resolved findings',
    meaning:
      'Findings the runner closed that day because the graph no longer matched them, summed across every runner pass.',
    href: '/issues',
    hrefLabel: 'Open issues',
    lowerIsBetter: false,
  },
};

export function metricCopy(id: string): TrendMetricCopy {
  return (
    TREND_METRICS[id] ?? {
      id,
      label: id.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase()),
      unit: 'count',
      meaning: 'Snapshot recorded by the risk runner.',
      href: '/issues',
      hrefLabel: 'Open issues',
      lowerIsBetter: true,
    }
  );
}

export function formatTrendDate(date: string): string {
  const [year, month, day] = date.split('-').map(Number);
  if (!year || !month || !day) return date;
  return new Date(Date.UTC(year, month - 1, day)).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
}

export function formatSigned(value: number): string {
  if (value > 0) return `+${value}`;
  if (value < 0) return String(value);
  return '0';
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;
export type TrendSeverity = (typeof SEVERITY_ORDER)[number];

export interface SeverityChip {
  severity: TrendSeverity;
  text: string;
}

// A change when the previous day also has a breakdown, the plain count on the
// first day that has one, and nothing for days recorded before severity was.
export function severityChips(point: TrendPoint, previous: TrendPoint | null): SeverityChip[] {
  const counts = point.bySeverity;
  if (!counts) return [];
  const before = previous?.bySeverity;
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    text: before ? formatSigned(counts[severity] - before[severity]) : String(counts[severity]),
  }));
}

export type DeltaTone = 'good' | 'bad' | 'neutral';

export function deltaTone(delta: number | null, lowerIsBetter: boolean): DeltaTone {
  if (delta === null || delta === 0) return 'neutral';
  return delta < 0 === lowerIsBetter ? 'good' : 'bad';
}

export interface TrendInsight {
  current: number;
  previous: number | null;
  start: number;
  dayDelta: number | null;
  windowDelta: number;
  peak: number;
  direction: 'improving' | 'worsening' | 'unchanged';
  headline: string;
}

export function summarizeTrend(metric: string, points: TrendPoint[]): TrendInsight | null {
  if (points.length === 0) return null;
  const copy = metricCopy(metric);
  const currentPoint = points[points.length - 1];
  const startPoint = points[0];
  const previousPoint = points.length > 1 ? points[points.length - 2] : undefined;
  const current = currentPoint.value;
  const start = startPoint.value;
  const previous = previousPoint ? previousPoint.value : null;
  const windowDelta = current - start;
  const dayDelta = previous === null ? null : current - previous;
  const peak = Math.max(...points.map((point) => point.value));
  const direction =
    windowDelta === 0
      ? 'unchanged'
      : copy.lowerIsBetter === windowDelta < 0
        ? 'improving'
        : 'worsening';

  return {
    current,
    previous,
    start,
    dayDelta,
    windowDelta,
    peak,
    direction,
    headline: `${copy.label}: ${current} as of ${formatTrendDate(currentPoint.date)}.`,
  };
}
