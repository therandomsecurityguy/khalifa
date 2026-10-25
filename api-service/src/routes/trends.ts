import type { Request, Response } from 'express';
import { forecastSeries, PostureTrendStore } from '@khalifa/risk-engine';
import { parseBoundedInteger } from '../middleware/gremlin-validator';
import type { SeverityCounts, TrendForecast, TrendPoint, TrendResponse } from '../types';

const trendStore = new PostureTrendStore();

const VALID_METRICS = [
  'openIssuesBySeverity',
  'issuesCreated',
  'issuesResolved',
  'publicBuckets',
  'usersWithoutMfa',
  'crossAccountTrusts',
  'openRiskScore',
  'mttrHours',
  'adminPrincipals',
];

const DAY_MS = 86_400_000;
const STALE_RUN_MS = 2 * DAY_MS;
const MAX_SERIES_GAP_DAYS = 3;

// The engine's projection plus the series' own honesty check: no runner pass
// in two days, or three or more missing days inside the window, lowers the
// confidence a level and says why. This is the trend-store equivalent of the
// compliance engine's freshCoverage gate.
function buildForecast(metric: string, points: TrendPoint[]): TrendForecast | undefined {
  const forecast = forecastSeries(
    points.map((point) => ({ date: point.date, value: point.value }))
  );
  if (!forecast) return undefined;

  let confidence = forecast.confidence;
  const notes: string[] = [];
  const last = points[points.length - 1];
  const recordedMs = last.recordedAt ? Date.parse(last.recordedAt) : NaN;
  if (Number.isFinite(recordedMs) && Date.now() - recordedMs > STALE_RUN_MS) {
    confidence = downgrade(confidence);
    notes.push('No runner pass in the last two days');
  }
  const spanDays = (Date.parse(last.date) - Date.parse(points[0].date)) / DAY_MS + 1;
  if (spanDays - points.length >= MAX_SERIES_GAP_DAYS) {
    confidence = downgrade(confidence);
    notes.push('gaps in the series');
  }

  return {
    ...forecast,
    confidence,
    ...(notes.length > 0 ? { note: notes.join('; ') } : {}),
  };
}

function downgrade(confidence: TrendForecast['confidence']): TrendForecast['confidence'] {
  if (confidence === 'high') return 'medium';
  if (confidence === 'medium') return 'low';
  return 'low';
}

export async function getTrend(req: Request<{ metric: string }>, res: Response): Promise<void> {
  try {
    const { metric } = req.params;
    const days = parseBoundedInteger(req.query.days, 90, 1, 365, 'days');

    if (!metric || !VALID_METRICS.includes(metric)) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: `metric must be one of: ${VALID_METRICS.join(', ')}`,
      });
      return;
    }

    if (days < 1 || days > 365) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'days must be between 1 and 365',
      });
      return;
    }

    const points = await trendStore.getSeries(metric as any, days);
    const trendPoints: TrendPoint[] = points.map((p) => {
      const bySeverity = severityCounts(p.sample?.bySeverity);
      return {
        metric: p.metric,
        date: p.date,
        value: p.value,
        accountIds: p.accountIds,
        recordedAt: p.recordedAt,
        ...(bySeverity ? { bySeverity } : {}),
      };
    });

    const forecast = points.length > 0 ? buildForecast(metric, trendPoints) : undefined;
    const response: TrendResponse = {
      metric,
      points: trendPoints,
      ...(forecast ? { forecast } : {}),
    };

    res.json(response);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('days must be')) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    console.error('Error getting trend:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get trend data',
    });
  }
}

// `sample` is free-form in storage; only these four counts reach the client.
function severityCounts(raw: unknown): SeverityCounts | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const counts = raw as Record<string, unknown>;
  const keys = ['critical', 'high', 'medium', 'low'] as const;
  if (!keys.every((key) => Number.isSafeInteger(counts[key]) && (counts[key] as number) >= 0)) {
    return undefined;
  }
  return {
    critical: counts.critical as number,
    high: counts.high as number,
    medium: counts.medium as number,
    low: counts.low as number,
  };
}

export async function listTrendMetrics(_req: Request, res: Response): Promise<void> {
  res.json({ metrics: VALID_METRICS });
}
