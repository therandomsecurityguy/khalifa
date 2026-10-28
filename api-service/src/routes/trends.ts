import type { Request, Response } from 'express';
import { PostureTrendStore } from '@khalifa/risk-engine';
import { parseBoundedInteger } from '../middleware/gremlin-validator';
import { buildForecast } from '../services/trend-forecast';
import type { ExposureCounts, SeverityCounts, TrendPoint, TrendResponse } from '../types';

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
  'sloBurning',
  'exposedByType',
];

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
      const breached = nonNegativeInteger(p.sample?.breached);
      const slo =
        metric === 'sloBurning' && bySeverity && breached !== undefined
          ? { ...bySeverity, breached }
          : undefined;
      const exposure =
        metric === 'exposedByType'
          ? exposureCounts(p.sample?.byType, p.sample?.truncated)
          : undefined;
      return {
        metric: p.metric,
        date: p.date,
        value: p.value,
        accountIds: p.accountIds,
        recordedAt: p.recordedAt,
        ...(bySeverity ? { bySeverity } : {}),
        ...(slo ? { slo } : {}),
        ...(exposure ? { exposure } : {}),
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

// `sample` is free-form in storage; only reviewed shapes reach the client. The
// exposure map is bounded twice: at most 25 types, label-shaped keys only.
const MAX_EXPOSURE_TYPES = 25;
const EXPOSURE_LABEL = /^[A-Za-z][A-Za-z0-9]{0,40}$/;

function nonNegativeInteger(raw: unknown): number | undefined {
  return Number.isSafeInteger(raw) && (raw as number) >= 0 ? (raw as number) : undefined;
}

function exposureCounts(byTypeRaw: unknown, truncatedRaw: unknown): ExposureCounts | undefined {
  if (!byTypeRaw || typeof byTypeRaw !== 'object') return undefined;
  const entries = Object.entries(byTypeRaw as Record<string, unknown>);
  if (entries.length === 0 || entries.length > MAX_EXPOSURE_TYPES) return undefined;
  const byType: Record<string, number> = {};
  for (const [label, count] of entries) {
    const parsed = nonNegativeInteger(count);
    if (!EXPOSURE_LABEL.test(label) || parsed === undefined) return undefined;
    byType[label] = parsed;
  }
  return { byType, truncated: truncatedRaw === true };
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
