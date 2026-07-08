import type { Request, Response } from 'express';
import { PostureTrendStore } from '@khalifa/risk-engine';
import type { TrendPoint, TrendResponse } from '../types';

const trendStore = new PostureTrendStore();

const VALID_METRICS = [
  'openIssuesBySeverity',
  'exposedResourcesByType',
  'failedControlsByFramework',
  'publicBuckets',
  'usersWithoutMfa',
  'crossAccountTrusts',
];

export async function getTrend(req: Request, res: Response): Promise<void> {
  try {
    const { metric } = req.params;
    const days = req.query.days ? parseInt(req.query.days as string, 10) : 90;

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
    const trendPoints: TrendPoint[] = points.map((p) => ({
      metric: p.metric,
      date: p.date,
      value: p.value,
      accountIds: p.accountIds,
      recordedAt: p.recordedAt,
    }));

    const response: TrendResponse = {
      metric,
      points: trendPoints,
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting trend:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get trend data',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function listTrendMetrics(_req: Request, res: Response): Promise<void> {
  res.json({ metrics: VALID_METRICS });
}
