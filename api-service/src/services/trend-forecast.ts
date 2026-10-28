import { forecastSeries } from '@khalifa/risk-engine';
import type { TrendForecast, TrendPoint } from '../types';

const DAY_MS = 86_400_000;
const STALE_RUN_MS = 2 * DAY_MS;
const MAX_SERIES_GAP_DAYS = 3;

// The engine's projection plus the series' own honesty check: no runner pass
// in two days, or three or more missing days inside the window, lowers the
// confidence a level and says why. This is the trend-store equivalent of the
// compliance engine's freshCoverage gate. Shared by the trends route and the
// trust-center projections, so the two can never disagree.
export function buildForecast(metric: string, points: TrendPoint[]): TrendForecast | undefined {
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

export function downgrade(confidence: TrendForecast['confidence']): TrendForecast['confidence'] {
  if (confidence === 'high') return 'medium';
  if (confidence === 'medium') return 'low';
  return 'low';
}
