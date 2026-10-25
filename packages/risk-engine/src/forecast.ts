// Trajectory forecasting for a trend series: an ordinary least-squares line
// over the window's daily points, projected forward with a residual-based band.
// Deliberately explainable — a straight line and its own noise — not a
// black-box model; calibration against outcomes belongs to a later phase.
export interface ForecastProjection {
  days: number;
  date: string;
  value: number;
  /** value ± the residual band, clamped at zero. */
  lower: number;
  upper: number;
}

export interface Forecast {
  basisDays: number;
  slopePerDay: number;
  confidence: 'high' | 'medium' | 'low';
  projected: ForecastProjection[];
}

// Fewer points than this and a line is noise; the caller shows no projection.
export const FORECAST_MIN_POINTS = 5;
// The residual band's z-factor: wide enough to be honest about a noisy series.
const BAND_FACTOR = 1.5;
const DAY_MS = 86_400_000;

function round1(value: number): number {
  return Math.round(value * 10) / 10;
}

export function forecastSeries(
  points: { date: string; value: number }[],
  horizons: number[] = [7, 30]
): Forecast | null {
  if (points.length < FORECAST_MIN_POINTS) return null;

  const n = points.length;
  const xs = points.map((_, index) => index);
  const ys = points.map((point) => point.value);
  const meanX = xs.reduce((a, b) => a + b, 0) / n;
  const meanY = ys.reduce((a, b) => a + b, 0) / n;
  const denominator = xs.reduce((sum, x) => sum + (x - meanX) ** 2, 0);
  if (denominator === 0) return null;
  const slope =
    xs.reduce((sum, x, index) => sum + (x - meanX) * (ys[index] - meanY), 0) / denominator;
  const intercept = meanY - slope * meanX;

  const residuals = ys.map((y, index) => y - (intercept + slope * index));
  const variance = residuals.reduce((sum, r) => sum + r * r, 0) / n;
  const stddev = Math.sqrt(variance);
  const scale = Math.max(Math.abs(meanY), 1);

  // Confidence is about how well the line fits and how many days back it: a
  // tight line over two weeks is high, a scattered one over a handful of days
  // is low. The API degrades it further when the series itself is stale.
  let confidence: Forecast['confidence'] = 'low';
  if (n >= 14 && stddev <= scale * 0.1) confidence = 'high';
  else if (n >= 7 && stddev <= scale * 0.3) confidence = 'medium';

  const lastDateMs = Date.parse(points[n - 1].date);
  const band = stddev * BAND_FACTOR;
  const projected = horizons.map((days) => {
    const value = Math.max(0, intercept + slope * (n - 1 + days));
    return {
      days,
      date: new Date(lastDateMs + days * DAY_MS).toISOString().slice(0, 10),
      value: round1(value),
      lower: round1(Math.max(0, value - band)),
      upper: round1(value + band),
    };
  });

  return { basisDays: n, slopePerDay: Math.round(slope * 100) / 100, confidence, projected };
}
