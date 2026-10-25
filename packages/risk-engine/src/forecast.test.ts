import { forecastSeries } from './forecast';

const days = (values: number[], start = '2026-10-01') => {
  const startMs = Date.parse(start);
  return values.map((value, index) => ({
    date: new Date(startMs + index * 86_400_000).toISOString().slice(0, 10),
    value,
  }));
};

describe('forecastSeries', () => {
  it('returns null below the minimum number of points', () => {
    expect(forecastSeries(days([1, 2, 3, 4]))).toBeNull();
    expect(forecastSeries([])).toBeNull();
  });

  it('projects a clean rising line with a tight band and high confidence', () => {
    const forecast = forecastSeries(days(Array.from({ length: 14 }, (_, i) => 10 + i)))!;

    expect(forecast.basisDays).toBe(14);
    expect(forecast.slopePerDay).toBe(1);
    expect(forecast.confidence).toBe('high');
    expect(forecast.projected[0]).toMatchObject({ days: 7, value: 30, lower: 30, upper: 30 });
    expect(forecast.projected[1]).toMatchObject({ days: 30, date: '2026-11-13', value: 53 });
  });

  it('projects a flat series without drifting', () => {
    const forecast = forecastSeries(days(Array(10).fill(7)))!;
    expect(forecast.slopePerDay).toBe(0);
    expect(forecast.projected[0].value).toBe(7);
    expect(forecast.projected[1].value).toBe(7);
  });

  it('widens the band and lowers confidence on a noisy short series', () => {
    const forecast = forecastSeries(days([2, 9, 1, 8, 2, 7]))!;
    expect(forecast.confidence).toBe('low');
    const [week] = forecast.projected;
    expect(week.upper).toBeGreaterThan(week.lower);
  });

  it('never projects below zero', () => {
    const forecast = forecastSeries(days(Array.from({ length: 10 }, (_, i) => 9 - i)))!;
    expect(forecast.slopePerDay).toBe(-1);
    expect(forecast.projected[1].value).toBe(0);
    expect(forecast.projected[1].lower).toBe(0);
  });
});
