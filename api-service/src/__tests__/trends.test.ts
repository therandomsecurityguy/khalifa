import type { Request, Response } from 'express';

const getSeries = jest.fn();

jest.mock('@khalifa/risk-engine', () => ({
  ...jest.requireActual('@khalifa/risk-engine'),
  PostureTrendStore: jest.fn().mockImplementation(() => ({ getSeries })),
}));

let getTrend: typeof import('../routes/trends').getTrend;

function response(): Response & { statusCode: number; body?: any } {
  const res: any = { statusCode: 200 };
  res.status = (statusCode: number) => Object.assign(res, { statusCode });
  res.json = (body: unknown) => Object.assign(res, { body });
  return res as unknown as Response & { statusCode: number; body?: any };
}

function request(metric: string): Request<{ metric: string }> {
  return { params: { metric }, query: {} } as unknown as Request<{ metric: string }>;
}

describe('trends route', () => {
  beforeAll(async () => {
    ({ getTrend } = await import('../routes/trends'));
  });

  beforeEach(() => {
    getSeries.mockReset();
  });

  it('returns the severity split and nothing else from sample', async () => {
    getSeries.mockResolvedValue([
      {
        metric: 'openIssuesBySeverity',
        date: '2026-09-28',
        value: 6,
        accountIds: [],
        recordedAt: '2026-09-28T20:00:00.000Z',
        sample: {
          bySeverity: { critical: 1, high: 2, medium: 3, low: 0, extra: 9 },
          internal: 'not for the browser',
        },
      },
    ]);
    const res = response();

    await getTrend(request('openIssuesBySeverity'), res);

    expect(res.statusCode).toBe(200);
    expect(res.body.points).toEqual([
      {
        metric: 'openIssuesBySeverity',
        date: '2026-09-28',
        value: 6,
        accountIds: [],
        recordedAt: '2026-09-28T20:00:00.000Z',
        bySeverity: { critical: 1, high: 2, medium: 3, low: 0 },
      },
    ]);
  });

  it.each([
    ['no sample', undefined],
    ['an empty sample', {}],
    ['a missing severity', { bySeverity: { critical: 1, high: 2, medium: 3 } }],
    ['a non-numeric count', { bySeverity: { critical: '1', high: 2, medium: 3, low: 0 } }],
    ['a negative count', { bySeverity: { critical: -1, high: 2, medium: 3, low: 0 } }],
  ])('omits bySeverity for %s', async (_label, sample) => {
    getSeries.mockResolvedValue([
      { metric: 'openIssuesBySeverity', date: '2026-09-20', value: 6, recordedAt: 'x', sample },
    ]);
    const res = response();

    await getTrend(request('openIssuesBySeverity'), res);

    expect(res.body.points[0]).not.toHaveProperty('bySeverity');
  });

  it('rejects the removed metrics', async () => {
    const res = response();

    await getTrend(request('exposedResourcesByType'), res);

    expect(res.statusCode).toBe(400);
    expect(getSeries).not.toHaveBeenCalled();
  });

  it('serves the new trajectory metrics', async () => {
    for (const metric of ['openRiskScore', 'mttrHours', 'adminPrincipals']) {
      getSeries.mockResolvedValue([]);
      const res = response();
      await getTrend(request(metric), res);
      expect(res.statusCode).toBe(200);
    }
  });

  function series(values: number[], recordedAt = new Date().toISOString()) {
    const start = Date.parse('2026-10-01T00:00:00.000Z');
    return values.map((value, index) => ({
      metric: 'openRiskScore',
      date: new Date(start + index * 86_400_000).toISOString().slice(0, 10),
      value,
      accountIds: [],
      recordedAt,
    }));
  }

  it('projects a clean rising series with high confidence and no note', async () => {
    getSeries.mockResolvedValue(series(Array.from({ length: 14 }, (_, i) => 10 + i)));
    const res = response();

    await getTrend(request('openRiskScore'), res);

    expect(res.body.forecast).toMatchObject({
      basisDays: 14,
      slopePerDay: 1,
      confidence: 'high',
    });
    expect(res.body.forecast.projected).toHaveLength(2);
    expect(res.body.forecast.projected[0]).toMatchObject({ days: 7, value: 30 });
    expect(res.body.forecast).not.toHaveProperty('note');
  });

  it('lowers the confidence and says why when the series is stale', async () => {
    const stale = new Date(Date.now() - 3 * 86_400_000).toISOString();
    getSeries.mockResolvedValue(
      series(
        Array.from({ length: 14 }, (_, i) => 10 + i),
        stale
      )
    );
    const res = response();

    await getTrend(request('openRiskScore'), res);

    expect(res.body.forecast.confidence).toBe('medium');
    expect(res.body.forecast.note).toContain('No runner pass in the last two days');
  });

  it('lowers the confidence on a gappy series and omits the forecast under five points', async () => {
    const gappy = series([1, 2, 3, 4, 5]);
    gappy[3].date = '2026-10-20';
    gappy[4].date = '2026-10-25';
    getSeries.mockResolvedValue(gappy);
    const gappyRes = response();
    await getTrend(request('openRiskScore'), gappyRes);
    expect(gappyRes.body.forecast.note).toContain('gaps in the series');

    getSeries.mockResolvedValue(series([1, 2, 3, 4]));
    const shortRes = response();
    await getTrend(request('openRiskScore'), shortRes);
    expect(shortRes.body).not.toHaveProperty('forecast');
  });
});
