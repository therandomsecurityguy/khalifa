import type { Request, Response } from 'express';

const getSeries = jest.fn();

jest.mock('@khalifa/risk-engine', () => ({
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
});
