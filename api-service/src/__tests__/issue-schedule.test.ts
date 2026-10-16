import type { Request, Response } from 'express';

const getLatest = jest.fn();

jest.mock('@khalifa/risk-engine', () => ({
  ...jest.requireActual('@khalifa/risk-engine'),
  DynamoDBIssueRepository: jest.fn(),
  PostureTrendStore: jest.fn(() => ({ getLatest })),
}));
jest.mock('../services/api-dependencies', () => ({ getApiNeptuneClient: () => ({}) }));

let route: typeof import('../routes/issues');

function call() {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return route.getIssueSchedule({} as Request, res as Response).then(() => res);
}

describe('GET /issues/schedule', () => {
  beforeAll(async () => {
    route = await import('../routes/issues');
  });
  beforeEach(() => {
    jest.useFakeTimers({ now: new Date('2026-10-07T19:00:00Z') });
    getLatest.mockReset().mockResolvedValue({ recordedAt: '2026-10-07T17:41:00Z' });
    process.env.RULE_RUNNER_SCHEDULE = '30 2-22/4 * * *';
    process.env.RULE_RUNNER_TIMEZONE = 'America/Los_Angeles';
  });
  afterEach(() => {
    jest.useRealTimers();
    delete process.env.RULE_RUNNER_SCHEDULE;
    delete process.env.RULE_RUNNER_TIMEZONE;
  });

  it('returns the last run and the next run in the schedule time zone', async () => {
    expect((await call()).body).toEqual({
      lastRunAt: '2026-10-07T17:41:00Z',
      nextRunAt: '2026-10-07T21:30:00.000Z',
      intervalMinutes: 240,
    });
    expect(getLatest).toHaveBeenCalledWith('openIssuesBySeverity');
  });

  it('leaves the next run empty when no schedule is configured', async () => {
    delete process.env.RULE_RUNNER_SCHEDULE;
    getLatest.mockResolvedValue(null);
    expect((await call()).body).toEqual({
      lastRunAt: null,
      nextRunAt: null,
      intervalMinutes: null,
    });
  });
});
