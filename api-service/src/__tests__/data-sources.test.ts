import type { Request, Response } from 'express';
import type { GraphVertex } from '../types';

const listAccounts = jest.fn();
const listCollectionCoverage = jest.fn();
const countByAccount = jest.fn();
const listDetectionSources = jest.fn();
const latestOutput = jest.fn();
const getLatest = jest.fn();
const getLatestReport = jest.fn();
const getSummary = jest.fn();

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({
    listAccounts,
    listCollectionCoverage,
    countByAccount,
    listDetectionSources,
    latestOutput,
  }),
}));
jest.mock('@khalifa/risk-engine', () => ({
  PostureTrendStore: jest.fn(() => ({ getLatest })),
  DynamoDBReportStore: jest.fn(() => ({ getLatestReport })),
}));
jest.mock('../services/least-privilege-store', () => ({
  LeastPrivilegeStore: jest.fn(() => ({ getSummary })),
}));

let route: typeof import('../routes/data-sources');

const coverage = (
  account: string,
  service: string,
  props: Record<string, unknown> = {}
): GraphVertex => ({
  id: `arn:aws:khalifa:us-west-2:${account}:collection-coverage/${service}`,
  label: 'CollectionCoverage',
  properties: {
    account_id: account,
    region: 'us-west-2',
    service,
    status: 'SUCCEEDED',
    last_attempt_at: '2026-10-06T10:00:00Z',
    last_success_at: '2026-10-06T10:00:00Z',
    node_count: 10,
    ...props,
  },
});

const source = (account: string, label: string, props: Record<string, unknown>): GraphVertex => ({
  id: `${label}-${account}`,
  label,
  properties: { account_id: account, ...props },
});

function call() {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return route.getDataSources({} as Request, res as Response).then(() => res);
}

describe('GET /data-sources', () => {
  beforeEach(async () => {
    jest.resetModules();
    listAccounts.mockReset().mockResolvedValue([
      { id: '111111111111', name: 'prod' },
      { id: '222222222222', name: 'dev' },
      { id: '333333333333', name: 'new' },
    ]);
    listCollectionCoverage.mockReset().mockResolvedValue([
      coverage('111111111111', 'resource-inventory', { node_count: 500 }),
      coverage('111111111111', 's3'),
      coverage('111111111111', 'iam'),
      coverage('222222222222', 'resource-inventory', { status: 'FAILED', node_count: 80 }),
      coverage('222222222222', 'tags', {
        status: 'FAILED',
        error: 'AccessDenied: tag:GetResources',
        failure_type: 'ACCESS_DENIED',
        last_success_at: '2026-10-01T10:00:00Z',
      }),
    ]);
    countByAccount.mockReset().mockResolvedValue({ '111111111111': 120 });
    listDetectionSources
      .mockReset()
      .mockResolvedValue([
        source('111111111111', 'SecurityHub', { findings_truncated: true }),
        source('111111111111', 'GuardDutyDetector', { status: 'ENABLED' }),
        source('111111111111', 'ConfigRecorder', { recording: false }),
        source('111111111111', 'AccessAnalyzer', { status: 'MISSING' }),
      ]);
    latestOutput.mockReset().mockResolvedValue({ count: 0, latest: null });
    getLatest.mockReset().mockResolvedValue({ recordedAt: '2026-10-06T10:30:00Z', value: 767 });
    getLatestReport.mockReset().mockResolvedValue({
      generatedAt: '2026-10-06T10:31:00Z',
      summary: { failed: 9, totalControls: 54 },
    });
    getSummary.mockReset().mockResolvedValue({ principalsSwept: 0, lastSweptAt: null });
    route = await import('../routes/data-sources');
  });

  it('summarises each account from its coverage records', async () => {
    const { body } = await call();
    const [dev, fresh, prod] = body.accounts;

    expect(prod).toMatchObject({
      id: '111111111111',
      name: 'prod',
      resources: 500,
      prod: 120,
      collectedAt: '2026-10-06T10:00:00Z',
      status: 'ok',
    });
    expect(prod.services.map((s: { service: string }) => s.service)).toEqual(['iam', 's3']);

    expect(dev.status).toBe('failing');
    expect(dev.services[0]).toMatchObject({
      service: 'tags',
      status: 'FAILED',
      error: 'AccessDenied: tag:GetResources',
      lastSuccessAt: '2026-10-01T10:00:00Z',
    });

    expect(fresh).toMatchObject({ name: 'new', status: 'not-collected', resources: null });
    expect(countByAccount).toHaveBeenCalledWith('env', 'prod');
  });

  it('reads the graph once per five minutes and retries after a failure', async () => {
    jest.useFakeTimers();
    listCollectionCoverage.mockRejectedValueOnce(new Error('MemoryLimitExceededException'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    expect((await call()).statusCode).toBe(500);
    await call();
    await call();
    expect(listCollectionCoverage).toHaveBeenCalledTimes(2);

    jest.advanceTimersByTime(5 * 60 * 1000 + 1);
    await call();
    expect(listCollectionCoverage).toHaveBeenCalledTimes(3);
    error.mockRestore();
    jest.useRealTimers();
  });

  it("reports each account's detection sources, and unknown when the check failed", async () => {
    const { body } = await call();
    const [dev, , prod] = body.accounts;

    expect(prod.detection).toEqual({
      securityHub: 'truncated',
      guardDuty: 'on',
      config: 'off',
      accessAnalyzer: 'missing',
    });
    // dev has no source records; none of its detection checks ran cleanly.
    expect(dev.detection).toEqual({
      securityHub: 'unknown',
      guardDuty: 'unknown',
      config: 'unknown',
      accessAnalyzer: 'unknown',
    });
  });

  it('lists each job with its last output and what it produced', async () => {
    latestOutput.mockImplementation(async (label: string) =>
      label === 'GuardDutyFinding'
        ? { count: 12, latest: '2026-10-06T10:05:00Z' }
        : { count: 0, latest: null }
    );
    const { body } = await call();
    const jobs = Object.fromEntries(body.jobs.map((job: { id: string }) => [job.id, job]));

    expect(jobs['org-collector']).toMatchObject({
      everyHours: 4,
      lastOutputAt: '2026-10-06T10:00:00Z',
      produced: '2 accounts',
    });
    expect(jobs['rule-runner']).toMatchObject({
      lastOutputAt: '2026-10-06T10:30:00Z',
      produced: '767 open issues',
    });
    expect(jobs.compliance).toMatchObject({ produced: 'CIS: 9 of 54 controls failing' });
    expect(jobs['guardduty-sweep']).toMatchObject({
      produced: '12 findings',
      quietWhenClean: true,
    });
    expect(jobs['dspm-scanner']).toMatchObject({ lastOutputAt: null, quietWhenClean: true });
    expect(latestOutput).toHaveBeenCalledWith('EffectivePermission', 'evaluated_at');
  });
});
