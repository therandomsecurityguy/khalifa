import type { Request, Response } from 'express';

const listResourceLabels = jest.fn();

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({ listResourceLabels }),
}));
jest.mock('@khalifa/risk-engine', () => ({ DynamoDBIssueRepository: jest.fn() }));

let route: typeof import('../routes/resources');

// Lets a background refresh settle; it chains a few promise steps.
const flush = async () => {
  for (let i = 0; i < 10; i++) await Promise.resolve();
};

function call() {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return route.listResourceLabels({} as Request, res as Response).then(() => res);
}

describe('GET /resources/labels', () => {
  beforeEach(async () => {
    jest.resetModules();
    jest.useFakeTimers();
    listResourceLabels.mockReset();
    route = await import('../routes/resources');
  });
  afterEach(() => jest.useRealTimers());

  it('counts labels once per ten minutes, and retries after a failure', async () => {
    listResourceLabels
      .mockRejectedValueOnce(new Error('MemoryLimitExceededException'))
      .mockResolvedValueOnce([{ label: 'S3Bucket', count: 2 }])
      .mockResolvedValueOnce([{ label: 'S3Bucket', count: 3 }]);
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    expect((await call()).statusCode).toBe(500);
    expect((await call()).body).toEqual({ labels: [{ label: 'S3Bucket', count: 2 }] });
    expect((await call()).body).toEqual({ labels: [{ label: 'S3Bucket', count: 2 }] });
    expect(listResourceLabels).toHaveBeenCalledTimes(2);

    // Stale: the old count is served at once while a refresh runs.
    jest.advanceTimersByTime(10 * 60 * 1000 + 1);
    expect((await call()).body).toEqual({ labels: [{ label: 'S3Bucket', count: 2 }] });
    await flush();
    expect((await call()).body).toEqual({ labels: [{ label: 'S3Bucket', count: 3 }] });
    expect(listResourceLabels).toHaveBeenCalledTimes(3);
    error.mockRestore();
  });

  it('keeps serving the last good count when a refresh fails', async () => {
    listResourceLabels
      .mockRejectedValue(new Error('TimeLimitExceededException'))
      .mockResolvedValueOnce([{ label: 'IamRole', count: 5 }]);
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    await call();
    jest.advanceTimersByTime(10 * 60 * 1000 + 1);
    expect((await call()).body).toEqual({ labels: [{ label: 'IamRole', count: 5 }] });
    await flush();
    const after = await call();
    expect(after.statusCode).toBe(200);
    expect(after.body).toEqual({ labels: [{ label: 'IamRole', count: 5 }] });
    error.mockRestore();
  });
});
