import { ReadinessService } from '../services/readiness';

const REQUIRED_ENV = ['NEPTUNE_ENDPOINT', 'COGNITO_USER_POOL_ID', 'COGNITO_CLIENT_ID'] as const;

describe('ReadinessService', () => {
  const original = Object.fromEntries(REQUIRED_ENV.map((name) => [name, process.env[name]]));

  beforeEach(() => {
    process.env.NEPTUNE_ENDPOINT = 'cluster.example.com';
    process.env.COGNITO_USER_POOL_ID = 'us-west-2_pool';
    process.env.COGNITO_CLIENT_ID = 'client-id';
  });

  afterAll(() => {
    REQUIRED_ENV.forEach((name) => {
      const value = original[name];
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    });
  });

  it('does not call dependencies when required configuration is missing', async () => {
    delete process.env.NEPTUNE_ENDPOINT;
    const checkNeptune = jest.fn(async () => undefined);
    const checkDynamo = jest.fn(async () => undefined);
    const readiness = new ReadinessService({ checkNeptune, checkDynamo });

    await expect(readiness.check()).resolves.toEqual({
      status: 'not_ready',
      checks: {
        configuration: { ok: false, missing: ['NEPTUNE_ENDPOINT'] },
        neptune: { ok: false },
        dynamodb: { ok: false },
      },
    });
    expect(checkNeptune).not.toHaveBeenCalled();
    expect(checkDynamo).not.toHaveBeenCalled();
  });

  it('requires both Neptune and DynamoDB to be available', async () => {
    const readiness = new ReadinessService({
      checkNeptune: async () => undefined,
      checkDynamo: async () => {
        throw new Error('unavailable');
      },
    });

    await expect(readiness.check()).resolves.toEqual({
      status: 'not_ready',
      checks: {
        configuration: { ok: true },
        neptune: { ok: true },
        dynamodb: { ok: false },
      },
    });
  });

  it('returns ready when both dependencies are available', async () => {
    const checkNeptune = jest.fn(async () => undefined);
    const checkDynamo = jest.fn(async () => undefined);
    const readiness = new ReadinessService({ checkNeptune, checkDynamo });

    await expect(readiness.check()).resolves.toMatchObject({ status: 'ready' });
    expect(checkNeptune).toHaveBeenCalledTimes(1);
    expect(checkDynamo).toHaveBeenCalledTimes(1);
  });
});
