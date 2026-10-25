import type { AddressInfo } from 'net';
import type { CollectorEvent } from '../collector';
import {
  createGraphWriterServer,
  createHttpGraphWriter,
  parseGuardDutyFindingsConfig,
  runBounded,
  runCommand,
  shuffle,
  validateRuntime,
} from './index';

const collectionEnvironment = {
  AWS_REGION: 'us-west-2',
  COLLECTION_ACCOUNT_IDS: '111122223333',
  COLLECTION_REGIONS: 'us-west-2',
  HOME_ACCOUNT_ID: '111122223333',
  COLLECTOR_EXTERNAL_ID: 'runtime-test-external-id',
  GRAPH_WRITER_URL: 'http://graph-writer:8080',
  GRAPH_WRITER_TOKEN: 'runtime-test-graph-token',
};

const analyzerEnvironment = {
  AWS_REGION: 'us-west-2',
  ATHENA_DATABASE: 'cloudtrail_database',
  ATHENA_WORKGROUP: 'cloudtrail_workgroup',
  ATHENA_RESULTS_S3_LOCATION: ['s3', 'example.invalid/athena-results'].join('://'),
  ACCESS_ANALYZER_TABLE: 'AccessAnalyzerCache',
};

describe('Kubernetes runtime', () => {
  it('validates required configuration for each command', () => {
    expect(() => validateRuntime('organization-collector', collectionEnvironment)).not.toThrow();
    expect(() =>
      validateRuntime('incremental-collector', {
        ...collectionEnvironment,
        SQS_QUEUE_URL: 'https://sqs.us-west-2.amazonaws.com/111122223333/incremental.fifo',
      })
    ).not.toThrow();
    expect(() => validateRuntime('graph-writer', { AWS_REGION: 'us-west-2' })).toThrow(
      'NEPTUNE_ENDPOINT is required'
    );
    expect(() =>
      validateRuntime('graph-writer', {
        AWS_REGION: 'us-west-2',
        NEPTUNE_ENDPOINT: 'cluster:8182',
      })
    ).toThrow('GRAPH_WRITER_TOKEN is required');
    expect(() =>
      validateRuntime('organization-collector', {
        ...collectionEnvironment,
        GRAPH_WRITER_TOKEN: '',
      })
    ).toThrow('GRAPH_WRITER_TOKEN is required');
    expect(() => validateRuntime('compliance', { NEPTUNE_ENDPOINT: 'cluster:8182' })).toThrow(
      'COMPLIANCE_EVIDENCE_TABLE is required'
    );
    expect(() => validateRuntime('cloudtrail-analyzer', analyzerEnvironment)).not.toThrow();
    expect(() =>
      validateRuntime('cloudtrail-analyzer', {
        AWS_REGION: 'us-west-2',
        ATHENA_DATABASE: 'cloudtrail_database',
        ATHENA_WORKGROUP: 'cloudtrail_workgroup',
        ACCESS_ANALYZER_TABLE: 'AccessAnalyzerCache',
      })
    ).toThrow('ATHENA_RESULTS_S3_LOCATION is required');
    expect(() =>
      validateRuntime('cloudtrail-analyzer', {
        ...analyzerEnvironment,
        GRAPH_WRITER_URL: 'http://graph-writer:8080',
      })
    ).toThrow('GRAPH_WRITER_TOKEN is required');
    expect(() =>
      validateRuntime('dspm-scanner', {
        AWS_REGION: 'us-west-2',
        GRAPH_WRITER_URL: 'http://graph-writer:8080',
        GRAPH_WRITER_TOKEN: 'runtime-test-graph-token',
      })
    ).not.toThrow();
    expect(() =>
      validateRuntime('dspm-scanner', {
        AWS_REGION: 'us-west-2',
        GRAPH_WRITER_URL: 'http://graph-writer:8080',
        GRAPH_WRITER_TOKEN: 'runtime-test-graph-token',
        DSPM_SCAN_MODE: 'sometimes',
      })
    ).toThrow("DSPM_SCAN_MODE must be one of 'tagged-only', 'all', 'off'");
    expect(() => validateRuntime('dspm-scanner', { AWS_REGION: 'us-west-2' })).toThrow(
      'GRAPH_WRITER_URL is required'
    );
    expect(() =>
      validateRuntime('dspm-scanner', {
        AWS_REGION: 'us-west-2',
        GRAPH_WRITER_URL: 'http://graph-writer:8080',
      })
    ).toThrow('GRAPH_WRITER_TOKEN is required');
  });

  it('runs the CloudTrail analyzer once and exits nonzero on failure', async () => {
    const analyze = jest.fn().mockResolvedValue({
      recordsProcessed: 4,
      queryExecutionId: 'query-123',
      anomalies: 0,
    });
    await expect(
      runCommand('cloudtrail-analyzer', analyzerEnvironment, new AbortController().signal, {
        analyzeCloudTrail: analyze,
      })
    ).resolves.toBeUndefined();
    expect(analyze).toHaveBeenCalledTimes(1);

    const failing = jest.fn().mockRejectedValue(new Error('Athena query FAILED'));
    await expect(
      runCommand('cloudtrail-analyzer', analyzerEnvironment, new AbortController().signal, {
        analyzeCloudTrail: failing,
      })
    ).rejects.toThrow('Athena query FAILED');
  });

  it('runs the DSPM scanner once with the HTTP graph writer', async () => {
    const runDspm = jest.fn().mockResolvedValue({
      bucketsScanned: 2,
      functionsScanned: 5,
      findingsWritten: 1,
      errors: 0,
    });
    const dspmEnvironment = {
      AWS_REGION: 'us-west-2',
      GRAPH_WRITER_URL: 'http://graph-writer:8080',
      GRAPH_WRITER_TOKEN: 'runtime-test-graph-token',
    };
    await expect(
      runCommand('dspm-scanner', dspmEnvironment, new AbortController().signal, {
        runDspm,
      })
    ).resolves.toBeUndefined();
    expect(runDspm).toHaveBeenCalledTimes(1);
    expect(runDspm).toHaveBeenCalledWith({}, {}, dspmEnvironment);

    const failing = jest.fn().mockRejectedValue(new Error('DSPM scan failed'));
    await expect(
      runCommand('dspm-scanner', dspmEnvironment, new AbortController().signal, {
        runDspm: failing,
      })
    ).rejects.toThrow('DSPM scan failed');
  });

  it('never exceeds configured concurrency', async () => {
    let active = 0;
    let peak = 0;
    const release: Array<() => void> = [];
    const signal = new AbortController().signal;
    const pending = runBounded([1, 2, 3, 4], 2, signal, async () => {
      active++;
      peak = Math.max(peak, active);
      await new Promise<void>((resolve) => release.push(resolve));
      active--;
    });

    await new Promise((resolve) => setImmediate(resolve));
    expect(peak).toBe(2);
    while (release.length > 0) {
      release.shift()!();
      await new Promise((resolve) => setImmediate(resolve));
    }
    await pending;
    expect(peak).toBe(2);
    await expect(runBounded([1], 0, signal, async () => {})).rejects.toThrow(
      'Concurrency must be a positive integer'
    );
  });

  it('shuffles a copy, keeping every item once', () => {
    const items = ['a', 'b', 'c', 'd'];
    expect(shuffle(items, () => 0)).toEqual(['b', 'c', 'd', 'a']);
    expect(items).toEqual(['a', 'b', 'c', 'd']);
    expect(shuffle(items).sort()).toEqual(items);
    expect(shuffle([])).toEqual([]);
  });

  it('collects organization accounts in shuffled order', async () => {
    const accounts = ['111111111111', '222222222222', '333333333333'];
    const collected: string[] = [];
    const collect = jest.fn(async (event: CollectorEvent) => {
      collected.push(event.accountId);
      return {
        accountId: event.accountId,
        region: 'us-west-2',
        status: 'SUCCEEDED' as const,
        failedServices: [],
        retryableServices: [],
        nodes: 0,
        edges: 0,
        skippedEdges: 0,
        tombstoned: 0,
        batches: 0,
      };
    });

    await runCommand(
      'organization-collector',
      { ...collectionEnvironment, COLLECTION_CONCURRENCY: '1' },
      new AbortController().signal,
      {
        inventory: async () => ({
          workItems: accounts.map((accountId) => ({
            accountId,
            region: 'us-west-2',
            collectGlobal: true,
          })),
        }),
        collect,
        random: () => 0,
      }
    );

    expect(collected).toEqual(['222222222222', '333333333333', '111111111111']);
  });

  it('serves bounded graph mutations and classifies persistence failures', async () => {
    let release: (result: { success: true; written: number; tombstoned: number }) => void;
    const write = jest
      .fn()
      .mockImplementationOnce(
        () =>
          new Promise((resolve) => {
            release = resolve;
          })
      )
      .mockRejectedValueOnce(
        new Error('Server error: {"code":"MemoryLimitExceededException"} (597)')
      )
      .mockRejectedValueOnce(
        Object.assign(
          new Error(
            'Server error: {"code":"InternalFailureException","message":"Property cardinality can only be set for a Vertex"} (500)'
          ),
          { statusCode: 500 }
        )
      );
    const token = 'runtime-test-graph-token';
    const server = createGraphWriterServer(write, 1024, 1, token);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const writer = createHttpGraphWriter(`http://127.0.0.1:${port}`, 1000, fetch, token);
    const mutation = {
      nodes: [{ id: 'node-1', label: 'AwsAccount', properties: {} }],
      edges: [],
      observedAt: '2026-09-11T00:00:00.000Z',
    };

    const first = writer(mutation);
    await new Promise((resolve) => setImmediate(resolve));
    await expect(writer(mutation)).rejects.toThrow(
      '503: {"error":"Graph writer is busy","retryable":true}'
    );
    release!({ success: true, written: 1, tombstoned: 0 });
    await expect(first).resolves.toEqual({
      success: true,
      written: 1,
      skipped: 0,
      tombstoned: 0,
    });
    await expect(writer(mutation)).rejects.toThrow(
      '503: {"error":"Graph persistence failed","retryable":true}'
    );
    await expect(writer(mutation)).rejects.toThrow(
      '500: {"error":"Graph persistence failed","retryable":false}'
    );
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
  });

  it('retries 503 responses and connection failures with backoff, and nothing else', async () => {
    const mutation = {
      nodes: [{ id: 'node-1', label: 'AwsAccount', properties: {} }],
      edges: [],
      observedAt: '2026-09-11T00:00:00.000Z',
    };
    const busy = () => new Response('{"error":"Graph writer is busy"}', { status: 503 });
    const ok = () => new Response('{"success":true,"written":1,"skipped":2}', { status: 200 });
    const sleep = jest.fn<Promise<void>, [number]>(async () => undefined);
    const writer = (request: jest.Mock, attempts: number) =>
      createHttpGraphWriter(
        'http://graph-writer',
        1000,
        request as unknown as typeof fetch,
        'token',
        {
          attempts,
          delayMs: 100,
          sleep,
        }
      );

    const recovers = jest
      .fn()
      .mockResolvedValueOnce(busy())
      .mockRejectedValueOnce(new TypeError('fetch failed'))
      .mockResolvedValueOnce(ok());
    await expect(writer(recovers, 4)(mutation)).resolves.toEqual({
      success: true,
      written: 1,
      skipped: 2,
      tombstoned: 0,
    });
    expect(recovers).toHaveBeenCalledTimes(3);
    expect(sleep.mock.calls.map(([ms]) => ms)).toEqual([100, 200]);

    const exhausted = jest.fn(async () => busy());
    await expect(writer(exhausted, 3)(mutation)).rejects.toThrow('503:');
    expect(exhausted).toHaveBeenCalledTimes(3);

    const permanent = jest.fn(async () => new Response('{"error":"nope"}', { status: 500 }));
    await expect(writer(permanent, 3)(mutation)).rejects.toThrow('500:');
    expect(permanent).toHaveBeenCalledTimes(1);
  });

  it('finishes degraded accounts once and retries only transient collection failures', async () => {
    const environment = { ...collectionEnvironment, COLLECTION_RETRY_DELAY_MS: '1' };
    const inventory = async () => ({
      workItems: [{ accountId: '111122223333', region: 'us-west-2', collectGlobal: true }],
    });
    const result = (failedServices: string[], retryableServices: string[]) => ({
      accountId: '111122223333',
      region: 'us-west-2',
      status: 'INCOMPLETE' as const,
      failedServices,
      retryableServices,
      nodes: 0,
      edges: 0,
      skippedEdges: 0,
      tombstoned: 0,
      batches: 0,
    });

    const degraded = jest.fn(async () => result(['s3', 'network'], []));
    await expect(
      runCommand('organization-collector', environment, new AbortController().signal, {
        inventory,
        collect: degraded,
      })
    ).resolves.toBeUndefined();
    expect(degraded).toHaveBeenCalledTimes(1);

    const transient = jest.fn(async () => result(['s3', 'ec2-instances'], ['ec2-instances']));
    await expect(
      runCommand('organization-collector', environment, new AbortController().signal, {
        inventory,
        collect: transient,
      })
    ).rejects.toThrow('111122223333/us-west-2 incomplete: ec2-instances');
    expect(transient).toHaveBeenCalledTimes(3);
  });

  it('rejects graph mutations without a valid bearer token', async () => {
    const write = jest.fn();
    const server = createGraphWriterServer(write, 1024, 1, 'runtime-test-graph-token');
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const mutation = {
      nodes: [{ id: 'node-1', label: 'AwsAccount', properties: {} }],
      edges: [],
      observedAt: '2026-09-11T00:00:00.000Z',
    };
    await expect(createHttpGraphWriter(`http://127.0.0.1:${port}`, 1000)(mutation)).rejects.toThrow(
      '401:'
    );
    await expect(
      createHttpGraphWriter(`http://127.0.0.1:${port}`, 1000, fetch, 'wrong-token-value')(mutation)
    ).rejects.toThrow('401:');
    expect(write).not.toHaveBeenCalled();
    const live = await fetch(`http://127.0.0.1:${port}/livez`);
    expect(live.status).toBe(200);
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
  });

  it('forwards a well-formed reconcile and rejects a malformed one', async () => {
    const write = jest.fn().mockResolvedValue({ success: true, written: 1, tombstoned: 0 });
    const token = 'runtime-test-graph-token';
    const server = createGraphWriterServer(write, 1024, 1, token);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    const mutation = {
      nodes: [{ id: 'node-1', label: 'AwsAccount', properties: {} }],
      edges: [],
      observedAt: '2026-09-11T00:00:00.000Z',
      reconcile: {
        scope: 'organization-inventory',
        runId: 'run-1',
        observedAt: '2026-09-11T00:00:00.000Z',
      },
    };

    const malformed = await fetch(`http://127.0.0.1:${port}/mutations`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ ...mutation, reconcile: { scope: 'organization-inventory' } }),
    });
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toEqual({
      error: 'reconcile requires scope, runId, and observedAt',
    });
    expect(write).not.toHaveBeenCalled();

    await expect(
      createHttpGraphWriter(`http://127.0.0.1:${port}`, 1000, fetch, token)(mutation)
    ).resolves.toEqual({ success: true, written: 1, skipped: 0, tombstoned: 0 });
    expect(write).toHaveBeenCalledWith(mutation);

    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
  });

  it('keeps polling when a batch has failed messages', async () => {
    const controller = new AbortController();
    let calls = 0;
    const batch = jest.fn(async () => {
      calls += 1;
      if (calls === 1) return { processed: 1, failed: 2 };
      controller.abort();
      return { processed: 0, failed: 0 };
    });
    await expect(
      runCommand(
        'incremental-collector',
        {
          ...collectionEnvironment,
          SQS_QUEUE_URL: 'https://sqs.us-west-2.amazonaws.com/111122223333/incremental.fifo',
        },
        controller.signal,
        { processBatch: batch as never }
      )
    ).resolves.toBeUndefined();
    expect(batch).toHaveBeenCalledTimes(2);
  });

  it('stops the incremental worker cleanly when signaled', async () => {
    const controller = new AbortController();
    const batch = jest.fn(async ({ abortSignal }: { abortSignal?: AbortSignal }) => {
      await new Promise<void>((resolve) =>
        abortSignal!.addEventListener('abort', () => resolve(), { once: true })
      );
      return { processed: 0, failed: 0 };
    });
    const running = runCommand(
      'incremental-collector',
      {
        ...collectionEnvironment,
        SQS_QUEUE_URL: 'https://sqs.us-west-2.amazonaws.com/111122223333/incremental.fifo',
      },
      controller.signal,
      { processBatch: batch as never }
    );

    await new Promise((resolve) => setImmediate(resolve));
    controller.abort();
    await expect(running).resolves.toBeUndefined();
    expect(batch).toHaveBeenCalledTimes(1);
  });
});

describe('CIEM runtime commands', () => {
  it('validates the environment each CIEM command needs', () => {
    expect(() => validateRuntime('policy-evaluator', {})).toThrow('NEPTUNE_ENDPOINT is required');
    expect(() => validateRuntime('least-privilege-sweep', { NEPTUNE_ENDPOINT: 'x' })).toThrow(
      'ACCESS_ANALYZER_TABLE is required'
    );
    expect(() =>
      validateRuntime('least-privilege-sweep', {
        NEPTUNE_ENDPOINT: 'x',
        ACCESS_ANALYZER_TABLE: 'a',
      })
    ).toThrow('LEAST_PRIVILEGE_TABLE is required');
    expect(() =>
      validateRuntime('least-privilege-sweep', {
        NEPTUNE_ENDPOINT: 'x',
        ACCESS_ANALYZER_TABLE: 'a',
        LEAST_PRIVILEGE_TABLE: 'l',
      })
    ).not.toThrow();
  });

  it('dispatches each CIEM command with the environment it was given', async () => {
    const environment = {
      NEPTUNE_ENDPOINT: 'x',
      ACCESS_ANALYZER_TABLE: 'a',
      LEAST_PRIVILEGE_TABLE: 'l',
    };
    const sweep = jest.fn().mockResolvedValue({});
    const evaluator = jest.fn().mockResolvedValue({});

    await runCommand('least-privilege-sweep', environment, new AbortController().signal, {
      runLeastPrivilegeSweep: sweep,
    });
    expect(sweep).toHaveBeenCalledWith({}, environment);

    await runCommand('policy-evaluator', environment, new AbortController().signal, {
      runPolicyEvaluation: evaluator,
    });
    expect(evaluator).toHaveBeenCalledWith({}, environment);
  });
});

describe('GuardDuty findings sweep', () => {
  const succeeded = {
    accountId: '111122223333',
    region: 'us-west-2',
    status: 'SUCCEEDED' as const,
    failedServices: [],
    retryableServices: [],
    nodes: 0,
    edges: 0,
    skippedEdges: 0,
    tombstoned: 0,
    batches: 0,
  };
  const inventory = async () => ({
    workItems: [{ accountId: '111122223333', region: 'us-west-2', collectGlobal: true }],
  });

  it('is off without an administrator account', () => {
    expect(parseGuardDutyFindingsConfig(collectionEnvironment)).toBeUndefined();
  });

  it('parses the administrator and de-duplicated regions', () => {
    expect(
      parseGuardDutyFindingsConfig({
        GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID: '058264196729',
        GUARDDUTY_FINDING_REGIONS: 'us-east-1, us-west-2,us-east-1',
      })
    ).toEqual({ administratorAccountId: '058264196729', regions: ['us-east-1', 'us-west-2'] });
  });

  it.each([
    [{ GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID: '123' }, 'valid 12-digit'],
    [
      { GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID: '058264196729' },
      'GUARDDUTY_FINDING_REGIONS is required',
    ],
    [
      { GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID: '058264196729', GUARDDUTY_FINDING_REGIONS: 'mars-1' },
      'invalid region',
    ],
  ])('rejects %j at startup', (extra, message) => {
    expect(() =>
      validateRuntime('organization-collector', { ...collectionEnvironment, ...extra })
    ).toThrow(message);
  });

  // DETECTS_ON edges need the resource vertices, so the sweep runs last.
  it('runs after every account when configured', async () => {
    const order: string[] = [];
    const collect = jest.fn(async () => {
      order.push('account');
      return succeeded;
    });
    const collectGuardDutyFindings = jest.fn(async () => {
      order.push('guardduty');
      return [];
    });

    await runCommand(
      'organization-collector',
      {
        ...collectionEnvironment,
        GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID: '058264196729',
        GUARDDUTY_FINDING_REGIONS: 'us-east-1,eu-west-2',
      },
      new AbortController().signal,
      { inventory, collect, collectGuardDutyFindings }
    );

    expect(order).toEqual(['account', 'guardduty']);
    expect(collectGuardDutyFindings).toHaveBeenCalledWith(
      { administratorAccountId: '058264196729', regions: ['us-east-1', 'eu-west-2'] },
      expect.objectContaining({ write: expect.any(Function) })
    );
  });

  // runBounded throws once every account has run if any failed. The sweep
  // reads only the administrator account, so one member account exhausting
  // its retries must not skip it; the failure is still reported after.
  it('still runs when an account fails every attempt, then reports the failure', async () => {
    const order: string[] = [];
    const collect = jest.fn(async () => {
      order.push('account');
      throw new Error('Graph writer returned 500');
    });
    const collectGuardDutyFindings = jest.fn(async () => {
      order.push('guardduty');
      return [];
    });

    await expect(
      runCommand(
        'organization-collector',
        {
          ...collectionEnvironment,
          COLLECTION_RETRY_DELAY_MS: '1',
          GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID: '058264196729',
          GUARDDUTY_FINDING_REGIONS: 'us-west-2',
        },
        new AbortController().signal,
        { inventory, collect, collectGuardDutyFindings }
      )
    ).rejects.toThrow('Graph writer returned 500');
    expect(collectGuardDutyFindings).toHaveBeenCalledTimes(1);
    expect(order.at(-1)).toBe('guardduty');
  });

  it('does not run when unconfigured', async () => {
    const collectGuardDutyFindings = jest.fn();
    await runCommand(
      'organization-collector',
      collectionEnvironment,
      new AbortController().signal,
      {
        inventory,
        collect: jest.fn(async () => succeeded),
        collectGuardDutyFindings,
      }
    );
    expect(collectGuardDutyFindings).not.toHaveBeenCalled();
  });
});
