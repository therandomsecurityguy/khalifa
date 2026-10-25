import type { S3Client } from '@aws-sdk/client-s3';
import type { LambdaClient } from '@aws-sdk/client-lambda';
import type { BucketScanResult } from './s3-sampler';
import type { LambdaScanResult } from './lambda-sampler';
import { runDspmScan, handleSqsEvent } from '../index';

const environment = {
  AWS_REGION: 'us-west-2',
  DSPM_SCAN_MODE: 'tagged-only',
  MACIE_ENABLED: 'false',
  GRAPH_WRITER_FUNCTION_NAME: 'khalifa-graph-writer',
};

const finding: BucketScanResult = {
  bucketArn: 'arn:aws:s3:::sensitive-bucket',
  bucketName: 'sensitive-bucket',
  engine: 'regex',
  macieCovered: false,
  optedIn: true,
  result: {
    piiTypes: ['email'],
    secretCount: 0,
    matches: [{ piiType: 'email', count: 2, confidence: 0.9 }],
    sampleSize: 4,
    skippedKms: 0,
    confidence: 0.9,
    scannedAt: '2026-09-10T12:00:00.000Z',
    classifier: 'regex',
  },
};

function dependencies(scanResults: BucketScanResult[], lambdaResults: LambdaScanResult[] = []) {
  return {
    s3Client: {} as S3Client,
    lambdaClient: {} as LambdaClient,
    classifiers: [],
    scan: jest.fn().mockResolvedValue(scanResults),
    scanLambdas: jest.fn().mockResolvedValue(lambdaResults),
    persist: jest.fn().mockResolvedValue({ success: true, written: 2 }),
  };
}

describe('DSPM handler persistence', () => {
  test('requires a graph-writer transport before scanning', async () => {
    const deps = dependencies([]);
    const { persist: _persist, ...noPersist } = deps;

    await expect(
      runDspmScan({}, noPersist, {
        AWS_REGION: 'us-west-2',
      })
    ).rejects.toThrow('GRAPH_WRITER_FUNCTION_NAME or GRAPH_WRITER_URL is required');
    expect(deps.scan).not.toHaveBeenCalled();
    expect(deps.persist).not.toHaveBeenCalled();
  });

  test('prefers the Lambda-invoke transport when GRAPH_WRITER_FUNCTION_NAME is set', async () => {
    const deps = dependencies([finding]);
    await runDspmScan({ accountId: '111122223333' }, deps, environment);
    expect(deps.persist).toHaveBeenCalledWith(
      expect.objectContaining({ nodes: expect.any(Array), edges: expect.any(Array) }),
      { functionName: 'khalifa-graph-writer' }
    );
  });

  test('uses the HTTP transport when GRAPH_WRITER_URL and token are set', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ success: true, written: 2 }), { status: 200 })
      );
    const originalFetch = global.fetch;
    global.fetch = fetchMock as unknown as typeof fetch;
    try {
      const deps = dependencies([finding]);
      const { persist: _persist, ...noPersist } = deps;
      await runDspmScan({ accountId: '111122223333' }, noPersist, {
        ...environment,
        GRAPH_WRITER_FUNCTION_NAME: '',
        GRAPH_WRITER_URL: 'http://graph-writer:8080',
        GRAPH_WRITER_TOKEN: 'a-super-secret-graph-writer-token',
      });
      expect(deps.persist).not.toHaveBeenCalled();
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0];
      expect(String(url)).toBe('http://graph-writer:8080/mutations');
      expect((init as { headers: Record<string, string> }).headers.authorization).toBe(
        'Bearer a-super-secret-graph-writer-token'
      );
    } finally {
      global.fetch = originalFetch;
    }
  });

  test('rejects a weak GRAPH_WRITER_TOKEN on the HTTP transport', async () => {
    const deps = dependencies([finding]);
    const { persist: _persist2, ...noPersist } = deps;
    await expect(
      runDspmScan({}, noPersist, {
        ...environment,
        GRAPH_WRITER_FUNCTION_NAME: '',
        GRAPH_WRITER_URL: 'http://graph-writer:8080',
        GRAPH_WRITER_TOKEN: 'short',
      })
    ).rejects.toThrow('GRAPH_WRITER_TOKEN must be at least 16 characters');
  });

  test('uses a deterministic per-bucket finding ID and reports only persisted findings', async () => {
    const deps = dependencies([finding]);

    await expect(runDspmScan({ accountId: '111122223333' }, deps, environment)).resolves.toEqual({
      bucketsScanned: 1,
      functionsScanned: 0,
      findingsWritten: 1,
      errors: 0,
      uncoveredBuckets: 0,
    });
    await runDspmScan({ accountId: '111122223333' }, deps, environment);

    expect(deps.scan).toHaveBeenCalledWith(
      deps.s3Client,
      deps.classifiers,
      'tagged-only',
      undefined,
      { deadlineAt: expect.any(Number) },
      undefined
    );
    expect(deps.persist).toHaveBeenCalledTimes(2);

    const firstMutations = deps.persist.mock.calls[0][0];
    const secondMutations = deps.persist.mock.calls[1][0];
    expect(firstMutations.nodes[0]).toMatchObject({
      id: 'arn:aws:s3:::sensitive-bucket/dspm-finding',
      label: 'DataClassificationFinding',
      observedAt: finding.result!.scannedAt,
      properties: { account_id: '111122223333', data_classification: 'restricted' },
    });
    expect(firstMutations.edges[0]).toMatchObject({
      from: firstMutations.nodes[0].id,
      to: finding.bucketArn,
      label: 'CLASSIFIES',
      observedAt: finding.result!.scannedAt,
    });
    expect(secondMutations.nodes[0].id).toBe(firstMutations.nodes[0].id);
    expect(deps.persist.mock.calls[0][1]).toEqual({
      functionName: 'khalifa-graph-writer',
    });
  });

  test('does not invoke the graph writer when there are no findings', async () => {
    const deps = dependencies([
      {
        bucketArn: 'arn:aws:s3:::clean-bucket',
        bucketName: 'clean-bucket',
        engine: 'regex',
        macieCovered: false,
        optedIn: true,
        result: {
          piiTypes: [],
          secretCount: 0,
          matches: [],
          sampleSize: 3,
          skippedKms: 0,
          confidence: 0,
          scannedAt: '2026-09-10T12:00:00.000Z',
          classifier: 'regex',
        },
      },
    ]);

    await expect(runDspmScan({}, deps, environment)).resolves.toEqual({
      bucketsScanned: 1,
      functionsScanned: 0,
      findingsWritten: 0,
      errors: 0,
      uncoveredBuckets: 0,
    });
    expect(deps.persist).not.toHaveBeenCalled();
  });

  test('persists successful findings before rejecting partial bucket failures', async () => {
    const deps = dependencies([
      finding,
      {
        bucketArn: 'arn:aws:s3:::unavailable-bucket',
        bucketName: 'unavailable-bucket',
        engine: 'none',
        macieCovered: false,
        optedIn: false,
        result: null,
        error: 'AccessDenied',
      },
    ]);

    await expect(runDspmScan({}, deps, environment)).rejects.toThrow(
      'DSPM scan completed with 1 bucket failure(s): unavailable-bucket: AccessDenied'
    );
    expect(deps.persist).toHaveBeenCalledTimes(1);
  });

  test('fails when a bucket is both Macie-covered and tagged dspm-scan', async () => {
    const deps = dependencies([{ ...finding, engine: 'macie', macieCovered: true, optedIn: true }]);

    await expect(runDspmScan({}, deps, environment)).rejects.toThrow(
      /DSPM misconfiguration: 1 bucket\(s\) are both Macie-covered and tagged/
    );
    expect(deps.persist).not.toHaveBeenCalled();
  });

  test('reports buckets that neither Macie covers nor the tag opts in', async () => {
    const deps = dependencies([
      {
        bucketArn: 'arn:aws:s3:::orphan',
        bucketName: 'orphan',
        engine: 'none',
        macieCovered: false,
        optedIn: false,
        result: null,
      },
    ]);

    await expect(runDspmScan({}, deps, environment)).resolves.toMatchObject({
      bucketsScanned: 1,
      uncoveredBuckets: 1,
    });
  });

  test('uses the graph bucket inventory when NEPTUNE_ENDPOINT is set', async () => {
    const graphClient = {
      submit: jest.fn(async () => ({
        toArray: () => [
          new Map([
            ['name', 'prod-bucket'],
            ['accountId', '111122223333'],
          ]),
        ],
      })),
    };
    const deps = { ...dependencies([finding]), graphClient };

    await runDspmScan({}, deps, { ...environment, NEPTUNE_ENDPOINT: 'wss://cluster:8182/gremlin' });

    expect(deps.scan).toHaveBeenCalledWith(
      deps.s3Client,
      deps.classifiers,
      'tagged-only',
      undefined,
      { deadlineAt: expect.any(Number) },
      [{ name: 'prod-bucket', accountId: '111122223333' }]
    );
  });

  test('uses Macie\u2019s own bucket inventory when Macie is enabled', async () => {
    const macieClassifier = {
      classify: jest.fn(),
      getFindingsForBucket: jest.fn().mockResolvedValue([]),
      hasCoverage: jest.fn().mockResolvedValue(false),
      listBuckets: jest.fn().mockResolvedValue([{ name: 'prod-data', accountId: '111122223333' }]),
    };
    const deps = {
      ...dependencies([finding]),
      macieClassifier: macieClassifier as unknown as NonNullable<
        Parameters<typeof runDspmScan>[1]
      >['macieClassifier'],
    };

    await runDspmScan({}, deps, { ...environment, MACIE_ENABLED: 'true' });

    expect(macieClassifier.listBuckets).toHaveBeenCalled();
    expect(deps.scan).toHaveBeenCalledWith(
      deps.s3Client,
      deps.classifiers,
      'tagged-only',
      macieClassifier,
      { deadlineAt: expect.any(Number) },
      [{ name: 'prod-data', accountId: '111122223333' }]
    );
  });

  test('propagates graph-writer failures', async () => {
    const deps = dependencies([finding]);
    deps.persist.mockRejectedValue(new Error('graph write failed'));

    await expect(runDspmScan({}, deps, environment)).rejects.toThrow('graph write failed');
  });

  test('scans lambda env vars into findings with a degraded persist failure', async () => {
    const lambdaFinding: LambdaScanResult = {
      functionArn: 'arn:aws:lambda:us-west-2:111122223333:function:leaky-fn',
      functionName: 'leaky-fn',
      result: {
        piiTypes: ['aws_access_key'],
        secretCount: 0,
        matches: [{ piiType: 'aws_access_key', count: 1, confidence: 0.95 }],
        sampleSize: 3,
        skippedKms: 0,
        confidence: 0.95,
        scannedAt: '2026-09-10T12:00:00.000Z',
        classifier: 'regex',
      },
    };
    const deps = dependencies([], [lambdaFinding]);

    await expect(runDspmScan({ accountId: '111122223333' }, deps, environment)).resolves.toEqual({
      bucketsScanned: 0,
      functionsScanned: 1,
      findingsWritten: 1,
      errors: 0,
      uncoveredBuckets: 0,
    });

    expect(deps.scanLambdas).toHaveBeenCalledWith(deps.lambdaClient, deps.classifiers);
    expect(deps.persist).toHaveBeenCalledTimes(1);
    const mutations = deps.persist.mock.calls[0][0];
    expect(mutationsNodes(mutations)[0]).toMatchObject({
      id: 'arn:aws:lambda:us-west-2:111122223333:function:leaky-fn/dspm-finding',
      label: 'DataClassificationFinding',
      properties: {
        data_classification: 'restricted',
        sample_size: 3,
      },
    });
    expect(mutationsEdges(mutations)[0]).toMatchObject({
      from: 'arn:aws:lambda:us-west-2:111122223333:function:leaky-fn/dspm-finding',
      to: 'arn:aws:lambda:us-west-2:111122223333:function:leaky-fn',
      label: 'CLASSIFIES',
    });
  });

  test('counts lambda findings but warns when the persist fails on missing endpoints', async () => {
    const lambdaFinding: LambdaScanResult = {
      functionArn: 'arn:aws:lambda:us-west-2:111122223333:function:leaky-fn',
      functionName: 'leaky-fn',
      result: {
        piiTypes: ['email'],
        secretCount: 0,
        matches: [],
        sampleSize: 2,
        skippedKms: 0,
        confidence: 0.4,
        scannedAt: '2026-09-10T12:00:00.000Z',
        classifier: 'regex',
      },
    };
    const deps = dependencies([], [lambdaFinding]);
    deps.persist.mockRejectedValueOnce(
      new Error('Neptune could not write edge; verify both endpoints exist')
    );

    await expect(runDspmScan({}, deps, environment)).resolves.toEqual({
      bucketsScanned: 0,
      functionsScanned: 1,
      findingsWritten: 0,
      errors: 1,
      uncoveredBuckets: 0,
    });
  });

  test('writes both bucket and lambda findings when both scans produce them', async () => {
    const lambdaFinding: LambdaScanResult = {
      functionArn: 'arn:aws:lambda:us-west-2:111122223333:function:leaky-fn',
      functionName: 'leaky-fn',
      result: {
        piiTypes: ['private_key'],
        secretCount: 1,
        matches: [],
        sampleSize: 2,
        skippedKms: 0,
        confidence: 0.99,
        scannedAt: '2026-09-10T12:00:00.000Z',
        classifier: 'regex',
      },
    };
    const deps = dependencies([finding], [lambdaFinding]);

    await expect(runDspmScan({}, deps, environment)).resolves.toEqual({
      bucketsScanned: 1,
      functionsScanned: 1,
      findingsWritten: 2,
      errors: 0,
      uncoveredBuckets: 0,
    });
    expect(deps.persist).toHaveBeenCalledTimes(2);
  });

  test('lambda scan errors are counted in errors without failing the scan', async () => {
    const deps = dependencies(
      [],
      [
        {
          functionArn: 'arn:aws:lambda:us-west-2:111122223333:function:f',
          functionName: 'f',
          result: null,
          error: 'ThrottlingException',
        },
      ]
    );

    await expect(runDspmScan({}, deps, environment)).resolves.toEqual({
      bucketsScanned: 0,
      functionsScanned: 1,
      findingsWritten: 0,
      errors: 1,
      uncoveredBuckets: 0,
    });
    expect(deps.persist).not.toHaveBeenCalled();
  });
});

function mutationsNodes(mutations: { nodes: unknown[] }): unknown[] {
  return mutations.nodes;
}

function mutationsEdges(mutations: { edges: unknown[] }): unknown[] {
  return mutations.edges;
}

describe('handleSqsEvent', () => {
  const s3EventBody = (bucket: string, key: string, size: number) =>
    JSON.stringify({ Records: [{ s3: { bucket: { name: bucket }, object: { key, size } } }] });

  // Event-driven scans only read from buckets tagged dspm-scan=true.
  const optedInTags = () => ({ TagSet: [{ Key: 'dspm-scan', Value: 'true' }] });

  // GitHub-token-shaped so secret scanners do not mistake the fixture for a
  // real AWS access key; the regex classifier still flags it as a secret.
  const TEST_SECRET = 'ghp_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

  const s3ClientWithOptIn = (getObjectBody: string | null, optedIn = true) =>
    ({
      send: jest.fn(async (command: { constructor: { name: string } }) => {
        if (command.constructor.name === 'GetBucketTaggingCommand') {
          return optedIn ? optedInTags() : { TagSet: [] };
        }
        if (command.constructor.name === 'GetObjectCommand') {
          return { Body: { transformToString: jest.fn().mockResolvedValue(getObjectBody) } };
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    }) as unknown as S3Client;

  it('scans objects from S3 event notifications and writes findings', async () => {
    const s3Client = s3ClientWithOptIn(TEST_SECRET);
    const persist = jest.fn().mockResolvedValue({ success: true, written: 1 });

    const result = await handleSqsEvent(
      { Records: [{ body: s3EventBody('leaky-bucket', 'secret.txt', 10) }] },
      { s3Client, persist },
      environment
    );

    expect(result).toEqual({ objectsScanned: 1, findingsWritten: 1 });
    expect(persist).toHaveBeenCalledTimes(1);
    const mutations = persist.mock.calls[0][0];
    expect(mutationsNodes(mutations)[0]).toMatchObject({
      id: 'arn:aws:s3:::leaky-bucket/dspm-finding',
      label: 'DataClassificationFinding',
    });
    expect(mutationsEdges(mutations)[0]).toMatchObject({
      to: 'arn:aws:s3:::leaky-bucket',
      label: 'CLASSIFIES',
    });
  });

  it('skips buckets that have not opted in via the dspm-scan tag', async () => {
    const s3Client = s3ClientWithOptIn(TEST_SECRET, false);
    const persist = jest.fn().mockResolvedValue({ success: true, written: 1 });

    const result = await handleSqsEvent(
      { Records: [{ body: s3EventBody('unlisted-bucket', 'secret.txt', 10) }] },
      { s3Client, persist },
      environment
    );

    expect(result).toEqual({ objectsScanned: 0, findingsWritten: 0 });
    expect(persist).not.toHaveBeenCalled();
    const commands = (s3Client.send as jest.Mock).mock.calls.map(
      (c: unknown[]) => (c[0] as { constructor: { name: string } }).constructor.name
    );
    expect(commands).toContain('GetBucketTaggingCommand');
    expect(commands).not.toContain('GetObjectCommand');
  });

  it('skips all objects when DSPM_SCAN_MODE is off', async () => {
    const s3Client = s3ClientWithOptIn(TEST_SECRET);
    const persist = jest.fn().mockResolvedValue({ success: true, written: 1 });

    const result = await handleSqsEvent(
      { Records: [{ body: s3EventBody('leaky-bucket', 'secret.txt', 10) }] },
      { s3Client, persist },
      { ...environment, DSPM_SCAN_MODE: 'off' }
    );

    expect(result).toEqual({ objectsScanned: 0, findingsWritten: 0 });
    expect(persist).not.toHaveBeenCalled();
    expect(s3Client.send).not.toHaveBeenCalled();
  });

  it('skips malformed bodies and objects without findings', async () => {
    const s3Client = s3ClientWithOptIn('clean text');
    const persist = jest.fn().mockResolvedValue({ success: true, written: 0 });

    const result = await handleSqsEvent(
      {
        Records: [{ body: 'not-json' }, { body: s3EventBody('clean-bucket', 'clean.txt', 10) }],
      },
      { s3Client, persist },
      environment
    );

    expect(result).toEqual({ objectsScanned: 1, findingsWritten: 0 });
    expect(persist).not.toHaveBeenCalled();
  });

  it('requires the graph-writer function', async () => {
    await expect(handleSqsEvent({ Records: [] }, {}, { AWS_REGION: 'us-west-2' })).rejects.toThrow(
      'GRAPH_WRITER_FUNCTION_NAME or GRAPH_WRITER_URL is required'
    );
  });
});
