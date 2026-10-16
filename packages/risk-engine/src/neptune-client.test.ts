import Gremlin from 'gremlin';
import {
  createSigV4Headers,
  isNeptuneRetryable,
  isNeptuneServerlessTransient,
  NeptuneRuntimeClient,
  normalizeNeptuneEndpoint,
} from './neptune-client';

class FakeClient {
  isOpen = false;
  openCalls = 0;
  closeCalls = 0;
  submissions: unknown[] = [];

  constructor(private readonly result: () => Promise<unknown>) {}

  async open(): Promise<void> {
    this.openCalls++;
    this.isOpen = true;
  }

  async close(): Promise<void> {
    this.closeCalls++;
    this.isOpen = false;
  }

  async submit(message: unknown): Promise<unknown> {
    this.submissions.push(message);
    return this.result();
  }
}

function createClient(
  fake: FakeClient,
  overrides: { timeoutMs?: number; maxAttempts?: number; maxResults?: number } = {}
) {
  return new NeptuneRuntimeClient(
    { endpoint: 'cluster.example.com', ...overrides },
    {
      createClient: () => fake,
      createHeaders: async () => ({ authorization: 'signed' }),
      sleep: async () => undefined,
    }
  );
}

describe('risk-engine Neptune client', () => {
  it('submits bytecode without script bindings', async () => {
    // Neptune rejects script bindings ("Bindings in Gremlin are not
    // supported"), so the client only ever forwards a script or Bytecode.
    const fake = new FakeClient(async () => [{}]);
    const client = createClient(fake);
    const bytecode = new Gremlin.process.Bytecode();

    await client.submit(bytecode);

    expect(fake.submissions).toEqual([bytecode]);
  });

  it('submit bypasses the result guard for callers that page themselves', async () => {
    // The CIEM lambdas page with range() and cap the total in enumerateGraph,
    // so a legitimate page can exceed maxResults.
    const rows = Array.from({ length: 5 }, (_, index) => ({ index }));
    const fake = new FakeClient(async () => rows);
    const client = createClient(fake, { maxResults: 3 });

    await expect(client.submit('g.V().range(0,5)')).resolves.toHaveLength(5);
    await expect(client.executeQuery('g.V()')).rejects.toThrow(
      'exceeded the configured result limit of 3'
    );
  });

  it('normalizes and signs a Neptune data-plane endpoint', async () => {
    const endpoint = normalizeNeptuneEndpoint('https://cluster.example.com/gremlin');
    const headers = await createSigV4Headers(endpoint, 'us-west-2', async () => ({
      accessKeyId: 'AKIDEXAMPLE',
      secretAccessKey: 'secret',
      sessionToken: 'token',
    }));

    expect(endpoint.url).toBe('wss://cluster.example.com:8182/gremlin');
    expect(headers.authorization).toContain('/us-west-2/neptune-db/aws4_request');
  });

  it('reuses one connection and applies a server-side result limit', async () => {
    const fake = new FakeClient(async () => ({ toArray: () => [1, 2, 3] }));
    const client = createClient(fake);

    await Promise.all([client.connect(), client.connect()]);
    await expect(client.executeQuery('g.V()')).resolves.toEqual([1, 2, 3]);

    expect(fake.openCalls).toBe(1);
    expect(fake.submissions[0]).toBe('g.V().limit(10001)');
  });

  it('does not append a result limit to a terminal count', async () => {
    const fake = new FakeClient(async () => ({ toArray: () => [3] }));
    const client = createClient(fake);

    await expect(client.executeQuery('g.V().count();')).resolves.toEqual([3]);

    expect(fake.submissions[0]).toBe('g.V().count()');
  });

  it('unwraps Traverser results from bytecode submissions and expands bulk', async () => {
    const vertex = new Map<unknown, unknown>([[Gremlin.process.t.id, 'v1']]);
    const fake = new FakeClient(async () => ({
      toArray: () => [new Gremlin.process.Traverser(vertex, 2), 'plain'],
    }));
    await expect(createClient(fake).execute(new Gremlin.process.Bytecode())).resolves.toEqual([
      vertex,
      vertex,
      'plain',
    ]);
  });

  it('rejects an oversized traverser bulk without allocating it', async () => {
    const fake = new FakeClient(async () => ({
      toArray: () => [new Gremlin.process.Traverser('v', Number.MAX_SAFE_INTEGER)],
    }));
    await expect(
      createClient(fake, { maxResults: 3 }).execute(new Gremlin.process.Bytecode())
    ).rejects.toThrow('result limit');
  });

  it('rejects an over-limit result', async () => {
    const fake = new FakeClient(async () => ({ toArray: () => [1, 2] }));
    await expect(createClient(fake, { maxResults: 1 }).executeQuery('g.V()')).rejects.toThrow(
      'result limit'
    );
  });

  it('retries ConcurrentModificationException and MemoryLimitExceededException', () => {
    expect(
      isNeptuneRetryable(
        new Error(
          'Server error: {"code":"ConcurrentModificationException","message":"Please retry."} (500)'
        )
      )
    ).toBe(true);
    expect(
      isNeptuneRetryable({
        message:
          'Server error: {"code":"MemoryLimitExceededException","message":"Query cannot be completed due to memory limitations."} (597)',
        statusCode: 597,
      })
    ).toBe(true);
  });

  it('does not retry Neptune InternalFailureException just because its status is 500', () => {
    expect(
      isNeptuneRetryable({
        message:
          'Server error: {"code":"InternalFailureException","message":"Property cardinality can only be set for a Vertex"} (500)',
        statusCode: 500,
      })
    ).toBe(false);
    expect(
      isNeptuneRetryable({
        message: 'Server error: {"code":"ConcurrentModificationException"} (500)',
        statusCode: 500,
      })
    ).toBe(true);
    expect(isNeptuneRetryable({ message: 'Service Unavailable', statusCode: 503 })).toBe(true);
  });

  it.each([
    'ThrottlingException',
    'Connection has been closed.',
    'ConcurrentModificationException',
  ])('reconnects after %s', async (message) => {
    const clients = [
      new FakeClient(async () => {
        throw new Error(message);
      }),
      new FakeClient(async () => ({ toArray: () => ['ok'] })),
    ];
    const client = new NeptuneRuntimeClient(
      { endpoint: 'cluster.example.com', maxAttempts: 2 },
      {
        createClient: () => clients.shift()!,
        createHeaders: async () => ({ authorization: 'signed' }),
        sleep: async () => undefined,
      }
    );

    await expect(client.executeQuery('g.V()')).resolves.toEqual(['ok']);
  });

  it('times out a stalled query and closes the connection', async () => {
    jest.useFakeTimers();
    const fake = new FakeClient(async () => new Promise(() => undefined));
    const client = createClient(fake, { timeoutMs: 25, maxAttempts: 1 });
    const rejected = expect(client.executeQuery('g.V()')).rejects.toThrow('timeout');

    await jest.advanceTimersByTimeAsync(26);
    await rejected;
    expect(fake.closeCalls).toBe(1);
    jest.useRealTimers();
  });

  it('classifies only Serverless capacity errors as the patient-retry class', () => {
    expect(
      isNeptuneServerlessTransient({
        message: 'Server error: {"code":"MemoryLimitExceededException"} (500)',
      })
    ).toBe(true);
    expect(isNeptuneServerlessTransient({ message: 'ConcurrentModificationException' })).toBe(true);
    expect(isNeptuneServerlessTransient({ message: 'Neptune timeout' })).toBe(false);
  });

  it('gives a Neptune Serverless memory error more attempts and a longer backoff', async () => {
    const sleeps: number[] = [];
    const fake = new FakeClient(async () => {
      throw new Error('Server error: {"code":"MemoryLimitExceededException"} (500)');
    });
    const client = new NeptuneRuntimeClient(
      { endpoint: 'cluster.example.com', maxAttempts: 3 },
      {
        createClient: () => fake,
        createHeaders: async () => ({ authorization: 'signed' }),
        sleep: async (ms) => {
          sleeps.push(ms);
        },
      }
    );

    await expect(client.executeQuery('g.V()')).rejects.toThrow('MemoryLimitExceededException');
    // 5 attempts (not the configured 3) -> 4 waits: 500 / 1000 / 2000 / 4000.
    expect(sleeps).toEqual([500, 1000, 2000, 4000]);
  });
});
