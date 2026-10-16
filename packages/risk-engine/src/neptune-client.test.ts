import Gremlin from 'gremlin';
import {
  NeptuneRuntimeClient,
  isNeptuneRetryable,
  normalizeNeptuneEndpoint,
  withTimeout,
} from './neptune-client';

class FakeConnection {
  isOpen = false;
  open = jest.fn(async () => {
    this.isOpen = true;
  });
  close = jest.fn(async () => {
    this.isOpen = false;
  });
  submit: jest.Mock;

  constructor(impl: (query: unknown) => unknown) {
    this.submit = jest.fn(async (query: unknown) => impl(query));
  }

  asClient(): Gremlin.driver.Client {
    return this as unknown as Gremlin.driver.Client;
  }
}

function clientWith(connections: FakeConnection[]): NeptuneRuntimeClient {
  return new NeptuneRuntimeClient(
    { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1' },
    {
      createHeaders: async () => ({}),
      createClient: () => {
        const next = connections.shift();
        if (!next) throw new Error('no fake connections left');
        return next.asClient();
      },
      sleep: async () => undefined,
    }
  );
}

describe('normalizeNeptuneEndpoint', () => {
  it('normalizes bare hostnames to a wss gremlin URL on 8182', () => {
    expect(normalizeNeptuneEndpoint('cluster.example.com')).toEqual({
      hostname: 'cluster.example.com',
      port: 8182,
      url: 'wss://cluster.example.com:8182/gremlin',
    });
  });

  it('accepts explicit wss urls and ports', () => {
    expect(normalizeNeptuneEndpoint('wss://cluster.example.com:9000/gremlin')).toEqual({
      hostname: 'cluster.example.com',
      port: 9000,
      url: 'wss://cluster.example.com:9000/gremlin',
    });
  });

  it('rejects empty values', () => {
    expect(() => normalizeNeptuneEndpoint('  ')).toThrow('NEPTUNE_ENDPOINT is required');
  });

  it('rejects non wss/https protocols', () => {
    expect(() => normalizeNeptuneEndpoint('http://cluster.example.com')).toThrow(
      'NEPTUNE_ENDPOINT must use wss or https'
    );
  });

  it('rejects credentials, query parameters, and fragments', () => {
    expect(() => normalizeNeptuneEndpoint('wss://user:pass@cluster.example.com/gremlin')).toThrow(
      'must not contain credentials'
    );
    expect(() => normalizeNeptuneEndpoint('wss://cluster.example.com/gremlin?x=1')).toThrow(
      'must not contain credentials'
    );
    expect(() => normalizeNeptuneEndpoint('wss://cluster.example.com/gremlin#frag')).toThrow(
      'must not contain credentials'
    );
  });

  it('rejects unexpected paths', () => {
    expect(() => normalizeNeptuneEndpoint('wss://cluster.example.com/other')).toThrow(
      'path must be /gremlin'
    );
  });
});

describe('isNeptuneRetryable', () => {
  it('retries transient HTTP status codes', () => {
    expect(isNeptuneRetryable({ statusCode: 503 })).toBe(true);
    expect(isNeptuneRetryable({ $metadata: { httpStatusCode: 429 } })).toBe(true);
  });

  it('retries known transient error text', () => {
    expect(isNeptuneRetryable(new Error('connect ECONNREFUSED 10.0.0.1:8182'))).toBe(true);
    expect(isNeptuneRetryable(new Error('ThrottlingException'))).toBe(true);
    expect(isNeptuneRetryable(new Error('MemoryLimitExceededException'))).toBe(true);
  });

  it('does not retry application errors', () => {
    expect(isNeptuneRetryable(new Error('Gremlin query is invalid'))).toBe(false);
  });
});

describe('NeptuneRuntimeClient', () => {
  it('rejects an empty query', async () => {
    const client = clientWith([new FakeConnection(() => [])]);
    await expect(client.executeQuery('  ')).rejects.toThrow('Gremlin query is required');
  });

  it('bounds queries with a result guard unless they count', async () => {
    const connection = new FakeConnection(() => []);
    const client = new NeptuneRuntimeClient(
      { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1', maxResults: 5 },
      {
        createHeaders: async () => ({}),
        createClient: () => connection.asClient(),
      }
    );

    await client.executeQuery('g.V()');
    expect(connection.submit).toHaveBeenCalledWith('g.V().limit(6)', undefined, expect.anything());

    await client.executeQuery('g.V().count()');
    expect(connection.submit).toHaveBeenLastCalledWith(
      'g.V().count()',
      undefined,
      expect.anything()
    );
  });

  it('submits unbounded queries through submit()', async () => {
    const connection = new FakeConnection(() => []);
    const client = new NeptuneRuntimeClient(
      { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1' },
      {
        createHeaders: async () => ({}),
        createClient: () => connection.asClient(),
      }
    );

    await client.submit('g.V().range(0, 20000)');
    expect(connection.submit).toHaveBeenCalledWith(
      'g.V().range(0, 20000)',
      undefined,
      expect.anything()
    );
  });

  it('throws when the result set exceeds the configured limit', async () => {
    const connection = new FakeConnection(() => [1, 2, 3]);
    const client = new NeptuneRuntimeClient(
      { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1', maxResults: 2 },
      {
        createHeaders: async () => ({}),
        createClient: () => connection.asClient(),
      }
    );

    await expect(client.executeQuery('g.V()')).rejects.toThrow(
      'Neptune query exceeded the configured result limit of 2'
    );
  });

  it('rejects malformed result sets', async () => {
    const connection = new FakeConnection(() => ({ notAResultSet: true }));
    const client = new NeptuneRuntimeClient(
      { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1' },
      {
        createHeaders: async () => ({}),
        createClient: () => connection.asClient(),
      }
    );

    await expect(client.submit('g.V()')).rejects.toThrow('Neptune returned an invalid result set');
  });

  it('expands traversers by bulk', async () => {
    const connection = new FakeConnection(() => [
      new Gremlin.process.Traverser('a', 2),
      new Gremlin.process.Traverser('b', 1),
    ]);
    const client = new NeptuneRuntimeClient(
      { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1' },
      {
        createHeaders: async () => ({}),
        createClient: () => connection.asClient(),
      }
    );

    await expect(client.submit('g.V()')).resolves.toEqual(['a', 'a', 'b']);
  });

  it('reconnects after a retryable failure', async () => {
    const failing = new FakeConnection(() => {
      throw { statusCode: 503, message: 'Service Unavailable' };
    });
    const healthy = new FakeConnection(() => []);
    const client = new NeptuneRuntimeClient(
      { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1' },
      {
        createHeaders: async () => ({}),
        createClient: () => (failing.submit.mock.calls.length ? healthy : failing).asClient(),
        sleep: async () => undefined,
      }
    );

    await expect(client.submit('g.V()')).resolves.toEqual([]);
    expect(failing.close).toHaveBeenCalled();
  });

  it('surfaces non-retryable failures without retrying', async () => {
    const connection = new FakeConnection(() => {
      throw new Error('Gremlin query is invalid');
    });
    const client = new NeptuneRuntimeClient(
      { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1' },
      {
        createHeaders: async () => ({}),
        createClient: () => connection.asClient(),
      }
    );

    await expect(client.executeQuery('g.V(')).rejects.toThrow('Gremlin query is invalid');
    expect(connection.submit).toHaveBeenCalledTimes(1);
  });

  it('closes the connection and reopens on the next query', async () => {
    const first = new FakeConnection(() => []);
    const second = new FakeConnection(() => []);
    const connections = [first, second];
    const client = new NeptuneRuntimeClient(
      { endpoint: 'wss://cluster.example.com:8182/gremlin', region: 'us-east-1' },
      {
        createHeaders: async () => ({}),
        createClient: () => (connections.shift() ?? second).asClient(),
      }
    );

    await client.submit('g.V()');
    await client.close();
    expect(first.close).toHaveBeenCalled();

    await client.submit('g.V()');
    expect(second.open).toHaveBeenCalled();
  });
});

describe('withTimeout', () => {
  it('resolves when the promise settles in time', async () => {
    await expect(withTimeout(Promise.resolve('ok'), 1000, 'test')).resolves.toBe('ok');
  });

  it('rejects when the promise exceeds the timeout', async () => {
    jest.useFakeTimers();
    try {
      const pending = withTimeout(new Promise(() => undefined), 50, 'Neptune query');
      const assertion = expect(pending).rejects.toThrow('Neptune query timeout after 50ms');
      jest.advanceTimersByTime(51);
      await assertion;
    } finally {
      jest.useRealTimers();
    }
  });
});
