import Gremlin from 'gremlin';
import {
  createGraphWriterHandler,
  createRemoteTraversal,
  createRuntimeWriter,
  NeptuneGraphWriter,
  normalizeNeptuneEndpoint,
  type WriterDependencies,
  type WriterEvent,
} from './index';

class FakeConnection {
  isOpen = false;
  openCalls = 0;
  closeCalls = 0;

  async open(): Promise<void> {
    this.openCalls += 1;
    this.isOpen = true;
  }

  async close(): Promise<void> {
    this.closeCalls += 1;
    this.isOpen = false;
  }
}

const event: WriterEvent = {
  nodes: [{ id: 'arn:aws:s3:::bucket', label: 'S3Bucket', properties: {} }],
  edges: [],
};

function createWriter(
  connections: FakeConnection[],
  write: jest.Mock,
  maxAttempts = 2,
  timeoutMs = 1_000
) {
  const createHeaders = jest.fn(async () => ({ authorization: 'signed' }));
  const dependencies: WriterDependencies = {
    createHeaders,
    createConnection: () => connections.shift()!,
    createRepository: () => ({ write }),
    sleep: async () => undefined,
  };
  return {
    writer: new NeptuneGraphWriter(
      {
        endpoint: normalizeNeptuneEndpoint('cluster.example.com'),
        region: 'us-west-2',
        timeoutMs,
        maxAttempts,
      },
      dependencies
    ),
    createHeaders,
  };
}

describe('graph-writer runtime', () => {
  it('reuses an open connection', async () => {
    const connection = new FakeConnection();
    const write = jest.fn().mockResolvedValue({ nodes: 1, edges: 0 });
    const { writer, createHeaders } = createWriter([connection], write);

    await writer.write(event);
    await writer.write(event);

    expect(connection.openCalls).toBe(1);
    expect(createHeaders).toHaveBeenCalledTimes(1);
  });

  it('reconnects after a transient failure', async () => {
    const first = new FakeConnection();
    const second = new FakeConnection();
    const write = jest
      .fn()
      .mockRejectedValueOnce(new Error('WebSocket is not open'))
      .mockResolvedValueOnce({ nodes: 1, edges: 0 });
    const { writer, createHeaders } = createWriter([first, second], write);

    await expect(writer.write(event)).resolves.toEqual({ nodes: 1, edges: 0 });
    expect(first.closeCalls).toBe(1);
    expect(createHeaders).toHaveBeenCalledTimes(2);
  });

  it('times out and closes the connection', async () => {
    jest.useFakeTimers();
    const connection = new FakeConnection();
    const write = jest.fn(async () => new Promise(() => undefined));
    const { writer } = createWriter([connection], write, 1, 25);
    const pending = writer.write(event);
    const rejected = expect(pending).rejects.toThrow('timeout');
    await jest.advanceTimersByTimeAsync(26);
    await rejected;
    expect(connection.closeCalls).toBe(1);
    jest.useRealTimers();
  });

  it('binds the remote connection through traversal().withRemote', () => {
    const graphSource = new Gremlin.structure.Graph().traversal();
    expect(graphSource.withRemote).toBeUndefined();
    expect(Gremlin.process.traversal().withRemote).toEqual(expect.any(Function));

    const source = createRemoteTraversal(new FakeConnection(), 1_000);
    expect(source.V).toEqual(expect.any(Function));
  });

  it('reports skipped edges alongside written elements', async () => {
    const write = jest
      .fn()
      .mockResolvedValue({ nodes: 2, edges: 1, skippedEdges: 3, tombstoned: 0 });

    await expect(createGraphWriterHandler({ write })(event)).resolves.toEqual({
      success: true,
      written: 3,
      skipped: 3,
      tombstoned: 0,
    });
  });

  it('rejects invalid input', async () => {
    await expect(
      createGraphWriterHandler({ write: jest.fn() })({ nodes: [] } as unknown as WriterEvent)
    ).rejects.toThrow('nodes and edges arrays');
  });

  it('validates NEPTUNE_MUTATION_CHUNK when building the runtime writer', () => {
    const original = process.env.NEPTUNE_MUTATION_CHUNK;
    process.env.NEPTUNE_MUTATION_CHUNK = 'not-a-number';
    try {
      expect(() => createRuntimeWriter()).toThrow(
        'NEPTUNE_MUTATION_CHUNK must be a positive integer'
      );
    } finally {
      if (original === undefined) delete process.env.NEPTUNE_MUTATION_CHUNK;
      else process.env.NEPTUNE_MUTATION_CHUNK = original;
    }
  });
});
