import Gremlin from 'gremlin';
import {
  buildEdgeUpsert,
  buildEdgeUpsertChunk,
  buildNodeUpsert,
  buildNodeUpsertChunk,
  writtenIds,
  buildReconcileTraversal,
  GraphRepository,
  graphEdgeId,
  isTransientWriteFailure,
  normalizeEdge,
  normalizeNode,
  RECONCILE_BATCH_SIZE,
  retryTransient,
} from '../shared/graph-repository';

function traversalSource(): Gremlin.process.GraphTraversalSource {
  return new Gremlin.process.GraphTraversalSource(
    new Gremlin.structure.Graph(),
    new Gremlin.process.TraversalStrategies(),
    new Gremlin.process.Bytecode()
  );
}

type Bytecode = { stepInstructions: unknown[][] };

function encode(traversal: Gremlin.process.GraphTraversal): {
  bytecode: Bytecode;
  encoded: string;
} {
  const bytecode = traversal.getBytecode() as unknown as Bytecode;
  return { bytecode, encoded: JSON.stringify(bytecode) };
}

describe('GraphRepository mutations', () => {
  it('upserts vertices by ARN id with stale-event protection and single-cardinality updates', () => {
    const mutation = normalizeNode(
      {
        id: 'arn:aws:s3:::bucket/with-quotes\'"',
        label: 'S3Bucket',
        properties: { name: 'bucket', tags: { owner: 'security' } },
        observedAt: '2026-09-10T01:02:03Z',
      },
      '2026-09-10T00:00:00Z'
    );

    const { bytecode, encoded } = encode(buildNodeUpsert(traversalSource(), mutation));

    expect(bytecode.stepInstructions.slice(0, 2)).toEqual([
      ['V', 'arn:aws:s3:::bucket/with-quotes\'"'],
      ['fold'],
    ]);
    // The create branch pins T.id to the ARN so later lookups are id steps.
    expect(encoded).toContain('"typeName":"T","elementName":"id"');
    expect(encoded).not.toContain('["has","arn"');
    expect(encoded).toContain('coalesce');
    expect(encoded).toContain('source_updated_at');
    expect(encoded).toContain('2026-09-10T01:02:03.000Z');
    expect(encoded).toContain('Cardinality');
    expect(encoded).toContain('{\\"owner\\":\\"security\\"}');
  });

  it('clears listed properties only when refreshing an existing vertex', () => {
    const mutation = normalizeNode(
      {
        id: 'arn:aws:ec2:us-west-2:111122223333:instance/i-1',
        label: 'Ec2Instance',
        properties: { state: 'running' },
        clearProperties: ['public_ip', 'env', 'env'],
        observedAt: '2026-09-10T01:00:00Z',
      },
      '2026-09-10T00:00:00Z'
    );
    expect(mutation.clearProperties).toEqual(['env', 'public_ip']);

    const { encoded } = encode(buildNodeUpsert(traversalSource(), mutation));
    expect(encoded).toContain('["sideEffect"');
    expect(encoded).toContain('["properties","env","public_ip"],["drop"]');
    // One drop: the refresh branch; a newly created vertex has nothing to clear.
    expect(encoded.split('"drop"').length - 1).toBe(1);
    expect(encoded.indexOf('"sideEffect"')).toBeLessThan(encoded.indexOf('"addV"'));
  });

  it('leaves the upsert unchanged when nothing is cleared', () => {
    const base = {
      id: 'arn:aws:s3:::bucket',
      label: 'S3Bucket',
      properties: { name: 'bucket' },
      observedAt: '2026-09-10T01:00:00Z',
    };
    const plain = normalizeNode(base, '2026-09-10T00:00:00Z');
    const empty = normalizeNode({ ...base, clearProperties: [] }, '2026-09-10T00:00:00Z');
    expect(empty).toEqual(plain);
    expect(encode(buildNodeUpsert(traversalSource(), plain)).encoded).not.toContain('drop');
  });

  it.each([
    [['arn'], 'cannot be cleared'],
    [['collection_run_id'], 'cannot be cleared'],
    [['name'], 'both set and cleared'],
    [[''], 'non-empty strings'],
    [[42], 'non-empty strings'],
  ])('rejects clearProperties %j', (keys, message) => {
    expect(() =>
      normalizeNode(
        {
          id: 'arn:aws:s3:::bucket',
          label: 'S3Bucket',
          properties: { name: 'bucket' },
          clearProperties: keys as string[],
        },
        '2026-09-10T00:00:00Z'
      )
    ).toThrow(message);
  });

  it('upserts edges by id, resolves endpoints by id, and never sets a cardinality on edge properties', () => {
    const edge = {
      from: 'arn:aws:iam::111122223333:role/source',
      to: 'arn:aws:s3:::target',
      label: 'CAN_READ',
      properties: { permission: 's3:GetObject' },
      observedAt: '2026-09-10T01:00:00Z',
    };
    const mutation = normalizeEdge(edge, '2026-09-10T00:00:00Z');
    const { bytecode, encoded } = encode(buildEdgeUpsert(traversalSource(), mutation));

    expect(mutation.id).toBe(graphEdgeId(edge));
    expect(graphEdgeId(edge)).toBe(graphEdgeId({ ...edge }));
    expect(graphEdgeId({ ...edge, to: 'arn:aws:s3:::other' })).not.toBe(graphEdgeId(edge));
    expect(bytecode.stepInstructions.slice(0, 2)).toEqual([['E', mutation.id], ['fold']]);
    // Neptune rejects property(Cardinality, ...) on edges; the create and refresh
    // branches must both use the two-argument form.
    expect(encoded).not.toContain('Cardinality');
    // Endpoints are id lookups; a mid-traversal has('arn') would scan every vertex.
    expect(encoded).toContain(JSON.stringify(['V', edge.from]));
    expect(encoded).toContain(JSON.stringify(['V', edge.to]));
    expect(encoded).not.toContain('["has","arn"');
    expect(encoded).toContain('addE');
    expect(encoded).toContain('permission');
    expect(encoded).toContain('s3:GetObject');
    expect(encoded).toContain('source_updated_at');
  });

  it('selects only elements the completed run did not touch, most selective filter first', () => {
    const reconcile = {
      scope: 'resource-inventory:us-west-2',
      runId: 'run-2',
      observedAt: '2026-09-10T02:00:00Z',
      accountId: '111122223333',
      region: 'us-west-2',
    };
    const vertices = encode(buildReconcileTraversal(traversalSource(), 'vertices', reconcile));
    const edges = encode(buildReconcileTraversal(traversalSource(), 'edges', reconcile));

    expect(vertices.bytecode.stepInstructions.slice(0, 3)).toEqual([
      ['V'],
      ['has', 'account_id', '111122223333'],
      ['has', 'collection_scope', 'resource-inventory:us-west-2'],
    ]);
    expect(vertices.encoded).toContain('us-west-2');
    expect(vertices.encoded).toContain('run-2');
    expect(vertices.encoded).toContain('2026-09-10T02:00:00.000Z');
    // The repository counts and then drops; the selection itself mutates nothing.
    expect(vertices.encoded).not.toContain('property');
    expect(vertices.encoded).not.toContain('drop');

    expect(edges.bytecode.stepInstructions[0]).toEqual(['E']);
    expect(edges.encoded).not.toContain('property');
  });
});

describe('Chunked upsert builders', () => {
  const node = (id: string) =>
    normalizeNode(
      { id, label: 'S3Bucket', properties: { name: id }, observedAt: '2026-09-10T01:00:00Z' },
      '2026-09-10T00:00:00Z'
    );

  it('chains several vertex upserts into one traversal', () => {
    const chunk = [node('arn:aws:s3:::a'), node('arn:aws:s3:::b'), node('arn:aws:s3:::c')];
    const { bytecode } = encode(buildNodeUpsertChunk(traversalSource(), chunk));

    expect(bytecode.stepInstructions.filter(([step]) => step === 'V')).toHaveLength(3);
    expect(bytecode.stepInstructions.filter(([step]) => step === 'fold')).toHaveLength(3);
    expect(bytecode.stepInstructions.filter(([step]) => step === 'coalesce')).toHaveLength(3);
    for (const mutation of chunk) {
      expect(JSON.stringify(bytecode)).toContain(mutation.id);
    }
  });

  it('chains several edge upserts into one traversal, each resolving endpoints by id', () => {
    const edge = (from: string, to: string) =>
      normalizeEdge(
        { from, to, label: 'GRANTS', properties: {}, observedAt: '2026-09-10T01:00:00Z' },
        '2026-09-10T00:00:00Z'
      );
    const chunk = [
      edge('arn:aws:s3:::a', 'arn:aws:s3:::b'),
      edge('arn:aws:s3:::c', 'arn:aws:s3:::d'),
    ];
    const { bytecode, encoded } = encode(buildEdgeUpsertChunk(traversalSource(), chunk));

    expect(bytecode.stepInstructions.filter(([step]) => step === 'E')).toHaveLength(2);
    expect(encoded).toContain(JSON.stringify(['V', 'arn:aws:s3:::a']));
    expect(encoded).toContain(JSON.stringify(['V', 'arn:aws:s3:::d']));
  });
});

describe('GraphRepository.write', () => {
  function chain(result: { done: boolean; value?: unknown; reject?: Error }): unknown {
    const next = async () => {
      if (result.reject) throw result.reject;
      return result;
    };
    const toList = async () => {
      if (result.reject) throw result.reject;
      return result.done ? [] : [result.value ?? {}];
    };
    const proxy: unknown = new Proxy(
      {},
      {
        get: (_target, property) => {
          if (property === 'next') return next;
          if (property === 'toList') return toList;
          return () => proxy;
        },
      }
    );
    return proxy;
  }

  it('drops stale reconcile elements with next(), never iterate()', async () => {
    // Neptune rejects the `discard` step that the 3.8 driver appends for iterate().
    const steps: string[] = [];
    function recording(results: Array<{ done: boolean; value?: unknown }>): unknown {
      const proxy: unknown = new Proxy(
        {},
        {
          get: (_target, property) => {
            if (property === 'iterate') throw new Error('iterate() encodes discard');
            if (property === 'next') return async () => results.shift() ?? { done: true };
            if (typeof property === 'string') steps.push(property);
            return () => proxy;
          },
        }
      );
      return proxy;
    }
    const graph = {
      V: () => recording([{ done: false, value: 3 }, { done: true }]),
      E: () => recording([{ done: false, value: 0 }]),
    } as unknown as Gremlin.process.GraphTraversalSource;

    const result = await new GraphRepository(graph, 1).write(
      {
        nodes: [],
        edges: [],
        reconcile: {
          scope: 'resource-inventory:us-west-2',
          runId: 'run-2',
          observedAt: '2026-09-10T02:00:00Z',
          accountId: '111122223333',
        },
      },
      '2026-09-10T02:00:00Z'
    );

    expect(result.tombstoned).toBe(3);
    expect(steps.filter((step) => step === 'drop')).toHaveLength(1);
    expect(steps.filter((step) => step === 'count')).toHaveLength(2);
  });

  it('drops stale elements in batches until a batch comes back short', async () => {
    const steps: string[] = [];
    const counts = [RECONCILE_BATCH_SIZE, RECONCILE_BATCH_SIZE, 7];
    function recording(): unknown {
      let counting = false;
      const proxy: unknown = new Proxy(
        {},
        {
          get: (_target, property) => {
            if (property === 'next') {
              return async () =>
                counting ? { done: false, value: counts.shift() ?? 0 } : { done: true };
            }
            if (property === 'count') counting = true;
            if (typeof property === 'string') steps.push(property);
            return () => proxy;
          },
        }
      );
      return proxy;
    }
    const graph = {
      V: () => recording(),
      E: () => recording(),
    } as unknown as Gremlin.process.GraphTraversalSource;

    const result = await new GraphRepository(graph, 1).write(
      {
        nodes: [],
        edges: [],
        reconcile: {
          scope: 'resource-inventory:us-west-2',
          runId: 'run-2',
          observedAt: '2026-09-10T02:00:00Z',
          accountId: '111122223333',
        },
      },
      '2026-09-10T02:00:00Z'
    );

    // Vertices: two full batches and a short one; edges: one empty count.
    expect(result.tombstoned).toBe(2 * RECONCILE_BATCH_SIZE + 7);
    expect(steps.filter((step) => step === 'drop')).toHaveLength(3);
    expect(steps.filter((step) => step === 'count')).toHaveLength(4);
    expect(steps.filter((step) => step === 'limit')).toHaveLength(7);
  });

  it('skips and counts edges whose endpoints are not in the graph', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const graph = {
      // A chunk's cap() yields the ids it wrote: the vertex chunk wrote the
      // bucket; the edge chunk yields nothing readable, so it is isolated.
      V: () => chain({ done: false, value: ['arn:aws:s3:::bucket'] }),
      E: () => chain({ done: true }),
    } as unknown as Gremlin.process.GraphTraversalSource;
    const repository = new GraphRepository(graph, 2);

    const result = await repository.write(
      {
        nodes: [{ id: 'arn:aws:s3:::bucket', label: 'S3Bucket', properties: {} }],
        edges: [
          { from: 'arn:aws:iam::111122223333:role/a', to: 'arn:aws:s3:::bucket', label: 'GRANTS' },
          { from: 'arn:aws:iam::111122223333:role/b', to: 'arn:aws:s3:::missing', label: 'GRANTS' },
        ],
      },
      '2026-09-10T00:00:00Z'
    );

    expect(result).toEqual({ nodes: 1, edges: 0, skippedEdges: 2, tombstoned: 0 });
    // Two warnings: the edge chunk isolated element-by-element, then the skip
    // report. The vertex chunk itself takes the fast chained path.
    expect(warn).toHaveBeenCalledTimes(2);
    expect(JSON.parse(warn.mock.calls[1][0] as string)).toMatchObject({
      message: 'Skipped edges whose endpoints are not in the graph',
      skipped: 2,
      sample: [
        'GRANTS arn:aws:iam::111122223333:role/a -> arn:aws:s3:::bucket',
        expect.any(String),
      ],
    });
    warn.mockRestore();
  });

  it('isolates a failing vertex chunk element-by-element and still writes the rest', async () => {
    let vCalls = 0;
    const graph = {
      // The chained chunk traversal (first V call) fails; the per-element
      // fallback then writes both vertices successfully.
      V: () => {
        vCalls += 1;
        return vCalls === 1
          ? chain({ done: false, reject: new Error('Server error (500)') })
          : chain({ done: false, value: {} });
      },
      E: () => chain({ done: true }),
    } as unknown as Gremlin.process.GraphTraversalSource;

    const result = await new GraphRepository(graph, 1).write(
      {
        nodes: [
          { id: 'arn:aws:s3:::one', label: 'S3Bucket', properties: {} },
          { id: 'arn:aws:s3:::two', label: 'S3Bucket', properties: {} },
        ],
        edges: [],
      },
      '2026-09-10T00:00:00Z'
    );

    expect(result.nodes).toBe(2);
    // One chained chunk traversal, then one round trip per isolated element.
    expect(vCalls).toBe(3);
  });

  it('names the failing element and keeps the Neptune status code', async () => {
    const neptuneError = Object.assign(
      new Error('Server error: {"code":"MemoryLimitExceededException"} (597)'),
      { statusCode: 597 }
    );
    const graph = {
      V: () => chain({ done: false, value: {}, reject: neptuneError }),
      E: () => chain({ done: true }),
    } as unknown as Gremlin.process.GraphTraversalSource;

    // The chained chunk rejects first (non-transient path logs and falls back);
    // the per-element fallback then retries the memory error to exhaustion and
    // rejects with the named element.
    await expect(
      new GraphRepository(graph, 1).write(
        { nodes: [{ id: 'arn:aws:s3:::bucket', label: 'S3Bucket', properties: {} }], edges: [] },
        '2026-09-10T00:00:00Z'
      )
    ).rejects.toMatchObject({
      message: expect.stringMatching(
        /^Graph write failed for vertex S3Bucket arn:aws:s3:::bucket: Server error/
      ),
      statusCode: 597,
    });
  });
});

describe('GraphRepository chunk size', () => {
  it('rejects chunk sizes outside 1..200', () => {
    const graph = {} as Gremlin.process.GraphTraversalSource;
    expect(() => new GraphRepository(graph, 2, 0)).toThrow('chunk size must be between 1 and 200');
    expect(() => new GraphRepository(graph, 2, 201)).toThrow(
      'chunk size must be between 1 and 200'
    );
    expect(() => new GraphRepository(graph, 2, 25)).not.toThrow();
  });
});

describe('Neptune error classification', () => {
  it('retries ConcurrentModificationException and then succeeds', async () => {
    const operation = jest
      .fn()
      .mockRejectedValueOnce(new Error('ConcurrentModificationException: Please retry.'))
      .mockResolvedValueOnce(undefined);

    await expect(retryTransient(operation, 4, async () => undefined)).resolves.toBeUndefined();
    expect(operation).toHaveBeenCalledTimes(2);
  });

  it('retries a ConstraintViolationException from a concurrent create of the same id', async () => {
    const operation = jest
      .fn()
      .mockRejectedValueOnce(
        new Error(
          'Server error: {"code":"ConstraintViolationException","message":"Vertex with id already exists"} (500)'
        )
      )
      .mockResolvedValueOnce(undefined);

    await expect(retryTransient(operation, 4, async () => undefined)).resolves.toBeUndefined();
    expect(operation).toHaveBeenCalledTimes(2);
  });

  it('retries MemoryLimitExceededException per element until the attempts run out', async () => {
    const memory = new Error(
      'Server error: {"code":"MemoryLimitExceededException","message":"Query cannot be completed due to memory limitations."} (597)'
    );
    const recovers = jest.fn().mockRejectedValueOnce(memory).mockResolvedValueOnce(undefined);
    await expect(retryTransient(recovers, 6, async () => undefined)).resolves.toBeUndefined();
    expect(recovers).toHaveBeenCalledTimes(2);

    const persistent = jest.fn().mockRejectedValue(memory);
    await expect(retryTransient(persistent, 3, async () => undefined)).rejects.toThrow(
      'MemoryLimitExceededException'
    );
    expect(persistent).toHaveBeenCalledTimes(3);
  });

  it('does not retry permanent write failures', async () => {
    const operation = jest
      .fn()
      .mockRejectedValue(new Error('Property cardinality can only be set for a Vertex'));

    await expect(retryTransient(operation, 4, async () => undefined)).rejects.toThrow(
      'cardinality'
    );
    expect(operation).toHaveBeenCalledTimes(1);
    expect(isTransientWriteFailure(new Error('InternalFailureException'))).toBe(false);
  });
});

describe('writtenIds', () => {
  it('reads the id list cap() yields, as an array or a set', () => {
    expect(writtenIds([['a', 'b']])).toEqual(new Set(['a', 'b']));
    expect(writtenIds([new Set(['a'])])).toEqual(new Set(['a']));
    expect(writtenIds([[]])).toEqual(new Set());
  });

  it('is undefined for anything but a single list', () => {
    expect(writtenIds([])).toBeUndefined();
    expect(writtenIds([['a'], ['b']])).toBeUndefined();
    expect(writtenIds([{}])).toBeUndefined();
  });
});
