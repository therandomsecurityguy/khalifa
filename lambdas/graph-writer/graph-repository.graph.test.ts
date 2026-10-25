import Gremlin from 'gremlin';
import { GraphRepository } from '../shared/graph-repository';
import type { GraphNode } from '../shared/types';

// Reconcile against a throwaway local Gremlin Server (CI only).
const endpoint = process.env.GREMLIN_TEST_ENDPOINT ?? '';
if (!/^ws:\/\/(127\.0\.0\.1|localhost):\d+\/gremlin$/.test(endpoint)) {
  throw new Error('GREMLIN_TEST_ENDPOINT must be a local ws://127.0.0.1:<port>/gremlin');
}

const connection = new Gremlin.driver.DriverRemoteConnection(endpoint, { traversalSource: 'g' });
const g = Gremlin.process.traversal().withRemote(connection);
const scope = 'resource-inventory:us-west-2';
const account = '111122223333';

function node(id: string, runId: string, props: Record<string, string> = {}): GraphNode {
  return {
    id,
    label: 'ContainerImage',
    properties: {
      account_id: account,
      collection_scope: scope,
      collection_region: 'us-west-2',
      collection_run_id: runId,
      ...props,
    },
  };
}

const ids = async () => (await g.V().id().toList()).map(String).sort();

beforeEach(async () => {
  await g.V().drop().next();
});
afterAll(() => connection.close());

describe('reconcile against a Gremlin Server', () => {
  it('drops every stale element across several batches and nothing else', async () => {
    // Batch size 5: twelve stale vertices take three batches.
    const repository = new GraphRepository(g, 1, 25, 5);
    const stale = Array.from({ length: 12 }, (_, index) => node(`stale-${index}`, 'run-1'));
    await repository.write(
      {
        nodes: [
          ...stale,
          node('kept', 'run-1'),
          node('other-account', 'run-1', { account_id: '999999999999' }),
          node('other-scope', 'run-1', { collection_scope: 'iam:global' }),
        ],
        edges: [{ from: 'stale-0', to: 'kept', label: 'BELONGS_TO' }],
      },
      '2026-10-19T00:00:00.000Z'
    );

    const result = await repository.write(
      {
        nodes: [node('kept', 'run-2')],
        edges: [],
        reconcile: {
          scope,
          runId: 'run-2',
          observedAt: '2026-10-19T04:00:00.000Z',
          accountId: account,
          region: 'us-west-2',
        },
      },
      '2026-10-19T04:00:00.000Z'
    );

    expect(result.tombstoned).toBe(12);
    expect(await ids()).toEqual(['kept', 'other-account', 'other-scope']);
    expect(await g.E().count().next()).toMatchObject({ value: 0 });
  });
});

describe('clearing properties against a Gremlin Server', () => {
  const instance = 'arn:aws:ec2:us-west-2:111122223333:instance/i-1';
  const props = async () => (await g.V(instance).valueMap().next()).value as Map<string, unknown[]>;

  it('drops cleared keys on a newer write and keeps every other property', async () => {
    const repository = new GraphRepository(g, 1);
    await repository.write(
      {
        nodes: [
          node(instance, 'run-1', { env: 'prod', public_ip: '203.0.113.7', state: 'running' }),
        ],
        edges: [],
      },
      '2026-10-19T00:00:00.000Z'
    );
    // Another writer's property, as the policy evaluator sets is_admin.
    await g.V(instance).property(Gremlin.process.cardinality.single, 'is_admin', true).next();

    await repository.write(
      {
        nodes: [
          {
            ...node(instance, 'run-2', { state: 'running' }),
            clearProperties: ['env', 'public_ip'],
          },
        ],
        edges: [],
      },
      '2026-10-19T04:00:00.000Z'
    );

    const after = await props();
    expect(after.has('env')).toBe(false);
    expect(after.has('public_ip')).toBe(false);
    expect(after.get('state')).toEqual(['running']);
    expect(after.get('is_admin')).toEqual([true]);
  });

  it('ignores clearProperties on an older write', async () => {
    const repository = new GraphRepository(g, 1);
    await repository.write(
      { nodes: [node(instance, 'run-2', { env: 'prod' })], edges: [] },
      '2026-10-19T04:00:00.000Z'
    );
    await repository.write(
      { nodes: [{ ...node(instance, 'run-1'), clearProperties: ['env'] }], edges: [] },
      '2026-10-19T00:00:00.000Z'
    );
    expect((await props()).get('env')).toEqual(['prod']);
  });
});

describe('chunked writes against a Gremlin Server', () => {
  // The upserts in a chunk are chained, so a complete chunk yields one
  // traverser. Every chunk used to be rejected for not yielding one per element
  // and written a second time, element by element.
  const fallbacks = () =>
    warn.mock.calls.filter(([line]) => /retrying element-by-element|isolating/.test(String(line)))
      .length;
  let warn: jest.SpyInstance;
  beforeEach(() => {
    warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  });
  afterEach(() => warn.mockRestore());

  const edgesFor = (count: number) =>
    Array.from({ length: count - 1 }, (_, index) => ({
      from: `chunk-${index}`,
      to: `chunk-${index + 1}`,
      label: 'BELONGS_TO',
    }));

  it('writes several full chunks in one pass, with no element-by-element fallback', async () => {
    const repository = new GraphRepository(g, 2, 25, 5);
    const nodes = Array.from({ length: 60 }, (_, index) => node(`chunk-${index}`, 'run-1'));

    const result = await repository.write({ nodes, edges: edgesFor(60) });

    expect(fallbacks()).toBe(0);
    expect(result).toMatchObject({ nodes: 60, edges: 59, skippedEdges: 0 });
    expect(await g.V().count().next()).toMatchObject({ value: 60 });
    expect(await g.E().count().next()).toMatchObject({ value: 59 });
  });

  it('updates existing elements in one pass on a newer write', async () => {
    const repository = new GraphRepository(g, 2, 25, 5);
    const nodes = (runId: string) =>
      Array.from({ length: 30 }, (_, index) => node(`chunk-${index}`, runId, { name: runId }));
    await repository.write(
      { nodes: nodes('run-1'), edges: edgesFor(30) },
      '2026-10-19T00:00:00.000Z'
    );
    warn.mockClear();

    await repository.write(
      { nodes: nodes('run-2'), edges: edgesFor(30) },
      '2026-10-19T04:00:00.000Z'
    );

    expect(fallbacks()).toBe(0);
    expect(await g.V().has('name', 'run-2').count().next()).toMatchObject({ value: 30 });
    expect(await g.E().count().next()).toMatchObject({ value: 29 });
  });

  it('writes the rest of an edge chunk and counts the edge whose endpoint is missing', async () => {
    const repository = new GraphRepository(g, 2, 25, 5);
    const nodes = Array.from({ length: 10 }, (_, index) => node(`chunk-${index}`, 'run-1'));
    const edges = edgesFor(10);
    // Mid-chunk: the chain stops here, so the edges after it need the fallback.
    edges.splice(4, 0, { from: 'chunk-0', to: 'not-in-graph', label: 'BELONGS_TO' });

    const result = await repository.write({ nodes, edges });

    expect(result.skippedEdges).toBe(1);
    expect(await g.E().count().next()).toMatchObject({ value: 9 });
  });
});
