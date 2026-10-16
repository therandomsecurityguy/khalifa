import { createGraphBatches, writeGraphInBatches } from '../../shared/graph-batch-writer';

describe('graph batch writer', () => {
  const nodes = [
    { id: 'node-1', label: 'Resource', properties: { value: 'a'.repeat(40) } },
    { id: 'node-2', label: 'Resource', properties: { value: 'b'.repeat(40) } },
  ];
  const edges = [{ from: 'node-1', to: 'node-2', label: 'CONNECTS' }];

  it('writes nodes before edges in bounded payloads', async () => {
    const observedAt = '2026-09-10T20:00:00.000Z';
    const maxBytes = Buffer.byteLength(
      JSON.stringify({ nodes: [nodes[0]], edges: [], observedAt })
    );
    const batches = createGraphBatches(nodes, edges, observedAt, maxBytes);

    expect(batches).toHaveLength(3);
    expect(batches.slice(0, 2).every((batch) => batch.nodes.length === 1)).toBe(true);
    expect(batches[2]).toEqual({ nodes: [], edges, observedAt });
    expect(batches.every((batch) => Buffer.byteLength(JSON.stringify(batch)) <= maxBytes)).toBe(
      true
    );
  });

  it('fails when a single mutation cannot fit', () => {
    expect(() => createGraphBatches(nodes, [], '2026-09-10T20:00:00.000Z', 20)).toThrow(
      'A graph node exceeds maxBytes'
    );
  });

  it('propagates writer failures without sending later batches', async () => {
    const write = jest.fn().mockRejectedValue(new Error('write failed'));

    await expect(
      writeGraphInBatches({ nodes, edges }, '2026-09-10T20:00:00.000Z', {
        maxBytes: 200,
        write,
      })
    ).rejects.toThrow('write failed');
    expect(write).toHaveBeenCalledTimes(1);
  });

  it('reconciles only after every mutation batch is written', async () => {
    const write = jest.fn().mockResolvedValue({ success: true, written: 1 });
    const reconcile = {
      scope: 'resource-inventory:us-west-2',
      runId: 'run-2',
      observedAt: '2026-09-10T20:00:00.000Z',
    };

    await writeGraphInBatches({ nodes, edges, reconcile }, reconcile.observedAt, { write });

    expect(write).toHaveBeenLastCalledWith({
      nodes: [],
      edges: [],
      observedAt: reconcile.observedAt,
      reconcile,
    });
  });
});
