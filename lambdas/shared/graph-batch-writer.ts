import type { GraphEdge, GraphNode, GraphReconcile } from './types';
import { invokeGraphWriter } from './graph-writer-client';

export interface GraphMutationBatch {
  nodes: GraphNode[];
  edges: GraphEdge[];
  observedAt: string;
  reconcile?: GraphReconcile;
}

export type GraphWriter = (
  batch: GraphMutationBatch
) => Promise<{ success: true; written: number; skipped?: number; tombstoned?: number }>;

interface BatchWriterOptions {
  maxBytes?: number;
  write?: GraphWriter;
}

const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;

function payloadBytes(batch: GraphMutationBatch): number {
  return Buffer.byteLength(JSON.stringify(batch));
}

function appendBatches<T extends GraphNode | GraphEdge>(
  items: T[],
  key: 'nodes' | 'edges',
  observedAt: string,
  maxBytes: number,
  batches: GraphMutationBatch[]
): void {
  let batch: GraphMutationBatch = { nodes: [], edges: [], observedAt };
  let bytes = payloadBytes(batch);

  for (const item of items) {
    const itemBytes = Buffer.byteLength(JSON.stringify(item));
    const target = batch[key] as T[];
    if (bytes + itemBytes + (target.length > 0 ? 1 : 0) > maxBytes) {
      if (target.length === 0) throw new Error(`A graph ${key.slice(0, -1)} exceeds maxBytes`);
      batches.push(batch);
      batch = { nodes: [], edges: [], observedAt };
      bytes = payloadBytes(batch);
    }
    (batch[key] as T[]).push(item);
    bytes += itemBytes + (batch[key].length > 1 ? 1 : 0);
  }

  if (batch[key].length > 0) batches.push(batch);
}

export function createGraphBatches(
  nodes: GraphNode[],
  edges: GraphEdge[],
  observedAt: string,
  maxBytes = DEFAULT_MAX_BYTES
): GraphMutationBatch[] {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error('maxBytes must be a positive integer');
  }

  const batches: GraphMutationBatch[] = [];
  appendBatches(nodes, 'nodes', observedAt, maxBytes, batches);
  appendBatches(edges, 'edges', observedAt, maxBytes, batches);
  return batches;
}

export async function writeGraphInBatches(
  graph: { nodes: GraphNode[]; edges: GraphEdge[]; reconcile?: GraphReconcile },
  observedAt: string,
  options: BatchWriterOptions = {}
): Promise<{ written: number; skipped: number; tombstoned: number; batches: number }> {
  const write: GraphWriter = options.write || invokeGraphWriter;
  const batches = createGraphBatches(
    graph.nodes,
    graph.edges,
    observedAt,
    options.maxBytes ?? DEFAULT_MAX_BYTES
  );
  let written = 0;
  let skipped = 0;
  let tombstoned = 0;
  for (const batch of batches) {
    const result = await write(batch);
    written += result.written;
    skipped += result.skipped || 0;
  }
  if (graph.reconcile) {
    tombstoned =
      (await write({ nodes: [], edges: [], observedAt, reconcile: graph.reconcile })).tombstoned ||
      0;
  }
  return { written, skipped, tombstoned, batches: batches.length + (graph.reconcile ? 1 : 0) };
}
