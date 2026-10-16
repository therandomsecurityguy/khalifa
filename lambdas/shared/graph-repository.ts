import { createHash } from 'crypto';
import Gremlin from 'gremlin';
import type { GraphNode, GraphEdge, GraphReconcile } from './types';
import { Logger } from './types';

// Vertex ids are the resource ARN and edge ids are the deterministic
// `khalifa_edge_id`. Every lookup, including the edge create branch, is an id
// step: Neptune's TinkerPop engine only serves property lookups from the index
// at the start of a traversal, so a mid-traversal `V().has('arn', …)` scans the
// whole vertex set.
const { single } = Gremlin.process.cardinality;
const { lt, neq } = Gremlin.process.P;
const { t } = Gremlin.process;
const __ = Gremlin.process.statics;

const logger = new Logger('graph-repository');
const SKIPPED_EDGE_SAMPLE = 5;

type TraversalSource = Gremlin.process.GraphTraversalSource;
type AnonymousTraversal = Gremlin.process.GraphTraversal;
type ElementKind = 'vertex' | 'edge';

// @types/gremlin omits the mid-traversal E() step (E is only declared as a
// start step on the traversal source); the runtime encodes it as a GraphStep
// exactly like V(), verified against the driver bytecode.
type GraphTraversalWithEdgeStep = Gremlin.process.GraphTraversal & {
  E(...ids: unknown[]): Gremlin.process.GraphTraversal;
};

export interface GraphWriteResult {
  nodes: number;
  edges: number;
  skippedEdges: number;
  tombstoned: number;
}

interface NormalizedMutation {
  id: string;
  label: string;
  properties: Record<string, string | number | boolean>;
  observedAt: string;
}

interface NormalizedEdgeMutation extends NormalizedMutation {
  from: string;
  to: string;
}

const MUTATION_CHUNK_MAX_BYTES = 512 * 1024;

export class GraphRepository {
  constructor(
    private readonly graph: TraversalSource,
    private readonly maxConcurrency: number = 2,
    private readonly chunkSize: number = 25
  ) {
    if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1 || maxConcurrency > 32) {
      throw new Error('Graph write concurrency must be between 1 and 32');
    }
    if (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > 200) {
      throw new Error('Graph write chunk size must be between 1 and 200');
    }
  }

  async write(
    mutations: { nodes: GraphNode[]; edges: GraphEdge[]; reconcile?: GraphReconcile },
    observedAt: string = new Date().toISOString()
  ): Promise<GraphWriteResult> {
    const normalizedObservedAt = normalizeTimestamp(observedAt);
    const nodes = mutations.nodes.map((node) => normalizeNode(node, normalizedObservedAt));
    const edges = mutations.edges.map((edge) => normalizeEdge(edge, normalizedObservedAt));

    // One chained traversal per chunk instead of one round trip per element:
    // a 4 MB batch used to cost tens of thousands of websocket round trips at
    // maxConcurrency 2, which could not finish inside the write timeout.
    await this.runChunks(nodes, async (chunk: NormalizedMutation[]) => {
      try {
        await retryTransient(async () => {
          const results = await buildNodeUpsertChunk(this.graph, chunk).toList();
          // Each single-element upsert yields exactly one traverser (the
          // refreshed or newly created vertex); fewer means Neptune silently
          // dropped part of the chain, which is re-run element by element.
          if (results.length !== chunk.length) {
            throw new Error(`Vertex chunk returned ${results.length} of ${chunk.length} elements`);
          }
        });
      } catch (error) {
        logger.warn('Vertex chunk write failed; retrying element-by-element', {
          size: chunk.length,
          error: error instanceof Error ? error.message : String(error),
        });
        await runBounded(chunk, this.maxConcurrency, async (node) => {
          try {
            await retryTransient(async () => {
              const result = await buildNodeUpsert(this.graph, node).next();
              if (result.done) throw new Error('Neptune returned no vertex');
            });
          } catch (e) {
            throw describeFailure(`vertex ${node.label} ${node.id}`, e);
          }
        });
      }
    });

    // An edge whose endpoint is not in the graph (a resource in another account,
    // an AWS-managed principal, an object ARN) produces no traverser. Those are
    // skipped and counted rather than failing the batch.
    const skipped: NormalizedEdgeMutation[] = [];
    await this.runChunks(edges, async (chunk: NormalizedEdgeMutation[]) => {
      try {
        const results = await buildEdgeUpsertChunk(this.graph, chunk).toList();
        if (results.length === chunk.length) return;
        logger.warn('Edge chunk returned fewer traversers than mutations; isolating', {
          size: chunk.length,
          results: results.length,
        });
        await this.isolateEdgeChunk(chunk, skipped);
      } catch (error) {
        logger.warn('Edge chunk write failed; retrying element-by-element', {
          size: chunk.length,
          error: error instanceof Error ? error.message : String(error),
        });
        await this.isolateEdgeChunk(chunk, skipped);
      }
    });
    if (skipped.length > 0) {
      logger.warn('Skipped edges whose endpoints are not in the graph', {
        skipped: skipped.length,
        sample: skipped
          .slice(0, SKIPPED_EDGE_SAMPLE)
          .map((edge) => `${edge.label} ${edge.from} -> ${edge.to}`),
      });
    }

    // Reconcile removes what the completed run no longer saw. Dropping a vertex
    // also drops its edges; the edge pass then removes edges whose endpoints
    // survived but which the run did not re-emit.
    let tombstoned = 0;
    if (mutations.reconcile) {
      const reconcile = mutations.reconcile;
      for (const element of ['vertices', 'edges'] as const) {
        let stale = 0;
        await retryTransient(async () => {
          const counted = await buildReconcileTraversal(this.graph, element, reconcile)
            .count()
            .next();
          stale = resultCount(counted.value);
          if (stale > 0) {
            // next(), not iterate(): the 3.8 driver encodes iterate() as a
            // `discard` step, which Neptune's TinkerPop 3.7 engine rejects with
            // InvalidParameterException ("Unable to find Traversal steps for the
            // graph operator: discard").
            await buildReconcileTraversal(this.graph, element, reconcile).drop().next();
          }
        });
        tombstoned += stale;
      }
    }

    return {
      nodes: nodes.length,
      edges: edges.length - skipped.length,
      skippedEdges: skipped.length,
      tombstoned,
    };
  }

  private async isolateEdgeChunk(
    chunk: NormalizedEdgeMutation[],
    into: NormalizedEdgeMutation[]
  ): Promise<void> {
    // Element-by-element isolation after a chunk failure: idempotent upserts
    // make the retry safe, and the error names the failing element.
    await runBounded(chunk, 1, async (edge) => {
      try {
        await retryTransient(async () => {
          const result = await buildEdgeUpsert(this.graph, edge).next();
          if (result.done) into.push(edge);
        });
      } catch (e) {
        throw describeFailure(`edge ${edge.label} ${edge.from} -> ${edge.to}`, e);
      }
    });
  }

  // Splits by element count and by the serialized size of the mutations: a
  // single document-heavy vertex (IAM policy documents) must not balloon the
  // chunk bytecode past what one round trip can carry.
  private chunkElements<T extends NormalizedMutation>(elements: T[]): T[][] {
    const chunks: T[][] = [];
    let current: T[] = [];
    let bytes = 0;
    for (const element of elements) {
      const elementBytes = Buffer.byteLength(JSON.stringify(element));
      if (
        current.length > 0 &&
        (current.length >= this.chunkSize || bytes + elementBytes > MUTATION_CHUNK_MAX_BYTES)
      ) {
        chunks.push(current);
        current = [];
        bytes = 0;
      }
      current.push(element);
      bytes += elementBytes;
    }
    if (current.length > 0) chunks.push(current);
    return chunks;
  }

  private runChunks<T extends NormalizedMutation>(
    elements: T[],
    operation: (chunk: T[]) => Promise<void>
  ): Promise<void> {
    return runBounded(this.chunkElements(elements), this.maxConcurrency, operation);
  }
}

// Selects the elements in a reconcile scope (and account / Region when given)
// that the completed run did not touch: a different run id and an older
// observation. The run re-wrote everything it saw, so what matches no longer
// exists in AWS. Equality filters lead, most selective first, because Neptune
// serves the first one from the index and applies the rest as filters.
export function buildReconcileTraversal(
  graph: TraversalSource,
  element: 'vertices' | 'edges',
  reconcile: GraphReconcile
): Gremlin.process.GraphTraversal {
  validateIdentity(reconcile.scope, 'reconcile scope');
  validateIdentity(reconcile.runId, 'reconcile run ID');
  const observedAt = normalizeTimestamp(reconcile.observedAt);
  let traversal = element === 'vertices' ? graph.V() : graph.E();
  if (reconcile.accountId) traversal = traversal.has('account_id', reconcile.accountId);
  traversal = traversal.has('collection_scope', reconcile.scope);
  if (reconcile.region) traversal = traversal.has('collection_region', reconcile.region);
  return traversal
    .has('collection_run_id', neq(reconcile.runId))
    .has('source_updated_at', lt(observedAt));
}

export function graphEdgeId(edge: Pick<GraphEdge, 'from' | 'to' | 'label'>): string {
  return `edge-${createHash('sha256')
    .update(`${edge.label}\0${edge.from}\0${edge.to}`)
    .digest('hex')}`;
}

export function normalizeNode(node: GraphNode, defaultObservedAt: string): NormalizedMutation {
  validateIdentity(node.id, 'node id');
  validateLabel(node.label);

  return {
    id: node.id,
    label: node.label,
    properties: normalizeProperties({ ...node.properties, arn: node.id }),
    observedAt: normalizeTimestamp(node.observedAt || defaultObservedAt),
  };
}

export function normalizeEdge(edge: GraphEdge, defaultObservedAt: string): NormalizedEdgeMutation {
  validateIdentity(edge.from, 'edge source');
  validateIdentity(edge.to, 'edge target');
  validateLabel(edge.label);

  return {
    id: graphEdgeId(edge),
    from: edge.from,
    to: edge.to,
    label: edge.label,
    properties: normalizeProperties({ ...edge.properties, khalifa_edge_id: graphEdgeId(edge) }),
    observedAt: normalizeTimestamp(edge.observedAt || defaultObservedAt),
  };
}

export function buildNodeUpsert(
  graph: TraversalSource,
  mutation: NormalizedMutation
): Gremlin.process.GraphTraversal {
  return graph
    .V(mutation.id)
    .fold()
    .coalesce(
      __.unfold().choose(
        versionPredicate(mutation.observedAt),
        applyProperties(__.identity(), mutation, 'vertex'),
        __.identity()
      ),
      applyProperties(__.addV(mutation.label).property(t.id, mutation.id), mutation, 'vertex')
    );
}

// Chains N single-element upserts into ONE traversal: each appended
// `V(id)` / `E(id)` is a graph step that restarts from the index, so the
// chain is N id lookups in a single round trip instead of N round trips.
// Every single-element upsert yields exactly one traverser (the refreshed or
// newly created element, nothing when an edge endpoint is missing), so the
// result count validates the chain.
export function buildNodeUpsertChunk(
  graph: TraversalSource,
  chunk: NormalizedMutation[]
): Gremlin.process.GraphTraversal {
  if (chunk.length === 0) throw new Error('Vertex chunk must not be empty');
  let traversal = buildNodeUpsert(graph, chunk[0]);
  for (let index = 1; index < chunk.length; index++) {
    traversal = appendNodeUpsert(traversal, chunk[index]);
  }
  return traversal;
}

function appendNodeUpsert(
  traversal: AnonymousTraversal,
  mutation: NormalizedMutation
): Gremlin.process.GraphTraversal {
  return traversal
    .V(mutation.id)
    .fold()
    .coalesce(
      __.unfold().choose(
        versionPredicate(mutation.observedAt),
        applyProperties(__.identity(), mutation, 'vertex'),
        __.identity()
      ),
      applyProperties(__.addV(mutation.label).property(t.id, mutation.id), mutation, 'vertex')
    );
}

export function buildEdgeUpsertChunk(
  graph: TraversalSource,
  chunk: NormalizedEdgeMutation[]
): Gremlin.process.GraphTraversal {
  if (chunk.length === 0) throw new Error('Edge chunk must not be empty');
  let traversal = buildEdgeUpsert(graph, chunk[0]);
  for (let index = 1; index < chunk.length; index++) {
    traversal = appendEdgeUpsert(traversal, chunk[index]);
  }
  return traversal;
}

function appendEdgeUpsert(
  traversal: AnonymousTraversal,
  mutation: NormalizedEdgeMutation
): Gremlin.process.GraphTraversal {
  return (traversal as GraphTraversalWithEdgeStep)
    .E(mutation.id)
    .fold()
    .coalesce(
      __.unfold().choose(
        versionPredicate(mutation.observedAt),
        applyProperties(__.identity(), mutation, 'edge'),
        __.identity()
      ),
      applyProperties(
        __.V(mutation.from)
          .as('source')
          .V(mutation.to)
          .addE(mutation.label)
          .from_('source')
          .property(t.id, mutation.id),
        mutation,
        'edge'
      )
    );
}

export function buildEdgeUpsert(
  graph: TraversalSource,
  mutation: NormalizedEdgeMutation
): Gremlin.process.GraphTraversal {
  return graph
    .E(mutation.id)
    .fold()
    .coalesce(
      __.unfold().choose(
        versionPredicate(mutation.observedAt),
        applyProperties(__.identity(), mutation, 'edge'),
        __.identity()
      ),
      applyProperties(
        __.V(mutation.from)
          .as('source')
          .V(mutation.to)
          .addE(mutation.label)
          .from_('source')
          .property(t.id, mutation.id),
        mutation,
        'edge'
      )
    );
}

function versionPredicate(observedAt: string): AnonymousTraversal {
  return __.coalesce(__.values('source_updated_at'), __.constant('')).is(lt(observedAt));
}

// Neptune rejects a cardinality token on edge properties ("Property cardinality
// can only be set for a Vertex"); edge properties are implicitly single.
function setProperty(
  traversal: AnonymousTraversal,
  element: ElementKind,
  key: string,
  value: string | number | boolean
): AnonymousTraversal {
  return element === 'vertex'
    ? traversal.property(single, key, value)
    : traversal.property(key, value);
}

function applyProperties(
  traversal: AnonymousTraversal,
  mutation: NormalizedMutation,
  element: ElementKind
): AnonymousTraversal {
  let result = traversal;
  for (const [key, value] of Object.entries(mutation.properties)) {
    result = setProperty(result, element, key, value);
  }

  return setProperty(result, element, 'source_updated_at', mutation.observedAt);
}

function normalizeProperties(
  properties: Record<string, unknown>
): Record<string, string | number | boolean> {
  const normalized: Record<string, string | number | boolean> = {};

  for (const [key, value] of Object.entries(properties)) {
    if (!key || value === undefined || value === null) continue;
    if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        throw new Error(`Graph property ${key} must be a finite number`);
      }
      normalized[key] = value;
      continue;
    }
    if (typeof value === 'string' || typeof value === 'boolean') {
      normalized[key] = value;
      continue;
    }
    normalized[key] = JSON.stringify(value);
  }

  return normalized;
}

function normalizeTimestamp(value: string): string {
  const timestamp = new Date(value);
  if (!value || Number.isNaN(timestamp.getTime())) {
    throw new Error(`Invalid graph observation timestamp: ${value}`);
  }
  return timestamp.toISOString();
}

function resultCount(value: unknown): number {
  if (typeof value === 'number') return value;
  if (typeof value === 'bigint') return Number(value);
  if (value && typeof value === 'object' && 'toNumber' in value) {
    return (value as { toNumber: () => number }).toNumber();
  }
  throw new Error('Neptune returned an invalid reconciliation count');
}

function validateIdentity(value: string, name: string): void {
  if (!value.trim()) throw new Error(`Graph ${name} must not be empty`);
}

// Names the element so the failing mutation can be found in the graph-writer
// log, while keeping the Neptune message and status code for classification.
function describeFailure(element: string, error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  const failure = new Error(`Graph write failed for ${element}: ${message}`) as Error & {
    cause?: unknown;
    statusCode?: unknown;
  };
  failure.cause = error;
  const statusCode = (error as { statusCode?: unknown } | null)?.statusCode;
  if (statusCode !== undefined) failure.statusCode = statusCode;
  return failure;
}

function validateLabel(value: string): void {
  if (!value.trim() || value.includes('::')) {
    throw new Error(`Invalid graph label: ${value}`);
  }
}

const TRANSIENT_ATTEMPTS = 6;

function errorText(error: unknown): string {
  return `${error instanceof Error ? error.message : String(error)}`.toLowerCase();
}

// Failures that clear on their own: a concurrent writer raced the same vertex
// (ConcurrentModification) or created the same id first (ConstraintViolation),
// or Neptune Serverless ran a write out of query memory while other writes were
// in flight (MemoryLimitExceeded). Measured in production, the identical write
// succeeds on the next attempt, so each element is retried before the batch
// is failed.
export function isTransientWriteFailure(error: unknown): boolean {
  const text = errorText(error);
  return (
    text.includes('concurrentmodificationexception') ||
    text.includes('constraintviolationexception') ||
    text.includes('memorylimitexceededexception')
  );
}

export async function retryTransient(
  operation: () => Promise<void>,
  attempts: number = TRANSIENT_ATTEMPTS,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((resolve) => setTimeout(resolve, ms))
): Promise<void> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await operation();
      return;
    } catch (error) {
      lastError = error;
      if (!isTransientWriteFailure(error) || attempt === attempts) throw error;
      await sleep(50 * 2 ** (attempt - 1));
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

async function runBounded<T>(
  items: T[],
  concurrency: number,
  operation: (item: T) => Promise<void>
): Promise<void> {
  let cursor = 0;
  let failed = false;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (cursor < items.length && !failed) {
      const index = cursor++;
      try {
        await operation(items[index]);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  });
  await Promise.all(workers);
}
