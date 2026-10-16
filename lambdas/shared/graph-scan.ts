import type Gremlin from 'gremlin';
import { appendAll } from './arrays';
import { Logger } from './types';

const logger = new Logger('graph-scan');

interface GraphResultSet {
  toArray(): unknown[];
}

/**
 * Minimal view of the raw Gremlin driver client used by the CIEM lambdas.
 * Typed structurally so this helper does not need the gremlin implementation.
 *
 * No bindings: Amazon Neptune rejects Gremlin script bindings ("Bindings in
 * Gremlin are not supported"), so callers submit a script or a Bytecode
 * traversal, never parameters.
 */
export interface GraphSubmitter {
  submit(query: string | Gremlin.process.Bytecode): Promise<unknown>;
}

export interface EnumerateOptions {
  /** Name used in logs when the cap is hit. */
  label: string;
  pageSize?: number;
  maxItems?: number;
}

const DEFAULT_PAGE_SIZE = 1_000;
const DEFAULT_MAX_ITEMS = 50_000;

/**
 * Drains a whole-label traversal in bounded pages with `range(low, high)`.
 *
 * The CIEM lambdas used to materialize every principal, trust edge, and
 * effective-permission vertex in one unbounded `submit`, which OOMs or times
 * out on a large organization. Pages keep peak memory bounded and the cap
 * makes the worst case explicit instead of silent.
 *
 * Page boundaries are not a snapshot: a concurrent writer can shift the
 * result set between pages. These enumerations feed derived evaluation output,
 * so a rare re-evaluation is acceptable and cheaper than the alternative.
 */
export async function enumerateGraph(
  client: GraphSubmitter,
  buildQuery: (start: number, end: number) => string,
  options: EnumerateOptions
): Promise<unknown[]> {
  const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE;
  const maxItems = options.maxItems ?? DEFAULT_MAX_ITEMS;
  if (!Number.isSafeInteger(pageSize) || pageSize < 1) {
    throw new Error('pageSize must be a positive integer');
  }
  if (!Number.isSafeInteger(maxItems) || maxItems < 1) {
    throw new Error('maxItems must be a positive integer');
  }

  const items: unknown[] = [];
  for (let start = 0; start < maxItems; start += pageSize) {
    const end = Math.min(start + pageSize, maxItems);
    const result = await client.submit(buildQuery(start, end));
    const page = toArray(result);
    appendAll(items, page);
    if (page.length < end - start) return items;
  }

  logger.warn('Graph enumeration hit the item cap; results may be incomplete', {
    label: options.label,
    maxItems,
  });
  return items;
}

/**
 * Normalizes a driver result set (which exposes toArray) or a plain array.
 * The shared SigV4 client returns an array; the raw driver returns a result
 * set, so callers that may receive either should use this.
 */
export function toArray(result: unknown): unknown[] {
  if (result && typeof (result as GraphResultSet).toArray === 'function') {
    return (result as GraphResultSet).toArray();
  }
  return Array.isArray(result) ? result : [];
}
