import type { GraphVertex } from './types';

// Observed-traffic citations: the flow-log analyzer aggregates the remote
// endpoints that actually sent accepted traffic to an interface, and the
// collector writes the top senders onto the workload vertex
// (observed_endpoints, JSON, bounded). A path hop that arrives at such a
// vertex can cite the observation instead of only claiming configured
// exposure.
export interface ObservedEndpoint {
  address: string;
  bytes?: number;
  flows?: number;
  lastSeen?: string;
}

export interface ObservedTrafficCitation {
  /** 1-based hop number: the edge that arrives at this vertex. */
  hop: number;
  vertexId: string;
  endpoints: ObservedEndpoint[];
}

export const MAX_CITED_ENDPOINTS = 5;

// Tolerant by construction: a malformed or oversized property means no
// citations, never a failed path.
export function parseObservedEndpoints(value: unknown): ObservedEndpoint[] {
  let parsed: unknown = value;
  if (typeof value === 'string') {
    try {
      parsed = JSON.parse(value);
    } catch {
      return [];
    }
  }
  if (!Array.isArray(parsed)) return [];
  const endpoints: ObservedEndpoint[] = [];
  for (const entry of parsed.slice(0, MAX_CITED_ENDPOINTS)) {
    if (!entry || typeof entry !== 'object') continue;
    const record = entry as Record<string, unknown>;
    const address = typeof record.address === 'string' ? record.address : undefined;
    if (!address) continue;
    endpoints.push({
      address,
      ...(typeof record.bytes === 'number' && Number.isFinite(record.bytes)
        ? { bytes: record.bytes }
        : {}),
      ...(typeof record.flows === 'number' && Number.isFinite(record.flows)
        ? { flows: record.flows }
        : {}),
      ...(typeof record.lastSeen === 'string' ? { lastSeen: record.lastSeen } : {}),
    });
  }
  return endpoints;
}

// One citation per hop whose target vertex has observed traffic. The entry
// vertex (index 0) is not a hop: nothing connects to it inside the path.
export function observedTrafficFromPath(path: GraphVertex[]): ObservedTrafficCitation[] {
  const citations: ObservedTrafficCitation[] = [];
  for (let index = 1; index < path.length; index++) {
    const vertex = path[index];
    if (vertex.properties?.traffic_observed !== true) continue;
    const endpoints = parseObservedEndpoints(vertex.properties?.observed_endpoints);
    citations.push({ hop: index, vertexId: vertex.id, endpoints });
  }
  return citations;
}
