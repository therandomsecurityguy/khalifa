import { BatchGetItemCommand, DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { Logger } from '../../shared/types';

const logger = new Logger('traffic-observations');

export interface ObservedEndpoint {
  address: string;
  bytes: number;
  flows: number;
  lastSeen?: string;
}

export interface TrafficObservation {
  interfaceId: string;
  packets: number;
  bytes: number;
  lastSeen?: string;
  /** The top remote senders the flow-log analyzer aggregated, if it ran with endpoint evidence. */
  endpoints?: ObservedEndpoint[];
}

// Per instance, enough endpoints to cite a hop without bloating the vertex.
export const MAX_INSTANCE_ENDPOINTS = 5;
const MAX_ENDPOINTS_PER_OBSERVATION = 20;

// Per-run bound: chunk into 100-key requests and stop after this many so a
// pathological account cannot turn one collection into thousands of reads.
export const MAX_OBSERVATION_LOOKUPS = 500;
const CHUNK_SIZE = 100;

// The flow-log analyzer's observations for these interfaces, keyed by
// interface id. Optional by design: the table may not exist yet (CDK path),
// the role may not have the read grant, or the analyzer may never have run —
// all of that is "no observed traffic", never a failed collection.
export async function loadTrafficObservations(
  client: DynamoDBClient,
  tableName: string,
  interfaceIds: Iterable<string>
): Promise<Map<string, TrafficObservation>> {
  const unique = [...new Set(interfaceIds)].filter(Boolean).slice(0, MAX_OBSERVATION_LOOKUPS);
  const observations = new Map<string, TrafficObservation>();
  if (unique.length === 0) return observations;

  for (let index = 0; index < unique.length; index += CHUNK_SIZE) {
    const chunk = unique.slice(index, index + CHUNK_SIZE);
    try {
      const response = await client.send(
        new BatchGetItemCommand({
          RequestItems: {
            [tableName]: {
              Keys: chunk.map((interfaceId) => ({ interface_id: { S: interfaceId } })),
            },
          },
        })
      );
      for (const item of response.Responses?.[tableName] ?? []) {
        const interfaceId = item.interface_id?.S;
        if (!interfaceId) continue;
        observations.set(interfaceId, {
          interfaceId,
          packets: Number(item.packets?.N ?? 0),
          bytes: Number(item.bytes?.N ?? 0),
          lastSeen: item.last_seen?.S,
          ...(parseEndpoints(item.endpoints) ?? {}),
        });
      }
    } catch (error) {
      logger.warn('Traffic observations unavailable; continuing without them', {
        error: error instanceof Error ? error.message : String(error),
        table: tableName,
      });
      return observations;
    }
  }
  return observations;
}

// The analyzer's endpoint list on an observation item, read defensively: a
// malformed list means no citations, never a failed collection.
function parseEndpoints(value: unknown): { endpoints?: ObservedEndpoint[] } | undefined {
  const raw = (value as { L?: unknown[] } | undefined)?.L;
  if (!Array.isArray(raw)) return undefined;
  const endpoints: ObservedEndpoint[] = [];
  for (const entry of raw.slice(0, MAX_ENDPOINTS_PER_OBSERVATION)) {
    const map = (entry as { M?: Record<string, { S?: string; N?: string }> }).M;
    const address = map?.address?.S;
    if (!address) continue;
    const bytes = Number(map?.bytes?.N ?? 0);
    const flows = Number(map?.flows?.N ?? 0);
    endpoints.push({
      address,
      bytes: Number.isFinite(bytes) ? bytes : 0,
      flows: Number.isFinite(flows) ? flows : 0,
      ...(map?.last_seen?.S ? { lastSeen: map.last_seen.S } : {}),
    });
  }
  return endpoints.length > 0 ? { endpoints } : undefined;
}

// One instance-level fact derived from its interfaces: traffic was observed,
// when it was most recently seen, and which remote endpoints sent it —
// deduplicated across interfaces, biggest senders first, capped. Reachability
// confidence then becomes observed AND configured (see pathLikelihood), and an
// attack path through this instance can cite observed traffic on its hop.
export function instanceObservation(
  interfaceIds: (string | undefined)[],
  observations: Map<string, TrafficObservation>
): { trafficObserved: true; lastSeen?: string; endpoints?: ObservedEndpoint[] } | undefined {
  let latest: string | undefined;
  let observed = false;
  const endpoints = new Map<string, ObservedEndpoint>();
  for (const interfaceId of interfaceIds) {
    if (!interfaceId) continue;
    const observation = observations.get(interfaceId);
    if (!observation) continue;
    observed = true;
    if (observation.lastSeen && (!latest || observation.lastSeen > latest)) {
      latest = observation.lastSeen;
    }
    for (const endpoint of observation.endpoints ?? []) {
      const existing = endpoints.get(endpoint.address);
      if (!existing || endpoint.bytes > existing.bytes) endpoints.set(endpoint.address, endpoint);
    }
  }
  if (!observed) return undefined;
  const top = [...endpoints.values()]
    .sort((a, b) => b.bytes - a.bytes || a.address.localeCompare(b.address))
    .slice(0, MAX_INSTANCE_ENDPOINTS);
  return {
    trafficObserved: true,
    ...(latest ? { lastSeen: latest } : {}),
    ...(top.length > 0 ? { endpoints: top } : {}),
  };
}
