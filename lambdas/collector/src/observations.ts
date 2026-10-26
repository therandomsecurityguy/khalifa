import { BatchGetItemCommand, DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { Logger } from '../../shared/types';

const logger = new Logger('traffic-observations');

export interface TrafficObservation {
  interfaceId: string;
  packets: number;
  bytes: number;
  lastSeen?: string;
}

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

// One instance-level fact derived from its interfaces: traffic was observed,
// and when it was most recently seen. Reachability confidence then becomes
// observed AND configured (see pathLikelihood).
export function instanceObservation(
  interfaceIds: (string | undefined)[],
  observations: Map<string, TrafficObservation>
): { trafficObserved: true; lastSeen?: string } | undefined {
  let latest: string | undefined;
  let observed = false;
  for (const interfaceId of interfaceIds) {
    if (!interfaceId) continue;
    const observation = observations.get(interfaceId);
    if (!observation) continue;
    observed = true;
    if (observation.lastSeen && (!latest || observation.lastSeen > latest)) {
      latest = observation.lastSeen;
    }
  }
  return observed ? { trafficObserved: true, ...(latest ? { lastSeen: latest } : {}) } : undefined;
}
