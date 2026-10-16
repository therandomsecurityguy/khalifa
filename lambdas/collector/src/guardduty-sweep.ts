import { randomUUID } from 'node:crypto';
import { GuardDutyClient } from '@aws-sdk/client-guardduty';
import type { GraphNode, GraphEdge } from '../../shared/types';
import { Logger } from '../../shared/types';
import { getTargetCredentials } from '../../shared/aws-credentials';
import { writeGraphInBatches, type GraphWriter } from '../../shared/graph-batch-writer';
import { invokeGraphWriter } from '../../shared/graph-writer-client';
import {
  buildRegionFindingGraph,
  collectRegionFindings,
  guardDutyFindingsScope,
} from './guardduty-findings';

const logger = new Logger('guardduty-findings');

export interface GuardDutyFindingsEvent {
  administratorAccountId: string;
  regions: string[];
}

export interface RegionFindingsResult {
  region: string;
  status: 'SUCCEEDED' | 'NO_DETECTOR' | 'FAILED';
  findings: number;
  edges: number;
  skippedEdges: number;
  tombstoned: number;
  error?: string;
}

export interface GuardDutySweepDependencies {
  client?: (region: string) => Promise<GuardDutyClient>;
  write?: GraphWriter;
}

// Stamps the reconcile fields without touching account_id: a finding keeps the
// member account and region it describes.
function scoped<T extends GraphNode | GraphEdge>(
  element: T,
  scope: string,
  region: string,
  runId: string
): T {
  return {
    ...element,
    properties: {
      ...element.properties,
      collection_region: region,
      collection_scope: scope,
      collection_run_id: runId,
      active: true,
    },
  };
}

export async function collectGuardDutyFindings(
  event: GuardDutyFindingsEvent,
  dependencies: GuardDutySweepDependencies = {}
): Promise<RegionFindingsResult[]> {
  const write = dependencies.write || invokeGraphWriter;
  const clientFor =
    dependencies.client ||
    (async (region: string) => {
      const credentials = await getTargetCredentials({
        accountId: event.administratorAccountId,
        region,
      });
      return new GuardDutyClient({
        region,
        maxAttempts: 3,
        retryMode: 'standard',
        ...(credentials ? { credentials } : {}),
      });
    });

  const results: RegionFindingsResult[] = [];
  // Regions run one at a time: each is at most a few hundred findings, and the
  // administrator account's GuardDuty API quota is shared across them.
  for (const region of event.regions) {
    const scope = guardDutyFindingsScope(region);
    const runId = randomUUID();
    try {
      const client = await clientFor(region);
      const collected = await collectRegionFindings(client, region);
      if (!collected) {
        // No detector: nothing to write, and nothing to reconcile away. A
        // missing detector is reported by the per-account detector check.
        logger.warn('No GuardDuty detector in administrator account region', { region });
        results.push({
          region,
          status: 'NO_DETECTOR',
          findings: 0,
          edges: 0,
          skippedEdges: 0,
          tombstoned: 0,
        });
        continue;
      }
      const graph = buildRegionFindingGraph(collected.findings, region);
      const completedAt = new Date().toISOString();
      const written = await writeGraphInBatches(
        {
          nodes: graph.nodes.map((node) => scoped(node, scope, region, runId)),
          edges: graph.edges.map((edge) => scoped(edge, scope, region, runId)),
          // No accountId: one administrator run owns every member's findings in
          // the region, so a finding archived since the last run is removed
          // whichever account it belongs to.
          reconcile: { scope, runId, observedAt: completedAt, region },
        },
        completedAt,
        { write }
      );
      results.push({
        region,
        status: 'SUCCEEDED',
        findings: graph.nodes.length,
        edges: graph.edges.length,
        skippedEdges: written.skipped,
        tombstoned: written.tombstoned,
      });
    } catch (error) {
      // A failed region keeps its previous findings: without a complete read
      // there is nothing to reconcile against.
      const message = error instanceof Error ? error.message : String(error);
      logger.error('GuardDuty findings collection failed', { region, error: message });
      results.push({
        region,
        status: 'FAILED',
        findings: 0,
        edges: 0,
        skippedEdges: 0,
        tombstoned: 0,
        error: message,
      });
    }
  }
  logger.info('GuardDuty findings collection complete', {
    regions: results.length,
    failed: results.filter((r) => r.status === 'FAILED').map((r) => r.region),
    findings: results.reduce((sum, r) => sum + r.findings, 0),
  });
  return results;
}
