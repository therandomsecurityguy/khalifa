import type { Request, Response } from 'express';
import { parseBoundedInteger } from '../middleware/gremlin-validator';
import { hasRole, Role } from '../middleware/rbac';
import {
  computeRiskScore,
  extractRulePath,
  getRuleById,
  pathLikelihood,
  riskInputFromPath,
} from '@khalifa/risk-engine';
import { getApiNeptuneClient } from '../services/api-dependencies';
import { graphCoverage } from '../services/coverage';
import type { AttackPathStart, AttackPathTarget } from '../services/neptune-client';
import type { AttackPathEntry, AttackPathSimulationResponse, GraphVertex } from '../types';

const neptuneClient = getApiNeptuneClient();

// The simulation re-runs one rule's query; bounded so a rule that matches
// thousands of paths cannot hold the request, and so the edge ranking covers
// the paths a caller can act on.
const MAX_SIMULATION_PATHS = 200;
const MAX_SIMULATION_EDGES = 10;

const START_VALUES: AttackPathStart[] = ['any', 'internet', 'outside', 'resource'];
const TARGET_VALUES: AttackPathTarget[] = ['restricted', 'crown', 'secrets', 'admin', 'resource'];
const MAX_TRUST_LOOKUPS = 10;
// A managed-policy grant is four graph steps (attached to, contains, contains,
// grants) but one drawn hop; search this much deeper so two grants still fit.
const POLICY_HOP_SLACK = 6;
const POLICY_LABELS = new Set(['IamPolicy', 'IamPolicyDocument', 'IamPolicyStatement']);

// Hops as the graph draws them: a whole policy chain counts once.
// Our client's own deadline, or Neptune's evaluation timeout.
function isSearchTimeout(error: unknown): boolean {
  const text = error instanceof Error ? `${error.name} ${error.message}` : String(error);
  return /timeout after \d+ms|TimeLimitExceeded/i.test(text);
}

export function drawnHops(path: { nodes: GraphVertex[] }): number {
  const policyNodes = path.nodes.filter((node) => POLICY_LABELS.has(node.label)).length;
  return Math.max(0, path.nodes.length - 1 - policyNodes);
}

export function outsidePrincipals(role: GraphVertex, principals: GraphVertex[]): GraphVertex[] {
  return principals.filter(
    (principal) =>
      principal.label === 'ExternalAccount' ||
      (principal.properties.account_id !== undefined &&
        principal.properties.account_id !== role.properties.account_id)
  );
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T | null {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value)
    ? (value as T)
    : null;
}

// Only resource ARNs can be a start or target.
const VERTEX_ID = /^arn:[\w-]{1,20}:[\w-]{0,40}:[\w-]{0,30}:\d{0,12}:[\x21-\x7e]{1,400}$/;

function optional<T>(value: unknown, parse: (text: string) => T | null): T | null | undefined {
  if (value === undefined || value === '') return undefined;
  return typeof value === 'string' ? parse(value) : null;
}

export async function searchAttackPaths(req: Request, res: Response): Promise<void> {
  try {
    const q = req.query;
    const from = oneOf(q.from ?? 'any', START_VALUES);
    const to = oneOf(q.to, TARGET_VALUES);
    const account = optional(q.account, (v) => (/^\d{12}$/.test(v) ? v : null));
    const fromResource = optional(q.fromResource, (v) => (VERTEX_ID.test(v) ? v : null));
    const toResource = optional(q.toResource, (v) => (VERTEX_ID.test(v) ? v : null));
    const invalid =
      !from ||
      !to ||
      [account, fromResource, toResource].includes(null) ||
      (from === 'resource') !== (fromResource !== undefined) ||
      (to === 'resource') !== (toResource !== undefined);
    if (invalid) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'Invalid attack path search' });
      return;
    }
    const maxAllowed = hasRole(req, Role.Analyst) ? 10 : 4;
    const maxLen = parseBoundedInteger(q.maxPathLength, 4, 1, maxAllowed, 'maxPathLength');
    const limit = parseBoundedInteger(q.limit, 50, 1, 100, 'limit');

    // "Any" runs the internet and outside searches side by side: one query over
    // both starts did not complete on Neptune. A search that times out drops out
    // and marks the result truncated; if every search times out, the request does.
    const starts = from === 'any' ? (['internet', 'outside'] as const) : [from];
    const settled = await Promise.allSettled(
      starts.map((start) =>
        neptuneClient.searchAttackPaths({
          from: start,
          to,
          fromResource: fromResource ?? undefined,
          toResource: toResource ?? undefined,
          maxPathLength: maxLen + POLICY_HOP_SLACK,
          limit,
          account: account ?? undefined,
        })
      )
    );
    const failures = settled.flatMap((r) => (r.status === 'rejected' ? [r.reason] : []));
    const results = settled.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []));
    const hard = failures.find((reason) => !isSearchTimeout(reason));
    if (hard !== undefined) throw hard;
    if (results.length === 0) throw failures[0];
    const seen = new Set<string>();
    const found = results.flat().filter((path) => {
      const key = path.nodes.map((node) => node.id).join('>');
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
    let truncated = failures.length > 0 || results.some((result) => result.length >= limit);
    // A stale graph tempers the likelihood of every path it yielded, and the
    // statement travels with the results (same as simulate and scenarios).
    const coverage = await graphCoverage(neptuneClient);
    // Same scoring as the rule runner, so the explorer and Issues agree on
    // severity and on the path likelihood.
    const paths = found
      .filter((path) => drawnHops(path) <= maxLen)
      .map((path) => {
        const riskInput = riskInputFromPath(path.nodes);
        const { score, severity } = computeRiskScore(riskInput);
        const likelihood = pathLikelihood(riskInput, coverage.level);
        return {
          ...path,
          score,
          severity,
          likelihood: likelihood.value,
          likelihoodFactors: likelihood.factors,
        };
      })
      .sort((a, b) => b.score - a.score || b.likelihood - a.likelihood);
    if (paths.length > limit) {
      paths.length = limit;
      truncated = true;
    }

    // Each path's real entry: the internet for exposed starts, the trusted
    // outside accounts for cross-account roles.
    const entries: Record<string, AttackPathEntry> = {};
    const trustRoles = new Set<string>();
    for (const path of paths) {
      const first = path.nodes[0];
      // The collector's own Internet vertex is already the entry.
      if (!first || entries[first.id] || first.label === 'Internet') continue;
      if (first.properties.is_internet_exposed === true) entries[first.id] = { kind: 'internet' };
      else if (first.properties.has_cross_account_trust === true) trustRoles.add(first.id);
    }
    // Roles past the lookup cap, or whose principals cannot be resolved, still
    // get an outside entry (with no principals) so the path never looks internal.
    if (trustRoles.size > MAX_TRUST_LOOKUPS) truncated = true;
    const lookups = [...trustRoles].slice(0, MAX_TRUST_LOOKUPS);
    for (const roleId of trustRoles) entries[roleId] = { kind: 'trust', principals: [] };
    await Promise.all(
      lookups.map(async (roleId) => {
        const role = paths.find((path) => path.nodes[0]?.id === roleId)!.nodes[0];
        entries[roleId] = {
          kind: 'trust',
          principals: outsidePrincipals(role, await neptuneClient.getTrustedPrincipals(roleId)),
        };
      })
    );

    res.json({ from, to, maxPathLength: maxLen, paths, entries, truncated, coverage });
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message.startsWith('maxPathLength must be') ||
        error.message.startsWith('limit must be'))
    ) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    if (isSearchTimeout(error)) {
      res.status(504).json({ code: 'SEARCH_TIMEOUT', message: 'Attack path search timed out' });
      return;
    }
    console.error('Error searching attack paths:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to search attack paths' });
  }
}

// What a fix would remove: re-runs one rule against the live graph and counts,
// per edge on the matched paths, how many paths traverse it — the remediation
// priority, since the top edge clears the most (or the worst) paths. Removal is
// simulated by filtering the returned paths, not by mutating the graph.
export async function simulateAttackPaths(req: Request, res: Response): Promise<void> {
  try {
    const ruleId = typeof req.query.ruleId === 'string' ? req.query.ruleId : '';
    const rule = getRuleById(ruleId);
    if (!rule) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'Unknown rule' });
      return;
    }

    const rows = await neptuneClient.executeStaticQuery(rule.gremlinQueryTemplate);
    const deduped = new Set<string>();
    const paths = rows
      .map((match) => extractRulePath(match))
      .filter((path) => {
        if (path.vertices.length === 0) return false;
        const key = path.vertices.map((vertex) => vertex.id).join('>');
        if (deduped.has(key)) return false;
        deduped.add(key);
        return true;
      });
    const truncated = paths.length > MAX_SIMULATION_PATHS;
    const bounded = paths.slice(0, MAX_SIMULATION_PATHS);
    const coverage = await graphCoverage(neptuneClient);

    const byEdge = new Map<
      string,
      {
        id: string;
        label: string;
        from: string;
        to: string;
        pathsUsing: number;
        worstLikelihood: number;
      }
    >();
    for (const path of bounded) {
      const likelihood = pathLikelihood(riskInputFromPath(path.vertices), coverage.level).value;
      const edgeCount = Math.min(path.edges.length, path.vertices.length - 1);
      for (let index = 0; index < edgeCount; index++) {
        const edge = path.edges[index];
        const from = path.vertices[index].id;
        const to = path.vertices[index + 1].id;
        const id = edge.id || `${from}>${edge.label}>${to}`;
        const entry = byEdge.get(id) ?? {
          id,
          label: edge.label,
          from,
          to,
          pathsUsing: 0,
          worstLikelihood: 0,
        };
        entry.pathsUsing += 1;
        entry.worstLikelihood = Math.max(entry.worstLikelihood, likelihood);
        byEdge.set(id, entry);
      }
    }

    const body: AttackPathSimulationResponse = {
      ruleId: rule.id,
      ruleName: rule.name,
      totalPaths: bounded.length,
      truncated,
      coverage,
      edges: [...byEdge.values()]
        .sort((a, b) => b.pathsUsing - a.pathsUsing || b.worstLikelihood - a.worstLikelihood)
        .slice(0, MAX_SIMULATION_EDGES)
        .map((entry) => ({
          ...entry,
          remainingPaths: bounded.length - entry.pathsUsing,
          worstLikelihood: Math.round(entry.worstLikelihood * 10000) / 10000,
        })),
    };
    res.json(body);
  } catch (error) {
    if (isSearchTimeout(error)) {
      res.status(504).json({ code: 'SEARCH_TIMEOUT', message: 'Attack path simulation timed out' });
      return;
    }
    console.error('Error simulating attack paths:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to simulate attack paths' });
  }
}

export async function listAccounts(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ accounts: await neptuneClient.listAccounts() });
  } catch (error) {
    console.error('Error listing accounts:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list accounts' });
  }
}
