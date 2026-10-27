import type { GraphEdge, GraphNode } from './types';

// Event-triggered recompute: which graph changes make yesterday's evaluation
// stale? IAM is the whole CIEM surface — a new grant, role, key or trust can
// create an escalation the policy evaluator only writes on its schedule — so
// any node or edge in that family marks a batch worth recomputing for.
export const RECOMPUTE_NODE_LABELS = new Set([
  'IamGroup',
  'IamPolicy',
  'IamPolicyDocument',
  'IamPolicyStatement',
  'IamRole',
  'IamUser',
  'AccessKey',
]);

export const RECOMPUTE_EDGE_LABELS = new Set([
  'ATTACHED_TO',
  'HAS_ACCESS_KEY',
  'HAS_IAM_ROLE',
  'MEMBER_OF',
  'TRUSTS',
]);

export function recomputeReasons(nodes: GraphNode[], edges: GraphEdge[]): string[] {
  const reasons = new Set<string>();
  for (const node of nodes) {
    if (RECOMPUTE_NODE_LABELS.has(node.label)) reasons.add(node.label);
  }
  for (const edge of edges) {
    if (RECOMPUTE_EDGE_LABELS.has(edge.label)) reasons.add(edge.label);
  }
  return [...reasons].sort();
}

// FIFO dedup window: SQS only keeps a deduplication id for five minutes, so a
// burst of IAM events in one window collapses to a single recompute message.
export const RECOMPUTE_DEDUP_WINDOW_MS = 5 * 60 * 1000;

export function recomputeDeduplicationId(nowMs: number): string {
  return `recompute-${Math.floor(nowMs / RECOMPUTE_DEDUP_WINDOW_MS)}`;
}
