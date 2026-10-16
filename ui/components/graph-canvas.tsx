import type { GraphEdge, GraphVertex } from '@/types';
import { EmptyState } from '@/components/states';
import { GraphNeighborhood } from '@/components/graph-neighborhood';

export { nodeName } from '@/lib/graph-labels';

export function GraphCanvas({
  nodes,
  edges,
  empty,
  origin,
}: {
  nodes: GraphVertex[];
  edges: GraphEdge[];
  empty: string;
  origin?: string;
}) {
  if (nodes.length === 0) {
    return <EmptyState title={empty} />;
  }

  return <GraphNeighborhood nodes={nodes} edges={edges} empty={empty} origin={origin} />;
}
