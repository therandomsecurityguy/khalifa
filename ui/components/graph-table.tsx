import Link from 'next/link';
import type { GraphEdge, GraphVertex } from '@/types';
import { resourceHref } from '@/lib/routes';
import { EmptyState } from '@/components/states';
import { GraphCanvas } from '@/components/graph-canvas';
import { formatEdgeLabel } from '@/components/graph-hops';
import { formatNodeLabel, nodeName } from '@/lib/graph-labels';

export function GraphTable({
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
  if (nodes.length === 0 && edges.length === 0) {
    return <EmptyState title={empty} />;
  }

  return (
    <div className="space-y-6">
      <GraphCanvas nodes={nodes} edges={edges} empty={empty} origin={origin} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="overflow-hidden rounded-lg bg-white shadow">
          <h2 className="border-b border-gray-200 px-4 py-3 text-sm font-medium text-gray-900">
            Nodes ({nodes.length})
          </h2>
          <ul className="max-h-96 divide-y divide-gray-100 overflow-y-auto">
            {nodes.map((node) => (
              <li key={node.id} className="px-4 py-3">
                <div className="text-xs text-gray-500">{formatNodeLabel(node.label)}</div>
                {node.id.startsWith('arn:') ? (
                  <Link
                    href={resourceHref(node.id)}
                    className="break-all text-sm font-medium text-indigo-600 hover:text-indigo-900"
                  >
                    {nodeName(node)}
                  </Link>
                ) : (
                  <div className="text-sm text-gray-900">{nodeName(node)}</div>
                )}
                <div className="break-all text-xs text-gray-500">{node.id}</div>
              </li>
            ))}
          </ul>
        </div>
        <div className="overflow-hidden rounded-lg bg-white shadow">
          <h2 className="border-b border-gray-200 px-4 py-3 text-sm font-medium text-gray-900">
            Edges ({edges.length})
          </h2>
          <ul className="max-h-96 divide-y divide-gray-100 overflow-y-auto">
            {edges.map((edge) => (
              <li key={edge.id} className="px-4 py-3 text-sm text-gray-700">
                <div className="font-medium">{formatEdgeLabel(edge.label)}</div>
                <div className="break-all text-xs text-gray-500">
                  {edge.from} → {edge.to}
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
