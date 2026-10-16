import { useId } from 'react';
import type { GraphEdge, GraphVertex } from '@/types';
import { EmptyState } from '@/components/states';
import { nodeName } from '@/lib/graph-labels';
import {
  CARD_H,
  CARD_W,
  GraphKpi,
  HopCard,
  TypeLegend,
  formatEdgeLabel,
  summarizeEdges,
} from '@/components/graph-hops';

const COL_GAP = 120;
const ROW_GAP = 36;
const PAD = 36;

function neighborsOf(id: string, edges: GraphEdge[]): string[] {
  const next = new Set<string>();
  for (const edge of edges) {
    if (edge.from === id) next.add(edge.to);
    if (edge.to === id) next.add(edge.from);
  }
  return [...next];
}

function layeredNodes(nodes: GraphVertex[], edges: GraphEdge[], origin?: string): GraphVertex[][] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const start =
    (origin && byId.get(origin)?.id) ||
    nodes.find((node) => !edges.some((edge) => edge.to === node.id))?.id ||
    nodes[0]?.id;
  if (!start) return [];

  const layers: GraphVertex[][] = [];
  const seen = new Set<string>([start]);
  let current = [start];
  while (current.length > 0) {
    layers.push(current.map((id) => byId.get(id)).filter(Boolean) as GraphVertex[]);
    const next: string[] = [];
    for (const id of current) {
      for (const neighbor of neighborsOf(id, edges)) {
        if (!seen.has(neighbor) && byId.has(neighbor)) {
          seen.add(neighbor);
          next.push(neighbor);
        }
      }
    }
    current = next;
  }

  const leftover = nodes.filter((node) => !seen.has(node.id));
  if (leftover.length > 0) layers.push(leftover);
  return layers;
}

export function GraphNeighborhood({
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
  const uid = useId().replace(/:/g, '');
  if (nodes.length === 0) {
    return <EmptyState title={empty} />;
  }

  const layers = layeredNodes(nodes, edges, origin);
  const maxRows = Math.max(...layers.map((layer) => layer.length), 1);
  const maxColHeight = maxRows * CARD_H + (maxRows - 1) * ROW_GAP;
  const width = PAD * 2 + layers.length * CARD_W + Math.max(layers.length - 1, 0) * COL_GAP;
  const height = PAD * 2 + maxColHeight;
  const positions = new Map<string, { x: number; y: number }>();

  layers.forEach((layer, column) => {
    const colHeight = layer.length * CARD_H + Math.max(layer.length - 1, 0) * ROW_GAP;
    const offset = (maxColHeight - colHeight) / 2;
    layer.forEach((node, row) => {
      positions.set(node.id, {
        x: PAD + column * (CARD_W + COL_GAP),
        y: PAD + offset + row * (CARD_H + ROW_GAP),
      });
    });
  });

  const drawnEdges = edges.flatMap((edge, index) => {
    const from = positions.get(edge.from);
    const to = positions.get(edge.to);
    if (!from || !to) return [];
    const x1 = from.x + CARD_W;
    const y1 = from.y + CARD_H / 2;
    const x2 = to.x;
    const y2 = to.y + CARD_H / 2;
    const cpx = (x1 + x2) / 2;
    const d = `M${x1},${y1} C${cpx},${y1} ${cpx},${y2} ${x2},${y2}`;
    const label = formatEdgeLabel(edge.label);
    const lw = Math.max(56, label.length * 6.4 + 14);
    return [
      {
        id: edge.id || `e-${index}`,
        d,
        label,
        midX: (x1 + x2) / 2,
        midY: (y1 + y2) / 2 - 18,
        lw,
      },
    ];
  });

  const types = [...new Set(nodes.map((node) => node.label))];
  const focusId = origin && positions.has(origin) ? origin : layers[0]?.[0]?.id;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <GraphKpi label="Nodes" value={String(nodes.length)} />
        <GraphKpi label="Edges" value={String(edges.length)} />
        <GraphKpi
          label="Focus"
          value={focusId ? nodeName(nodes.find((node) => node.id === focusId) ?? nodes[0]) : '—'}
        />
        <GraphKpi label="Depth" value={String(Math.max(layers.length - 1, 0))} />
      </div>

      <div className="overflow-auto rounded-lg border border-slate-200 bg-slate-50">
        <div className="relative" style={{ width, height }}>
          <svg width={width} height={height} className="absolute inset-0" role="img">
            <defs>
              <marker
                id={`${uid}-arrow`}
                markerWidth="8"
                markerHeight="8"
                refX="7"
                refY="4"
                orient="auto"
              >
                <path d="M0,0 L8,4 L0,8 Z" fill="#475569" />
              </marker>
            </defs>
            {drawnEdges.map((edge) => (
              <g key={edge.id}>
                <path
                  d={edge.d}
                  fill="none"
                  stroke="#cbd5e1"
                  strokeWidth="6"
                  strokeLinecap="round"
                />
                <path
                  d={edge.d}
                  fill="none"
                  stroke="#475569"
                  strokeWidth="2"
                  markerEnd={`url(#${uid}-arrow)`}
                />
                <circle r="3.5" fill="#4f46e5">
                  <animateMotion dur="2s" repeatCount="indefinite" path={edge.d} />
                </circle>
                <rect
                  x={edge.midX - edge.lw / 2}
                  y={edge.midY - 10}
                  width={edge.lw}
                  height="18"
                  rx="9"
                  fill="white"
                  stroke="#e2e8f0"
                />
                <text
                  x={edge.midX}
                  y={edge.midY + 3}
                  textAnchor="middle"
                  fill="#334155"
                  fontSize="10"
                  fontWeight="600"
                >
                  {edge.label}
                </text>
              </g>
            ))}
          </svg>
          {nodes.map((node) => {
            const point = positions.get(node.id);
            if (!point) return null;
            const inbound = edges.filter((edge) => edge.to === node.id);
            const outbound = edges.filter((edge) => edge.from === node.id);
            const role =
              node.id === focusId
                ? 'focus'
                : inbound.length === 0
                  ? 'ingress'
                  : outbound.length === 0
                    ? 'egress'
                    : 'hop';
            return (
              <div key={node.id} className="absolute" style={{ left: point.x, top: point.y }}>
                <HopCard
                  node={node}
                  inbound={summarizeEdges(inbound)}
                  outbound={summarizeEdges(outbound)}
                  role={role}
                />
              </div>
            );
          })}
        </div>
      </div>
      <TypeLegend labels={types} />
    </div>
  );
}
