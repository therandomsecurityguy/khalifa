import Link from 'next/link';
import type { GraphEdge, GraphVertex } from '@/types';
import { resourceHref } from '@/lib/routes';
import { formatNodeLabel, nodeName } from '@/lib/graph-labels';

const TYPE_COLOR: Record<string, string> = {
  Internet: '#dc2626',
  LoadBalancer: '#7c3aed',
  SecurityGroup: '#4b5563',
  Ec2Instance: '#2563eb',
  EC2Instance: '#2563eb',
  LambdaFunction: '#7e22ce',
  Lambda: '#7e22ce',
  IamRole: '#ca8a04',
  IAMRole: '#ca8a04',
  IamUser: '#d97706',
  IAMUser: '#d97706',
  S3Bucket: '#16a34a',
  Secret: '#b45309',
  RdsInstance: '#ea580c',
  RDSInstance: '#ea580c',
  DataClassificationFinding: '#be123c',
  ExternalAccount: '#0f766e',
  Account: '#0f766e',
};

export const CARD_W = 188;
export const CARD_H = 112;

export function formatEdgeLabel(label: string): string {
  return label
    .toLowerCase()
    .split(/[_-]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

export function summarizeEdges(edges: GraphEdge[]): string | undefined {
  if (edges.length === 0) return undefined;
  const first = formatEdgeLabel(edges[0].label);
  return edges.length > 1 ? `${first} +${edges.length - 1}` : first;
}

export function HopCard({
  node,
  inbound,
  outbound,
  role,
}: {
  node: GraphVertex;
  inbound?: string;
  outbound?: string;
  role: 'ingress' | 'hop' | 'egress' | 'focus';
}) {
  const color = TYPE_COLOR[node.label] ?? '#475569';
  const name = nodeName(node);
  const href = node.id.startsWith('arn:') ? resourceHref(node.id) : undefined;
  const roleLabel =
    role === 'ingress'
      ? 'Ingress'
      : role === 'egress'
        ? 'Egress'
        : role === 'focus'
          ? 'Focus'
          : 'Hop';
  const roleClass =
    role === 'ingress'
      ? 'bg-red-50 text-red-700'
      : role === 'egress'
        ? 'bg-emerald-50 text-emerald-700'
        : role === 'focus'
          ? 'bg-indigo-50 text-indigo-700'
          : 'bg-slate-100 text-slate-600';

  return (
    <article
      className="relative shrink-0 rounded-[10px] border bg-white shadow-sm"
      style={{ width: CARD_W, height: CARD_H, borderColor: color }}
    >
      <div
        className="absolute inset-y-0 left-0 w-1.5 rounded-l-[10px]"
        style={{ backgroundColor: color }}
      />
      <div
        className={`absolute -top-2.5 left-4 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${roleClass}`}
      >
        {roleLabel}
      </div>
      <div className="flex h-full flex-col px-3.5 pb-2.5 pt-4">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span
              className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-30"
              style={{ backgroundColor: color }}
            />
            <span
              className="relative inline-flex h-2.5 w-2.5 rounded-full"
              style={{ backgroundColor: color }}
            />
          </span>
          <span className="truncate text-[10px] font-medium text-slate-500">
            {formatNodeLabel(node.label)}
          </span>
        </div>
        {href ? (
          <Link
            href={href}
            title={name}
            className="mt-1 truncate text-sm font-semibold text-slate-900 hover:text-indigo-700"
          >
            {name}
          </Link>
        ) : (
          <div title={name} className="mt-1 truncate text-sm font-semibold text-slate-900">
            {name}
          </div>
        )}
        <dl className="mt-auto space-y-1 border-t border-slate-100 pt-2 text-[11px] text-slate-600">
          <div className="flex items-center justify-between gap-2">
            <dt className="text-slate-500">In</dt>
            <dd className="truncate font-medium text-slate-700">{inbound ?? '—'}</dd>
          </div>
          <div className="flex items-center justify-between gap-2">
            <dt className="text-slate-500">Out</dt>
            <dd className="truncate font-medium text-slate-700">{outbound ?? '—'}</dd>
          </div>
        </dl>
      </div>
    </article>
  );
}

export function GraphKpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2">
      <div className="text-[10px] font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-0.5 truncate text-sm font-semibold text-slate-900" title={value}>
        {value}
      </div>
    </div>
  );
}

export function TypeLegend({ labels }: { labels: string[] }) {
  return (
    <div className="flex flex-wrap gap-x-4 gap-y-2 text-[11px] text-slate-600">
      {labels.map((type) => (
        <span key={type} className="inline-flex items-center gap-1.5">
          <span
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: TYPE_COLOR[type] ?? '#475569' }}
          />
          {formatNodeLabel(type)}
        </span>
      ))}
    </div>
  );
}
