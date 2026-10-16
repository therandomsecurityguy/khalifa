'use client';

import Link from 'next/link';
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from 'react';
import type { AttackPathEntry } from '@/types';
import { EmptyState } from '@/components/states';
import { formatNodeLabel, nodeName } from '@/lib/graph-labels';
import { resourceHref } from '@/lib/routes';
import {
  CARD_H,
  CARD_W,
  AWS_MANAGED_ACCOUNT,
  INTERNET_ID,
  LANE_HEAD,
  UNRESOLVED_ACCOUNT,
  buildAttackGraph,
  chokePoints,
  groupSiblings,
  layoutAttackGraph,
  describePaths,
  type AttackGraphModel,
  type AttackPathInput,
  type Band,
  type EntryKind,
  type GraphLink,
  type GraphNode,
  type PathDescription,
  type RiskFlag,
  type Stage,
} from '@/lib/attack-graph';
import { SeverityBadge } from '@/components/ui';

const ENTRY_LABEL: Record<EntryKind, string> = {
  internet: 'From the internet',
  outside: 'From an outside account',
  internal: 'From inside',
};
const ENTRY_ICON: Record<EntryKind, string> = {
  internet: 'internet',
  outside: 'account',
  internal: 'house',
};
const SEVERITY_EDGE: Record<string, string> = {
  critical: 'border-red-700',
  high: 'border-orange-500',
  medium: 'border-yellow-400',
  low: 'border-blue-700',
};

const STAGE_COLOR: Record<Stage, string> = {
  entry: '#dc2626',
  external: '#475569',
  compute: '#2563eb',
  identity: '#d97706',
  permission: '#7c3aed',
  data: '#059669',
  finding: '#db2777',
};

const STAGE_LABEL: Record<Stage, string> = {
  entry: 'Entry',
  external: 'Outside account',
  compute: 'Compute & network',
  identity: 'Identity',
  permission: 'Permissions',
  data: 'Data',
  finding: 'Finding',
};

// 24px stroke icons; unknown labels fall back to a plain dot.
const ICONS: Record<string, string> = {
  internet:
    'M3 12h18M12 3c2.8 3 2.8 15 0 18M12 3c-2.8 3-2.8 15 0 18M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18',
  account:
    'M5 6h14a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2zM8 6V4h8v2M3 11h18',
  server:
    'M6 4h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zM8 9h8M8 12h8M8 15h5',
  person: 'M12 4.5a3.5 3.5 0 1 1 0 7a3.5 3.5 0 1 1 0-7zM5 20c.8-4 3.6-6 7-6s6.2 2 7 6',
  key: 'M8 11a4 4 0 1 1 0 .01M11.5 12.5L20 21M16 17l2-2M18 19l2-2',
  document: 'M7 3h7l4 4v14H7zM14 3v4h4M9.5 12h6M9.5 15.5h6',
  list: 'M9 7h11M9 12h11M9 17h11M5 7h.01M5 12h.01M5 17h.01',
  bucket:
    'M5 6a7 2.5 0 1 0 14 0a7 2.5 0 1 0-14 0M5 6l1.5 12c.2 1.4 2.7 2.5 5.5 2.5s5.3-1.1 5.5-2.5L19 6',
  database:
    'M5 6a7 2.5 0 1 0 14 0a7 2.5 0 1 0-14 0M5 6v12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5V6M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5',
  shield: 'M12 3l8 3v6c0 4.5-3.4 8-8 9c-4.6-1-8-4.5-8-9V6z',
  alert: 'M12 4l9 16H3zM12 10v4M12 17h.01',
  house: 'M3 11l9-8 9 8M5 10v10h14V10M10 20v-6h4v6',
  dot: 'M12 8a4 4 0 1 1 0 8a4 4 0 1 1 0-8',
};

const ICON_BY_LABEL: Record<string, string> = {
  Internet: 'internet',
  ExternalAccount: 'account',
  AwsAccount: 'account',
  Ec2Instance: 'server',
  EC2Instance: 'server',
  LambdaFunction: 'server',
  EksCluster: 'server',
  LoadBalancer: 'server',
  IamRole: 'person',
  IamUser: 'person',
  IamGroup: 'person',
  AccessKey: 'key',
  Secret: 'key',
  IamPolicy: 'document',
  IamPolicyDocument: 'document',
  IamPolicyStatement: 'list',
  S3Bucket: 'bucket',
  RdsInstance: 'database',
  DynamoDBTable: 'database',
  RedshiftCluster: 'database',
  SecurityGroup: 'shield',
  SecurityGroupRule: 'shield',
  SecurityHubFinding: 'alert',
  DataClassificationFinding: 'alert',
  CloudTrailAnomaly: 'alert',
};

const HIDDEN_PROPS = new Set(['id', 'arn', 'name', 'account_id', 'external_account_id']);

function typeLabel(node: GraphNode): string {
  return node.vertex.id === INTERNET_ID ? 'Internet' : formatNodeLabel(node.vertex.label);
}

function shortName(node: GraphNode): string {
  const name = nodeName(node.vertex);
  return name.length > 20 ? `${name.slice(0, 19)}…` : name;
}

function worstLevel(risks: RiskFlag[]): RiskFlag['level'] | null {
  if (risks.some((flag) => flag.level === 'risk')) return 'risk';
  return risks.length ? 'warn' : null;
}

function formatValue(value: unknown): string {
  if (value === true) return 'yes';
  if (value === false) return 'no';
  if (Array.isArray(value)) return value.join(', ');
  return String(value);
}

function bandTitle(band: Pick<Band, 'account' | 'external'>, names: Record<string, string>) {
  if (band.account === null) return { title: 'Outside AWS', id: '', note: '' };
  if (band.account === 'unknown') return { title: 'Unknown account', id: '', note: '' };
  if (band.account === AWS_MANAGED_ACCOUNT) {
    return { title: 'AWS managed policies', id: '', note: '' };
  }
  if (band.account === UNRESOLVED_ACCOUNT) {
    return { title: 'Outside account', id: '', note: 'not resolved' };
  }
  if (band.external) return { title: 'External account', id: band.account, note: 'not collected' };
  return { title: names[band.account] || 'Account', id: band.account, note: '' };
}

function accountText(node: GraphNode, names: Record<string, string>): string {
  const { title, id, note } = bandTitle(node, names);
  return [title, id, note].filter(Boolean).join(' · ');
}

// Every node and link on some path through `id`.
function pathsThrough(id: string, links: GraphLink[]) {
  const up = new Set([id]);
  const down = new Set([id]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const link of links) {
      if (down.has(link.from) && !down.has(link.to)) {
        down.add(link.to);
        changed = true;
      }
      if (up.has(link.to) && !up.has(link.from)) {
        up.add(link.from);
        changed = true;
      }
    }
  }
  const linkKeys = new Set(
    links
      .filter(
        (link) =>
          (up.has(link.from) && up.has(link.to)) || (down.has(link.from) && down.has(link.to))
      )
      .map((link) => `${link.from}>${link.to}`)
  );
  return { nodes: new Set([...up, ...down]), links: linkKeys };
}

function resourceCount(model: AttackGraphModel): number {
  return model.nodes.filter(
    (node) => node.vertex.id !== INTERNET_ID && node.account !== UNRESOLVED_ACCOUNT
  ).length;
}

const H4 = 'mb-1 text-[11px] font-semibold uppercase tracking-wider text-gray-500';

function RiskChips({ risks }: { risks: RiskFlag[] }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {risks.map((flag) => (
        <span
          key={flag.text}
          className={`rounded-full px-2 py-0.5 text-xs font-medium ${
            flag.level === 'risk' ? 'bg-red-50 text-red-800' : 'bg-amber-50 text-amber-800'
          }`}
        >
          {flag.text}
        </span>
      ))}
    </div>
  );
}

function PathRow({
  description,
  onSelect,
}: {
  description: PathDescription;
  onSelect: () => void;
}) {
  const { path, entry, start, target, hops, risks } = description;
  const edge = (path.severity && SEVERITY_EDGE[path.severity]) || 'border-gray-300';
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`flex w-full items-start gap-3 border-l-[3px] py-2 pl-2.5 pr-1 text-left hover:bg-gray-50 ${edge}`}
    >
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm text-gray-900">
          <span className="font-medium">{nodeName(start.vertex)}</span>
          <span className="text-gray-400"> → </span>
          <span className="font-medium">{nodeName(target.vertex)}</span>
        </span>
        <span className="mt-0.5 flex items-center gap-1.5 text-xs text-gray-500">
          <svg viewBox="0 0 24 24" className="h-3.5 w-3.5 shrink-0" aria-hidden="true">
            <path
              d={ICONS[ENTRY_ICON[entry]]}
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <span className="sr-only">{ENTRY_LABEL[entry]} · </span>
          {hops} {hops === 1 ? 'hop' : 'hops'}
          {risks.length > 0 && ` · ${risks.length} ${risks.length === 1 ? 'risk' : 'risks'}`}
        </span>
      </span>
      <span className="shrink-0 text-right">
        {path.severity && <SeverityBadge severity={path.severity} tone="soft" />}
        {path.score !== undefined && (
          <span className="block text-xs tabular-nums text-gray-500">{path.score.toFixed(0)}</span>
        )}
      </span>
    </button>
  );
}

function PathDetails({
  description,
  model,
  onSelectNode,
  onClear,
}: {
  description: PathDescription;
  model: AttackGraphModel;
  onSelectNode: (id: string) => void;
  onClear: () => void;
}) {
  const { path, entry, start, target, hops, risks } = description;
  const byId = new Map(model.nodes.map((node) => [node.vertex.id, node]));
  const links = new Map(model.links.map((link) => [`${link.from}>${link.to}`, link]));
  const steps = path.linkKeys
    .map((key) => links.get(key))
    .filter((link): link is GraphLink => link !== undefined);
  const nodeButton =
    'rounded px-1 text-left font-medium text-gray-900 underline decoration-gray-300 underline-offset-2 hover:text-indigo-700';
  return (
    <div className="space-y-4">
      <div>
        <div className="flex flex-wrap items-center gap-2 text-xs font-medium text-gray-500">
          {path.severity && <SeverityBadge severity={path.severity} tone="soft" />}
          {path.score !== undefined && (
            <span className="tabular-nums">Score {path.score.toFixed(0)}</span>
          )}
          <span>{ENTRY_LABEL[entry]}</span>
        </div>
        <h3 className="mt-1 break-words text-base font-semibold text-gray-900">
          {nodeName(start.vertex)} → {nodeName(target.vertex)}
        </h3>
        <p className="text-xs text-gray-500">
          {hops} {hops === 1 ? 'hop' : 'hops'} · one of {model.pathCount} paths
        </p>
      </div>
      {risks.length > 0 && (
        <section>
          <h4 className={H4}>Risks on this path</h4>
          <RiskChips risks={risks} />
        </section>
      )}
      <section>
        <h4 className={H4}>Steps</h4>
        <ol className="space-y-1.5 text-sm">
          <li>
            <button
              type="button"
              className={nodeButton}
              onClick={() => onSelectNode(start.vertex.id)}
            >
              {nodeName(start.vertex)}
            </button>
            <span className="ml-1 text-xs text-gray-500">{typeLabel(start)}</span>
          </li>
          {steps.map((link) => {
            const to = byId.get(link.to)!;
            return (
              <li key={`${link.from}>${link.to}`} className="border-l-2 border-gray-200 pl-3">
                <div className="text-xs text-gray-500">
                  {link.label}
                  {link.crossAccount ? ' · cross-account' : ''}
                  {link.kind === 'deny' ? ' · no access' : ''}
                </div>
                <button
                  type="button"
                  className={nodeButton}
                  onClick={() => onSelectNode(to.vertex.id)}
                >
                  {nodeName(to.vertex)}
                </button>
                <span className="ml-1 text-xs text-gray-500">{typeLabel(to)}</span>
              </li>
            );
          })}
        </ol>
      </section>
      <button
        type="button"
        onClick={onClear}
        className="text-sm font-medium text-indigo-600 hover:text-indigo-900"
      >
        Show all paths
      </button>
    </div>
  );
}

function Overview({
  model,
  names,
  ranked,
  onSelect,
  onSelectPath,
}: {
  model: AttackGraphModel;
  names: Record<string, string>;
  ranked: PathDescription[];
  onSelect: (id: string) => void;
  onSelectPath: (index: number) => void;
}) {
  const targets = model.nodes.filter((node) => !model.links.some((l) => l.from === node.vertex.id));
  const accounts = new Map(
    model.nodes
      .filter((node) => node.account !== null && node.account !== AWS_MANAGED_ACCOUNT)
      .map((node) => [node.account, accountText(node, names)])
  );
  const chokes = chokePoints(model);
  const count = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)_minmax(0,2fr)]">
      <div>
        <h4 className={H4}>Overview</h4>
        <p className="text-sm text-gray-600">
          {[
            count(model.pathCount, 'path'),
            count(resourceCount(model), 'resource'),
            count(accounts.size, 'account'),
            count(targets.length, 'target'),
          ].join(' · ')}
        </p>
      </div>
      {chokes.length > 0 && model.pathCount > 1 && (
        <section>
          <h4 className={H4}>Choke points - fix first</h4>
          <div className="flex flex-wrap gap-1.5">
            {chokes.map(({ node, paths }) => (
              <button
                key={node.vertex.id}
                type="button"
                onClick={() => onSelect(node.vertex.id)}
                aria-label={`${nodeName(node.vertex)}, ${paths} of ${model.pathCount} paths`}
                title={typeLabel(node)}
                className="inline-flex max-w-full items-center gap-1.5 rounded-full border border-gray-200 py-0.5 pl-2.5 pr-1 text-xs hover:border-indigo-400 hover:bg-indigo-50"
              >
                <span className="truncate font-medium text-gray-900">{nodeName(node.vertex)}</span>
                <span className="rounded-full bg-gray-100 px-1.5 tabular-nums text-gray-700">
                  {paths}/{model.pathCount}
                </span>
              </button>
            ))}
          </div>
        </section>
      )}
      {model.pathCount > 1 && (
        <section>
          <h4 className={H4}>Paths · worst first</h4>
          <ol className="max-h-80 divide-y divide-gray-100 overflow-y-auto" aria-label="Paths">
            {ranked.map((description) => (
              <li key={description.index}>
                <PathRow
                  description={description}
                  onSelect={() => onSelectPath(description.index)}
                />
              </li>
            ))}
          </ol>
        </section>
      )}
    </div>
  );
}

function NodeDetails({
  node,
  model,
  names,
  onClear,
  clearLabel = 'Show all paths',
}: {
  node: GraphNode;
  model: AttackGraphModel;
  names: Record<string, string>;
  onClear?: () => void;
  clearLabel?: string;
}) {
  const { vertex } = node;
  const through = model.paths.filter((path) => path.nodeIds.includes(vertex.id)).length;
  const byId = new Map(model.nodes.map((n) => [n.vertex.id, n]));
  const inbound = model.links.filter((link) => link.to === vertex.id);
  const outbound = model.links.filter((link) => link.from === vertex.id);
  const props = Object.entries(vertex.properties ?? {})
    .filter(
      ([key, value]) =>
        !HIDDEN_PROPS.has(key) && value !== null && value !== '' && typeof value !== 'object'
    )
    .slice(0, 12);
  const isResource = vertex.id.startsWith('arn:') && !node.external;
  const describe = (link: GraphLink, other: string) =>
    `${nodeName(byId.get(other)!.vertex)} · ${link.label}${link.crossAccount ? ' · cross-account' : ''}`;

  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-center gap-2 text-xs font-medium text-gray-500">
          <span
            className="h-2 w-2 rounded-full"
            style={{ backgroundColor: STAGE_COLOR[node.stage] }}
          />
          {typeLabel(node)}
        </div>
        <h3 className="mt-1 break-words text-base font-semibold text-gray-900">
          {nodeName(vertex)}
        </h3>
        {vertex.id.startsWith('arn:') && (
          <p className="mt-1 break-all font-mono text-xs text-gray-500">{vertex.id}</p>
        )}
      </div>
      {node.risks.length > 0 && (
        <section>
          <h4 className={H4}>Risks</h4>
          <RiskChips risks={node.risks} />
        </section>
      )}
      <section>
        <h4 className={H4}>Account</h4>
        <p className="text-sm text-gray-900">{accountText(node, names)}</p>
      </section>
      {node.permissions.length > 0 && (
        <section>
          <h4 className={H4}>Permissions</h4>
          <ul className="space-y-2 text-sm">
            {node.permissions.map((p) => (
              <li
                key={`${p.policy}/${p.statement}`}
                className="rounded-md border border-orange-100 bg-orange-50 px-3 py-2"
              >
                <div className="font-medium text-gray-900">
                  {p.statement}
                  {p.effect === 'Deny' && (
                    <span className="ml-2 rounded-full bg-gray-200 px-2 py-0.5 text-xs font-medium text-gray-800">
                      Deny
                    </span>
                  )}
                </div>
                <div className="text-xs text-gray-600">Policy {p.policy}</div>
                {p.actions && (
                  <div className="mt-1 break-words font-mono text-xs text-gray-700">
                    {p.actions}
                  </div>
                )}
                {p.notActions && (
                  <div className="mt-1 break-words font-mono text-xs text-gray-700">
                    All actions except {p.notActions}
                  </div>
                )}
                {p.conditions && (
                  <div className="mt-1 break-words text-xs text-amber-800">
                    Only when: <span className="font-mono">{p.conditions}</span>
                  </div>
                )}
                {p.resources && (
                  <div className="break-words font-mono text-xs text-gray-500">
                    on {p.resources}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}
      {props.length > 0 && (
        <section>
          <h4 className={H4}>Properties</h4>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
            {props.map(([key, value]) => (
              <div key={key} className="contents">
                <dt className="text-gray-500">{formatNodeLabel(key)}</dt>
                <dd className="break-words text-gray-900">{formatValue(value)}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}
      <section>
        <h4 className={H4}>On this path</h4>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
          <dt className="text-gray-500">Reached from</dt>
          <dd className="text-gray-900">
            {inbound.length ? inbound.map((l) => describe(l, l.from)).join('; ') : 'Start of path'}
          </dd>
          <dt className="text-gray-500">Leads to</dt>
          <dd className="text-gray-900">
            {outbound.length ? outbound.map((l) => describe(l, l.to)).join('; ') : 'End of path'}
          </dd>
          {model.pathCount > 1 && (
            <>
              <dt className="text-gray-500">Paths through</dt>
              <dd className="tabular-nums text-gray-900">
                {through} of {model.pathCount}
              </dd>
            </>
          )}
        </dl>
      </section>
      <div className="flex flex-wrap gap-4">
        {isResource && (
          <Link
            href={resourceHref(vertex.id)}
            className="text-sm font-medium text-indigo-600 hover:text-indigo-900"
          >
            Open in resource explorer →
          </Link>
        )}
        {onClear && (
          <button
            type="button"
            onClick={onClear}
            className="text-sm font-medium text-indigo-600 hover:text-indigo-900"
          >
            {clearLabel}
          </button>
        )}
      </div>
    </div>
  );
}

const EDGE_STYLE = {
  plain: { stroke: '#94a3b8', dash: undefined, width: 1.6, text: '#374151', border: '#e5e7eb' },
  risk: { stroke: '#b91c1c', dash: undefined, width: 1.6, text: '#374151', border: '#e5e7eb' },
  cross: { stroke: '#7c3aed', dash: '6 4', width: 2, text: '#5b21b6', border: '#ddd6fe' },
  conditional: {
    stroke: '#d97706',
    dash: undefined,
    width: 1.6,
    text: '#92400e',
    border: '#fde68a',
  },
  deny: { stroke: '#9ca3af', dash: '2 4', width: 1.4, text: '#6b7280', border: '#e5e7eb' },
} as const;
type EdgeStyle = keyof typeof EDGE_STYLE;

// Deny never reads as reach; otherwise cross-account, conditional, then risk.
function edgeStyle(link: GraphLink, target: GraphNode): EdgeStyle {
  if (link.kind === 'deny') return 'deny';
  if (link.crossAccount) return 'cross';
  if (link.kind === 'conditional') return 'conditional';
  return worstLevel(target.risks) === 'risk' ? 'risk' : 'plain';
}
const ZOOMS = [0.5, 0.67, 0.8, 1, 1.25, 1.5];

export function AttackGraph({
  paths,
  entries,
  accountNames = {},
  empty,
}: {
  paths: AttackPathInput[];
  entries?: Record<string, AttackPathEntry>;
  accountNames?: Record<string, string>;
  empty: string;
}) {
  const uid = useId().replace(/:/g, '');
  const model = useMemo(() => buildAttackGraph(paths, entries), [paths, entries]);
  const ranked = useMemo(() => describePaths(model), [model]);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const grouped = useMemo(() => groupSiblings(model, expanded), [model, expanded]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  // Index into model.paths of the one path shown alone, if any.
  const [pathIndex, setPathIndex] = useState<number | null>(null);
  const [focusedId, setFocusedId] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const canvasRef = useRef<HTMLDivElement>(null);
  // Canvas width in px, so lanes can stretch to the right edge.
  const [viewWidth, setViewWidth] = useState(0);
  const hasGraph = model.nodes.length > 0;
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(([entry]) => setViewWidth(entry.contentRect.width));
    observer.observe(canvas);
    return () => observer.disconnect();
  }, [hasGraph]);
  const layout = useMemo(
    () => layoutAttackGraph(grouped.model, Math.max(0, viewWidth - 2) / zoom),
    [grouped, viewWidth, zoom]
  );

  if (!hasGraph) return <EmptyState title={empty} />;

  const byId = new Map(model.nodes.map((node) => [node.vertex.id, node]));
  const drawn = (id: string) => grouped.groupOf.get(id) ?? id;
  const targets = model.nodes.filter((node) => !model.links.some((l) => l.from === node.vertex.id));
  // A single path opens on its target; merged paths open on the overview.
  const fallback = model.pathCount <= 1 && targets.length === 1 ? targets[0] : undefined;
  const selected = (selectedId ? byId.get(selectedId) : undefined) ?? fallback;
  const isolated =
    pathIndex !== null ? ranked.find((description) => description.index === pathIndex) : undefined;
  // An isolated path dims everything off it; otherwise a selected resource
  // dims everything not on a path through it.
  const focusOriginal = isolated
    ? { nodes: new Set(isolated.path.nodeIds), links: new Set(isolated.path.linkKeys) }
    : selectedId && byId.has(selectedId) && model.pathCount > 1
      ? pathsThrough(selectedId, model.links)
      : null;
  const focus = focusOriginal && {
    nodes: new Set([...focusOriginal.nodes].map(drawn)),
    links: new Set([...focusOriginal.links].map((key) => grouped.linkOf.get(key) ?? key)),
  };
  const stages = [...new Set(model.nodes.map((node) => node.stage))];
  const kinds = new Set(model.links.map((link) => edgeStyle(link, byId.get(link.to)!)));
  const select = (id: string) =>
    setSelectedId((current) => (current === id && model.pathCount > 1 ? null : id));
  const activate = (id: string) =>
    grouped.members.has(id) ? setExpanded((current) => new Set(current).add(id)) : select(id);
  const onKey = (event: KeyboardEvent, id: string) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      activate(id);
    }
  };
  const drawnNodes = new Map(grouped.model.nodes.map((node) => [node.vertex.id, node]));
  const { positions, bands, width, height } = layout;
  const fit = () => {
    const natural = layoutAttackGraph(grouped.model).width;
    const available = canvasRef.current?.clientWidth ?? natural;
    setZoom(Math.min(1, Math.max(0.3, (available - 8) / natural)));
  };
  const stepZoom = (direction: 1 | -1) =>
    setZoom((current) => {
      const index = ZOOMS.findIndex((value) => value >= current - 0.001);
      const next = ZOOMS[Math.min(ZOOMS.length - 1, Math.max(0, index + direction))];
      return next ?? current;
    });
  const toolButton =
    'grid h-7 min-w-7 place-items-center rounded-md border border-gray-200 bg-white px-1.5 text-xs font-semibold text-gray-600 hover:bg-gray-50';
  const selectedDrawn = selected ? drawn(selected.vertex.id) : null;

  return (
    <div
      className="overflow-hidden rounded-lg border border-gray-200"
      onKeyDown={(event) => {
        if (event.key !== 'Escape') return;
        if (selectedId) {
          event.stopPropagation();
          setSelectedId(null);
        } else if (pathIndex !== null) {
          event.stopPropagation();
          setPathIndex(null);
        }
      }}
    >
      <div className="relative">
        <div className="absolute right-3 top-3 z-10 flex gap-1" role="group" aria-label="Zoom">
          {expanded.size > 0 && (
            <button type="button" className={toolButton} onClick={() => setExpanded(new Set())}>
              Regroup
            </button>
          )}
          <button
            type="button"
            className={toolButton}
            onClick={() => stepZoom(-1)}
            aria-label="Zoom out"
          >
            −
          </button>
          <button
            type="button"
            className={toolButton}
            onClick={() => stepZoom(1)}
            aria-label="Zoom in"
          >
            +
          </button>
          <button type="button" className={toolButton} onClick={fit}>
            Fit
          </button>
        </div>
        <div
          ref={canvasRef}
          className="overflow-auto bg-slate-50"
          style={{
            backgroundImage: 'radial-gradient(#dbe3ee 1px, transparent 1px)',
            backgroundSize: '18px 18px',
          }}
        >
          <svg
            viewBox={`0 0 ${width} ${height}`}
            width={width * zoom}
            height={height * zoom}
            className="block"
            role="group"
            aria-label="Attack path graph"
          >
            <defs>
              {(Object.keys(EDGE_STYLE) as EdgeStyle[]).map((key) => (
                <marker
                  key={key}
                  id={`${uid}-${key}`}
                  viewBox="0 0 10 10"
                  refX="9"
                  refY="5"
                  markerWidth="7"
                  markerHeight="7"
                  orient="auto-start-reverse"
                >
                  <path d="M0,0 L10,5 L0,10 z" fill={EDGE_STYLE[key].stroke} />
                </marker>
              ))}
            </defs>

            {bands.map((band) => {
              const { title, id, note } = bandTitle(band, accountNames);
              const collected =
                band.account !== null &&
                !band.external &&
                band.account !== 'unknown' &&
                band.account !== AWS_MANAGED_ACCOUNT;
              return (
                <g key={`band-${band.account ?? 'outside'}`} aria-hidden="true">
                  <rect
                    x="8"
                    y={band.y}
                    width={width - 16}
                    height={band.height}
                    rx="10"
                    fill={collected ? '#f5f7ff' : '#f8fafc'}
                    stroke={collected ? '#e0e7ff' : '#cbd5e1'}
                    strokeDasharray={collected ? undefined : '5 4'}
                  />
                  <text x="22" y={band.y + LANE_HEAD / 2 + 5} fontSize="12" fill="#6b7280">
                    <tspan fontWeight="600" fill="#1f2937">
                      {title}
                    </tspan>
                    {id && (
                      <tspan dx="8" fontFamily="ui-monospace, Menlo, monospace" fontSize="11">
                        {id}
                      </tspan>
                    )}
                    {note && <tspan dx="8">{note}</tspan>}
                  </text>
                </g>
              );
            })}

            {grouped.model.links.map((link) => {
              const key = `${link.from}>${link.to}`;
              const p = positions.get(link.from)!;
              const q = positions.get(link.to)!;
              const kind = edgeStyle(link, drawnNodes.get(link.to)!);
              const style = EDGE_STYLE[kind];
              const x1 = p.x + CARD_W / 2;
              const x2 = q.x - CARD_W / 2 - 2;
              const mx = (x1 + x2) / 2;
              const dim = focus && !focus.links.has(key);
              // Labels only where the reader is looking: one path, or the focused one.
              const labelled = model.pathCount <= 1 || (focus?.links.has(key) ?? false);
              const full = link.crossAccount ? `${link.label} · Cross-account` : link.label;
              const text = full.length > 26 ? `${full.slice(0, 25)}…` : full;
              const w = text.length * 6.3 + 16;
              return (
                <g key={key} opacity={dim ? 0.18 : 1} aria-hidden="true">
                  <path
                    d={`M${x1},${p.y} C${mx},${p.y} ${mx},${q.y} ${x2},${q.y}`}
                    fill="none"
                    stroke={style.stroke}
                    strokeWidth={style.width}
                    strokeDasharray={style.dash}
                    markerEnd={`url(#${uid}-${kind})`}
                  />
                  {labelled && (
                    <>
                      {text !== full && <title>{full}</title>}
                      <rect
                        x={mx - w / 2}
                        y={(p.y + q.y) / 2 - 10}
                        width={w}
                        height="20"
                        rx="10"
                        fill="#ffffff"
                        stroke={style.border}
                      />
                      <text
                        x={mx}
                        y={(p.y + q.y) / 2 + 4}
                        textAnchor="middle"
                        fontSize="10.5"
                        fontWeight="500"
                        fill={style.text}
                      >
                        {text}
                      </text>
                    </>
                  )}
                </g>
              );
            })}

            {grouped.model.nodes.map((node) => {
              const id = node.vertex.id;
              const { x, y } = positions.get(id)!;
              const group = grouped.members.get(id);
              const color = STAGE_COLOR[node.stage];
              const level = worstLevel(node.risks);
              const isSelected = id === selectedDrawn;
              const ring = isSelected
                ? '#4f46e5'
                : level === 'risk'
                  ? '#b91c1c'
                  : level === 'warn'
                    ? '#b45309'
                    : '#cbd5e1';
              const dim = focus && !focus.nodes.has(id);
              const fullName = nodeName(node.vertex);
              const left = x - CARD_W / 2;
              const top = y - CARD_H / 2;
              return (
                <g
                  key={id}
                  role="button"
                  tabIndex={0}
                  aria-pressed={group ? undefined : isSelected}
                  aria-expanded={group ? false : undefined}
                  aria-label={
                    group
                      ? `${group.length} ${typeLabel(node)} with the same links, grouped`
                      : `${typeLabel(node)} ${fullName}${node.risks.length ? `, ${node.risks.length} risk flags` : ''}`
                  }
                  opacity={dim ? 0.18 : 1}
                  className="cursor-pointer outline-none"
                  onClick={() => activate(id)}
                  onKeyDown={(event) => onKey(event, id)}
                  onFocus={() => setFocusedId(id)}
                  onBlur={() => setFocusedId((current) => (current === id ? null : current))}
                >
                  <title>
                    {group
                      ? group.map((member) => nodeName(member.vertex)).join('\n')
                      : `${fullName}${id.startsWith('arn:') ? `\n${id}` : ''}`}
                  </title>
                  {group &&
                    [6, 3].map((offset) => (
                      <rect
                        key={offset}
                        x={left + offset}
                        y={top + offset}
                        width={CARD_W}
                        height={CARD_H}
                        rx="8"
                        fill="#ffffff"
                        stroke="#e5e7eb"
                      />
                    ))}
                  {focusedId === id && (
                    <rect
                      x={left - 4}
                      y={top - 4}
                      width={CARD_W + 8}
                      height={CARD_H + 8}
                      rx="11"
                      fill="none"
                      stroke="#4f46e5"
                      strokeWidth="2"
                      strokeDasharray="4 3"
                    />
                  )}
                  <rect
                    x={left}
                    y={top}
                    width={CARD_W}
                    height={CARD_H}
                    rx="8"
                    fill={isSelected ? '#eef2ff' : '#ffffff'}
                    stroke={ring}
                    strokeWidth={isSelected || level ? 1.8 : 1.2}
                  />
                  <g transform={`translate(${left + 10},${y - 12})`}>
                    <path
                      d={ICONS[ICON_BY_LABEL[node.vertex.label] ?? 'dot']}
                      fill="none"
                      stroke={color}
                      strokeWidth="1.7"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </g>
                  <text x={left + 42} y={y - 3} fontSize="12" fontWeight="600" fill="#111827">
                    {group ? `${typeLabel(node)} ×${group.length}` : shortName(node)}
                  </text>
                  <text x={left + 42} y={y + 13} fontSize="10.5" fill="#6b7280">
                    {group ? 'Same links · click to expand' : typeLabel(node)}
                  </text>
                  {level && (
                    <g>
                      <circle
                        cx={left + CARD_W - 2}
                        cy={top + 2}
                        r="8.5"
                        fill={level === 'risk' ? '#b91c1c' : '#b45309'}
                      />
                      <text
                        x={left + CARD_W - 2}
                        y={top + 5.5}
                        textAnchor="middle"
                        fontSize="10"
                        fontWeight="700"
                        fill="#ffffff"
                      >
                        {node.risks.length}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
        <ul className="sr-only" aria-label="Path steps">
          {model.links.map((link) => (
            <li key={`sr-${link.from}->${link.to}`}>
              {nodeName(byId.get(link.from)!.vertex)} {link.label.toLowerCase()}{' '}
              {nodeName(byId.get(link.to)!.vertex)}
              {link.crossAccount ? ', cross-account' : ''}
            </li>
          ))}
        </ul>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1.5 border-t border-gray-200 bg-white px-5 py-2.5 text-xs text-gray-500">
        {stages.map((stage) => (
          <span key={stage} className="inline-flex items-center gap-1.5">
            <span
              className="h-2.5 w-2.5 rounded-full"
              style={{ backgroundColor: STAGE_COLOR[stage] }}
            />
            {STAGE_LABEL[stage]}
          </span>
        ))}
        <span className="inline-flex items-center gap-1.5">
          <span className="grid h-3.5 w-3.5 place-items-center rounded-full bg-red-700 text-[8px] font-bold text-white">
            2
          </span>
          Risk flags (count)
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-full bg-amber-700" />
          Warning only
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-4 rounded-sm border border-indigo-100 bg-indigo-50" />
          Collected account
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="h-2.5 w-4 rounded-sm border border-dashed border-slate-400 bg-slate-50" />
          Outside / not collected
        </span>
        {kinds.has('risk') && (
          <span className="inline-flex items-center gap-1.5">
            <span className="w-4 border-t-2 border-red-700" />
            Into a risky resource
          </span>
        )}
        {kinds.has('cross') && (
          <span className="inline-flex items-center gap-1.5">
            <span className="w-4 border-t-2 border-dashed border-violet-600" />
            Cross-account hop
          </span>
        )}
        {kinds.has('conditional') && (
          <span className="inline-flex items-center gap-1.5">
            <span className="w-4 border-t-2 border-amber-600" />
            Conditional grant
          </span>
        )}
        {kinds.has('deny') && (
          <span className="inline-flex items-center gap-1.5">
            <span className="w-4 border-t-2 border-dotted border-gray-400" />
            Deny (no access)
          </span>
        )}
      </div>
      <aside className="border-t border-gray-200 bg-white p-5" aria-live="polite">
        {selected ? (
          <NodeDetails
            node={selected}
            model={model}
            names={accountNames}
            onClear={model.pathCount > 1 ? () => setSelectedId(null) : undefined}
            clearLabel={isolated ? 'Back to path' : 'Show all paths'}
          />
        ) : isolated ? (
          <PathDetails
            description={isolated}
            model={model}
            onSelectNode={(id) => setSelectedId(id)}
            onClear={() => setPathIndex(null)}
          />
        ) : (
          <Overview
            model={model}
            names={accountNames}
            ranked={ranked}
            onSelect={select}
            onSelectPath={setPathIndex}
          />
        )}
      </aside>
    </div>
  );
}
