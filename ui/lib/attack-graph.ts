import type { AttackPathEntry, GraphEdge, GraphVertex, Severity } from '@/types';
import { nodeName } from '@/lib/graph-labels';

export type Stage =
  'entry' | 'external' | 'compute' | 'identity' | 'permission' | 'data' | 'finding';
export type RiskFlag = { level: 'risk' | 'warn'; text: string };

export interface Permission {
  policy: string;
  statement: string;
  effect: 'Allow' | 'Deny';
  actions?: string;
  notActions?: string;
  resources?: string;
  conditions?: string;
}

export interface GraphNode {
  vertex: GraphVertex;
  stage: Stage;
  // null for the synthetic Internet node, which belongs to no account.
  account: string | null;
  external: boolean;
  risks: RiskFlag[];
  // Policy statements folded into this principal when policy hops collapse.
  permissions: Permission[];
}

export interface GraphLink {
  from: string;
  to: string;
  label: string;
  crossAccount: boolean;
  // How a collapsed policy hop grants reach; plain relationships are 'access'.
  kind: GrantKind;
  via?: string;
}

export type GrantKind = 'access' | 'conditional' | 'deny';
const GRANT_STRENGTH: Record<GrantKind, number> = { deny: 0, conditional: 1, access: 2 };

export interface PathSummary {
  startId: string;
  // Node ids and link keys after policy collapse, entries included.
  nodeIds: string[];
  linkKeys: string[];
  score?: number;
  severity?: Severity;
}

export interface AttackGraphModel {
  nodes: GraphNode[];
  links: GraphLink[];
  pathCount: number;
  paths: PathSummary[];
}

export interface AttackPathInput {
  nodes: GraphVertex[];
  edges: GraphEdge[];
  score?: number;
  severity?: Severity;
}

export const INTERNET_ID = 'khalifa:internet';
export const UNRESOLVED_ACCOUNT = 'unresolved';
// AWS-managed policies are one shared vertex for every account; their stored
// account_id is whichever account collected them last, so it is ignored.
export const AWS_MANAGED_ACCOUNT = 'aws-managed';
const AWS_MANAGED_ID = /^arn:aws[\w-]*:iam::aws:/;
const ACCOUNT_ID = /^\d{12}$/;
const ACRONYMS = new Set(['iam', 's3', 'ec2', 'kms', 'rds', 'eks', 'sg']);
const POLICY_LABELS = new Set(['IamPolicyDocument', 'IamPolicy']);

const STAGE_BY_LABEL: Record<string, Stage> = {
  Internet: 'entry',
  ExternalAccount: 'external',
  AwsAccount: 'external',
  Ec2Instance: 'compute',
  EC2Instance: 'compute',
  LambdaFunction: 'compute',
  EksCluster: 'compute',
  LoadBalancer: 'compute',
  InternetGateway: 'compute',
  SecurityGroup: 'compute',
  SecurityGroupRule: 'compute',
  NetworkInterface: 'compute',
  IamRole: 'identity',
  IamUser: 'identity',
  IamGroup: 'identity',
  AccessKey: 'identity',
  IamPolicy: 'permission',
  IamPolicyDocument: 'permission',
  IamPolicyStatement: 'permission',
  S3Bucket: 'data',
  RdsInstance: 'data',
  Secret: 'data',
  DynamoDBTable: 'data',
  RedshiftCluster: 'data',
  SecurityHubFinding: 'finding',
  DataClassificationFinding: 'finding',
  CloudTrailAnomaly: 'finding',
};

function stageOf(vertex: GraphVertex): Stage {
  return STAGE_BY_LABEL[vertex.label] ?? 'compute';
}

// Flags come only from properties the collector writes; nothing is inferred.
export function riskFlags(vertex: GraphVertex): RiskFlag[] {
  const p = vertex.properties ?? {};
  const flags: RiskFlag[] = [];
  const add = (level: RiskFlag['level'], text: string) => flags.push({ level, text });
  if (p.is_internet_exposed === true) add('risk', 'Internet exposed');
  if (p.is_publicly_accessible === true) add('risk', 'Publicly accessible');
  if (p.endpoint_world_open === true) add('risk', 'API endpoint open to the world');
  if (p.is_world_open === true) add('risk', 'Open to 0.0.0.0/0');
  if (p.metadata_http_tokens === 'optional') add('warn', 'IMDSv1');
  if (p.is_admin === true || p.is_admin_role === true) add('risk', 'Admin');
  if (p.has_cross_account_trust === true) add('warn', 'Cross-account trust');
  if (p.has_wildcard_action === true) add('risk', 'Wildcard action');
  if (p.has_wildcard_resource === true) add('risk', 'Wildcard resource');
  if (p.grants_secret_read === true) add('warn', 'Reads secrets');
  if (p.password_enabled === true && p.mfa_enabled === false) add('risk', 'Console without MFA');
  if (typeof p.key_age_days === 'number' && p.key_age_days > 90)
    add('warn', 'Key older than 90 days');
  if (p.data_classification === 'secret') add('risk', 'Secret data');
  if (p.data_classification === 'restricted') add('risk', 'Restricted data');
  if (p.crown_jewel === true) add('risk', 'Crown jewel');
  return flags;
}

function accountOf(vertex: GraphVertex): string | null {
  if (vertex.id === INTERNET_ID || vertex.label === 'Internet') return null;
  if (vertex.properties?.unresolved === true) return UNRESOLVED_ACCOUNT;
  if (AWS_MANAGED_ID.test(vertex.id)) return AWS_MANAGED_ACCOUNT;
  const account = vertex.properties?.account_id ?? vertex.properties?.external_account_id;
  if (typeof account === 'string' && account) return account;
  const match = /^arn:aws[\w-]*:[^:]*:[^:]*:(\d{12}):/.exec(vertex.id);
  return match ? match[1] : 'unknown';
}

// Rules walk some edges backwards (access key to user, statement to policy) and
// issue paths keep that order, so a step against an edge's direction reads as
// its inverse. Each edge type is known by the vertex labels it starts from.
const EDGE_SOURCES: Record<string, string[]> = {
  HAS_ACCESS_KEY: ['IamUser'],
  ATTACHED_TO: ['IamRole', 'IamUser', 'IamGroup', 'NetworkInterface', 'InternetGateway'],
  HAS_IAM_ROLE: ['Ec2Instance', 'LambdaFunction'],
  GRANTS: ['IamPolicyStatement'],
  DETECTS_ON: ['SecurityHubFinding', 'GuardDutyFinding'],
  CLASSIFIES: ['DataClassificationFinding'],
  PART_OF: ['SecurityGroupRule'],
  PROTECTS: ['SecurityGroup'],
  HAS_RESOURCE_POLICY: ['Secret'],
};
const CONTAINS_RANK: Record<string, number> = {
  AwsAccount: 4,
  Vpc: 3,
  IamPolicy: 3,
  Subnet: 2,
  IamPolicyDocument: 2,
  IamPolicyStatement: 1,
};
const INVERSE_LABEL: Record<string, string> = {
  HAS_ACCESS_KEY: 'Access key of',
  ATTACHED_TO: 'Has attached',
  HAS_IAM_ROLE: 'Role of',
  GRANTS: 'Granted by',
  DETECTS_ON: 'Detected by',
  CLASSIFIES: 'Classified by',
  PART_OF: 'Includes',
  PROTECTS: 'Protected by',
  HAS_RESOURCE_POLICY: 'Resource policy of',
  CONTAINS: 'In',
};

export function walkedBackwards(label: string, from: GraphVertex, to: GraphVertex): boolean {
  if (label === 'CONTAINS') {
    const [a, b] = [CONTAINS_RANK[from.label], CONTAINS_RANK[to.label]];
    return a !== undefined && b !== undefined && a < b;
  }
  const sources = EDGE_SOURCES[label];
  return !!sources && !sources.includes(from.label) && sources.includes(to.label);
}

export function edgeLabel(label: string, backwards = false): string {
  if (backwards && INVERSE_LABEL[label]) return INVERSE_LABEL[label];
  if (label === 'CAN_ASSUME') return 'Can assume';
  return label
    .toLowerCase()
    .split(/[_-]+/)
    .filter(Boolean)
    .map((word, index) =>
      ACRONYMS.has(word)
        ? word.toUpperCase()
        : index === 0
          ? word.charAt(0).toUpperCase() + word.slice(1)
          : word
    )
    .join(' ');
}

function listItems(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value !== 'string' || !value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.map(String);
  } catch {
    // Not JSON; treat as a comma-separated list.
  }
  return value.split(',').map((item) => item.trim());
}

function permissionLabel(statement: GraphVertex): string {
  const props = statement.properties ?? {};
  const verb = props.effect === 'Deny' ? 'Denies' : 'Allows';
  const items = listItems(props.actions);
  const notItems = listItems(props.not_actions);
  const what = items.length
    ? ` ${items[0]}${items.length > 1 ? ` +${items.length - 1}` : ''}`
    : notItems.length
      ? ' all but listed actions'
      : '';
  return `${verb}${what}${props.conditions_json ? ' (conditional)' : ''}`;
}

function grantKind(statement: GraphVertex): GrantKind {
  if (statement.properties?.effect === 'Deny') return 'deny';
  return statement.properties?.conditions_json ? 'conditional' : 'access';
}

function mergeFlags(into: RiskFlag[], extra: RiskFlag[]): void {
  for (const flag of extra) {
    if (!into.some((existing) => existing.text === flag.text)) into.push(flag);
  }
}

class GraphBuilder {
  private readonly nodes = new Map<string, GraphNode>();
  private readonly links = new Map<string, GraphLink>();
  private readonly paths: PathSummary[] = [];
  // Statements behind each collapsed link, so two policies to one target say so.
  private readonly statementsByLink = new Map<string, Map<string, GrantKind>>();

  node(vertex: GraphVertex): GraphNode {
    let node = this.nodes.get(vertex.id);
    if (!node) {
      node = {
        vertex,
        stage: stageOf(vertex),
        account: accountOf(vertex),
        external: vertex.label === 'ExternalAccount',
        risks: riskFlags(vertex),
        permissions: [],
      };
      this.nodes.set(vertex.id, node);
    }
    return node;
  }

  link(
    from: GraphNode,
    to: GraphNode,
    label: string,
    via?: string,
    grant?: { statementId: string; kind: GrantKind }
  ): string {
    const key = `${from.vertex.id}>${to.vertex.id}`;
    if (grant) {
      const statements = this.statementsByLink.get(key) ?? new Map<string, GrantKind>();
      statements.set(grant.statementId, grant.kind);
      this.statementsByLink.set(key, statements);
      const existing = this.links.get(key);
      if (existing && statements.size > 1) {
        // The strongest grant decides how the merged hop is drawn.
        existing.kind = [...statements.values()].reduce((a, b) =>
          GRANT_STRENGTH[b] > GRANT_STRENGTH[a] ? b : a
        );
        existing.label =
          existing.kind === 'deny'
            ? `Denies (${statements.size} statements)`
            : `Allows ${statements.size} statements`;
        existing.via = undefined;
        return key;
      }
    }
    if (this.links.has(key)) return key;
    this.links.set(key, {
      from: from.vertex.id,
      to: to.vertex.id,
      label,
      // Only two known, different account IDs make a hop cross-account.
      crossAccount:
        ACCOUNT_ID.test(from.account ?? '') &&
        ACCOUNT_ID.test(to.account ?? '') &&
        from.account !== to.account,
      kind: grant?.kind ?? 'access',
      via,
    });
    return key;
  }

  private absorb(principal: GraphNode, policy: GraphVertex, statement: GraphVertex): void {
    const props = statement.properties ?? {};
    const permission: Permission = {
      policy: nodeName(policy),
      statement: nodeName(statement),
      effect: props.effect === 'Deny' ? 'Deny' : 'Allow',
      actions: listItems(props.actions).join(', ') || undefined,
      notActions: listItems(props.not_actions).join(', ') || undefined,
      resources: listItems(props.resources).join(', ') || undefined,
      conditions: typeof props.conditions_json === 'string' ? props.conditions_json : undefined,
    };
    const known = principal.permissions.some(
      (p) => p.policy === permission.policy && p.statement === permission.statement
    );
    if (!known) principal.permissions.push(permission);
    mergeFlags(principal.risks, riskFlags(statement));
  }

  // Principal → policy [→ document] → statement (→ granted resource) becomes one
  // "Allows …" hop. Managed policies carry the extra document vertex; inline ones don't.
  addPath(path: AttackPathInput): GraphNode | undefined {
    const vertices = path.nodes;
    if (vertices.length === 0) return undefined;
    const edgeBetween = (a: GraphVertex, b: GraphVertex) =>
      path.edges.find((edge) => edge.from === a.id && edge.to === b.id)?.label ?? 'CONNECTED';
    const start = this.node(vertices[0]);
    const nodeIds = [start.vertex.id];
    const linkKeys: string[] = [];
    let current = start;
    let i = 0;
    while (i < vertices.length - 1) {
      const next = vertices[i + 1];
      let j = i + 1;
      while (POLICY_LABELS.has(vertices[j]?.label)) j += 1;
      const statement = vertices[j];
      if (j > i + 1 && statement?.label === 'IamPolicyStatement') {
        this.absorb(current, next, statement);
        const granted = vertices[j + 1];
        if (granted) {
          const target = this.node(granted);
          linkKeys.push(
            this.link(current, target, permissionLabel(statement), nodeName(next), {
              statementId: statement.id,
              kind: grantKind(statement),
            })
          );
          nodeIds.push(target.vertex.id);
          current = target;
          i = j + 1;
        } else {
          i = j;
        }
        continue;
      }
      const target = this.node(next);
      const raw = edgeBetween(vertices[i], next);
      const label = edgeLabel(raw, walkedBackwards(raw, vertices[i], next));
      linkKeys.push(this.link(current, target, label));
      nodeIds.push(target.vertex.id);
      current = target;
      i += 1;
    }
    this.paths.push({
      startId: start.vertex.id,
      nodeIds,
      linkKeys,
      score: path.score,
      severity: path.severity,
    });
    return start;
  }

  // Entry nodes and links join every path that starts at `start`.
  addEntry(start: GraphNode, entry: AttackPathEntry): void {
    const added: Array<{ nodeId: string; linkKey: string }> = [];
    if (entry.kind === 'internet') {
      const internet = this.node({
        id: INTERNET_ID,
        label: 'Internet',
        properties: { name: 'Public internet' },
      });
      added.push({ nodeId: internet.vertex.id, linkKey: this.link(internet, start, 'Exposes') });
    } else if (entry.principals.length === 0) {
      const unresolved = this.node({
        id: `khalifa:unresolved-trust:${start.vertex.id}`,
        label: 'ExternalAccount',
        properties: { name: 'Trusted outside account', unresolved: true },
      });
      added.push({
        nodeId: unresolved.vertex.id,
        linkKey: this.link(unresolved, start, 'Can assume'),
      });
    } else {
      for (const principal of entry.principals) {
        const node = this.node(principal);
        added.push({ nodeId: node.vertex.id, linkKey: this.link(node, start, 'Can assume') });
      }
    }
    for (const summary of this.paths) {
      if (summary.startId !== start.vertex.id) continue;
      for (const { nodeId, linkKey } of added) {
        summary.nodeIds.unshift(nodeId);
        summary.linkKeys.unshift(linkKey);
      }
    }
  }

  build(): AttackGraphModel {
    return {
      nodes: [...this.nodes.values()],
      links: [...this.links.values()],
      pathCount: this.paths.length,
      paths: this.paths,
    };
  }
}

// Merges one or more paths into one graph; entries are keyed by each path's first vertex id.
export function buildAttackGraph(
  paths: AttackPathInput[],
  entries: Record<string, AttackPathEntry> = {}
): AttackGraphModel {
  const builder = new GraphBuilder();
  const starts = new Map<string, GraphNode>();
  for (const path of paths) {
    const start = builder.addPath(path);
    if (start) starts.set(start.vertex.id, start);
  }
  for (const [id, start] of starts) {
    const entry = entries[id];
    if (entry) builder.addEntry(start, entry);
  }
  return builder.build();
}

// Intermediate nodes ranked by how many paths run through them: fixing the
// top one closes the most paths at once.
export function chokePoints(
  model: AttackGraphModel,
  limit = 5
): Array<{ node: GraphNode; paths: number }> {
  const hasIn = new Set(model.links.map((link) => link.to));
  const hasOut = new Set(model.links.map((link) => link.from));
  return model.nodes
    .filter((node) => hasIn.has(node.vertex.id) && hasOut.has(node.vertex.id))
    .map((node) => ({
      node,
      paths: model.paths.filter((path) => path.nodeIds.includes(node.vertex.id)).length,
    }))
    .filter((entry) => entry.paths > 0)
    .sort(
      (a, b) => b.paths - a.paths || nodeName(a.node.vertex).localeCompare(nodeName(b.node.vertex))
    )
    .slice(0, limit);
}

export type EntryKind = 'internet' | 'outside' | 'internal';

export interface PathDescription {
  path: PathSummary;
  // Position in model.paths, which is what the graph isolates by.
  index: number;
  entry: EntryKind;
  start: GraphNode;
  target: GraphNode;
  hops: number;
  risks: RiskFlag[];
}

// Each path with where it starts, where it ends, and every distinct risk flag
// along the way, in the order given (the API returns them worst first).
export function describePaths(model: AttackGraphModel): PathDescription[] {
  const byId = new Map(model.nodes.map((node) => [node.vertex.id, node]));
  return model.paths.map((path, index) => {
    const nodes = path.nodeIds
      .map((id) => byId.get(id))
      .filter((node): node is GraphNode => node !== undefined);
    const start = nodes[0];
    const entry: EntryKind =
      start.vertex.id === INTERNET_ID
        ? 'internet'
        : start.external || start.account === UNRESOLVED_ACCOUNT
          ? 'outside'
          : 'internal';
    const risks: RiskFlag[] = [];
    for (const node of nodes) mergeFlags(risks, node.risks);
    return {
      path,
      index,
      entry,
      start,
      target: nodes[nodes.length - 1],
      hops: path.linkKeys.length,
      risks,
    };
  });
}

export interface Band {
  account: string | null;
  external: boolean;
  y: number;
  height: number;
}

export interface GraphLayout {
  positions: Map<string, { x: number; y: number }>;
  bands: Band[];
  width: number;
  height: number;
}

export const CARD_W = 200;
export const CARD_H = 48;
const ROW = 64;
const STEP = 320;
// Widest column spacing when the graph stretches to fill a wide screen.
const MAX_STEP = 520;
const PAD = 24;
export const LANE_HEAD = 30;
const BAND_GAP = 12;

export interface GroupedGraph {
  model: AttackGraphModel;
  // Member id -> drawn id, for members of collapsed groups only.
  groupOf: Map<string, string>;
  // Drawn id -> the members it stands for.
  members: Map<string, GraphNode[]>;
  // Original link key -> drawn link key.
  linkOf: Map<string, string>;
}

// Nodes in one lane with the same type, risks and identical links draw as one
// card. Only exact duplicates merge, so a group never implies reach a member lacks.
export function groupSiblings(
  model: AttackGraphModel,
  expanded: ReadonlySet<string> = new Set()
): GroupedGraph {
  const sig = (link: GraphLink, other: string) =>
    `${other}|${link.label}|${link.kind}|${link.crossAccount}`;
  const buckets = new Map<string, GraphNode[]>();
  for (const node of model.nodes) {
    const id = node.vertex.id;
    if (id === INTERNET_ID) continue;
    const key = JSON.stringify([
      node.account,
      node.external,
      node.vertex.label,
      node.stage,
      node.risks.map((flag) => `${flag.level}:${flag.text}`).sort(),
      model.links
        .filter((l) => l.to === id)
        .map((l) => sig(l, l.from))
        .sort(),
      model.links
        .filter((l) => l.from === id)
        .map((l) => sig(l, l.to))
        .sort(),
    ]);
    buckets.set(key, [...(buckets.get(key) ?? []), node]);
  }

  const groupOf = new Map<string, string>();
  const members = new Map<string, GraphNode[]>();
  for (const group of buckets.values()) {
    const drawn = group[0].vertex.id;
    if (group.length < 2 || expanded.has(drawn)) continue;
    members.set(drawn, group);
    for (const node of group) groupOf.set(node.vertex.id, drawn);
  }

  const to = (id: string) => groupOf.get(id) ?? id;
  const linkOf = new Map<string, string>();
  const links = new Map<string, GraphLink>();
  for (const link of model.links) {
    const mapped = { ...link, from: to(link.from), to: to(link.to) };
    const key = `${mapped.from}>${mapped.to}`;
    linkOf.set(`${link.from}>${link.to}`, key);
    if (!links.has(key)) links.set(key, mapped);
  }
  const unique = (ids: string[]) => [...new Set(ids)];
  return {
    model: {
      ...model,
      nodes: model.nodes.filter((node) => to(node.vertex.id) === node.vertex.id),
      links: [...links.values()],
      paths: model.paths.map((path) => ({
        ...path,
        startId: to(path.startId),
        nodeIds: unique(path.nodeIds.map(to)),
        linkKeys: unique(path.linkKeys.map((key) => linkOf.get(key) ?? key)),
      })),
    },
    groupOf,
    members,
    linkOf,
  };
}

// Column = longest hop distance from an entry. One horizontal lane per account:
// the internet first, then outside accounts, then collected accounts.
export function layoutAttackGraph(model: AttackGraphModel, minWidth = 0): GraphLayout {
  const layer = new Map(model.nodes.map((node) => [node.vertex.id, 0]));
  for (let pass = 0; pass < model.nodes.length; pass++) {
    let changed = false;
    for (const link of model.links) {
      const next = (layer.get(link.from) ?? 0) + 1;
      if (next > (layer.get(link.to) ?? 0)) {
        layer.set(link.to, next);
        changed = true;
      }
    }
    if (!changed) break;
  }

  const rank = (node: GraphNode) => (node.account === null ? 0 : node.external ? 1 : 2);
  const ordered = [...model.nodes].sort(
    (a, b) => rank(a) - rank(b) || (layer.get(a.vertex.id) ?? 0) - (layer.get(b.vertex.id) ?? 0)
  );
  const bandKeys: Array<{ account: string | null; external: boolean }> = [];
  for (const node of ordered) {
    if (!bandKeys.some((band) => band.account === node.account)) {
      bandKeys.push({ account: node.account, external: node.external });
    }
  }

  // Group by band and column; band heights depend only on the largest column.
  const cells = new Map<string, GraphNode[]>();
  let maxLayer = 0;
  for (const node of ordered) {
    const column = layer.get(node.vertex.id) ?? 0;
    maxLayer = Math.max(maxLayer, column);
    const key = `${node.account}|${column}`;
    cells.set(key, [...(cells.get(key) ?? []), node]);
  }
  // Spread columns into spare width so lanes reach the right edge.
  const spare = maxLayer > 0 ? (minWidth - PAD * 2 - CARD_W) / maxLayer : 0;
  const step = Math.min(MAX_STEP, Math.max(STEP, spare));
  const bands: Band[] = [];
  let y = 12;
  for (const band of bandKeys) {
    let rows = 1;
    for (let column = 0; column <= maxLayer; column++) {
      rows = Math.max(rows, cells.get(`${band.account}|${column}`)?.length ?? 0);
    }
    const height = LANE_HEAD + rows * ROW;
    bands.push({ account: band.account, external: band.external, y, height });
    y += height + BAND_GAP;
  }

  // Left to right, order each cell by the mean height of its incoming links
  // (barycenter), which keeps edges from crossing.
  const positions = new Map<string, { x: number; y: number }>();
  const incoming = (id: string) =>
    model.links
      .filter((link) => link.to === id)
      .map((link) => positions.get(link.from)?.y)
      .filter((value): value is number => value !== undefined);
  for (let column = 0; column <= maxLayer; column++) {
    for (const band of bands) {
      const cell = cells.get(`${band.account}|${column}`) ?? [];
      const center = (node: GraphNode) => {
        const ys = incoming(node.vertex.id);
        return ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : Number.POSITIVE_INFINITY;
      };
      const sorted = [...cell].sort((a, b) => center(a) - center(b));
      sorted.forEach((node, slot) => {
        positions.set(node.vertex.id, {
          x: PAD + column * step + CARD_W / 2,
          y: band.y + LANE_HEAD + slot * ROW + ROW / 2,
        });
      });
    }
  }
  return {
    positions,
    bands,
    width: Math.max(minWidth, PAD * 2 + maxLayer * step + CARD_W),
    height: y,
  };
}
