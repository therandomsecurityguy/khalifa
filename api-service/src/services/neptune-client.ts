import {
  NeptuneRuntimeClient,
  effectivePermissionId,
  type NeptuneQueryOptions,
} from '@khalifa/risk-engine';
import Gremlin from 'gremlin';
import type { GraphEdge, GraphVertex } from '../types';
import type { ReaderRow } from './secret-readers';

const graph = new Gremlin.structure.Graph();
const __ = Gremlin.process.statics;
const { P, TextP, t } = Gremlin.process;

type GraphTraversal = Gremlin.process.GraphTraversal;
type GraphTraversalSource = Gremlin.process.GraphTraversalSource;
export type NeptuneRawMap = Map<unknown, unknown> | Record<string, unknown>;

export interface NeptuneConfig {
  endpoint: string;
  region?: string;
  timeout?: number;
  maxAttempts?: number;
}

interface NeptuneClientDependencies {
  runtime?: Pick<NeptuneRuntimeClient, 'close' | 'execute'>;
}

interface QueryOptions {
  timeout?: number;
  maxAttempts?: number;
}

// Guardrails for label-rooted attack-path traversals: global dedup plus a
// per-hop expansion cap keep intermediate state bounded on dense graphs, and
// a short non-retried query budget keeps interactive requests from monopolizing
// Neptune capacity.
export const ALL_LABELS = '*';
const MAX_LABELS_PER_PAGE = 10;
// The properties the collector writes on resources of every kind, offered as
// filters when searching every label.
export const CROSS_LABEL_PROPERTIES = [
  'account_id',
  'collection_region',
  'crown_jewel',
  'data_classification',
  'env',
  'is_internet_exposed',
  'name',
  'owner',
];
// Known value sets for the cross-label properties; account_id comes from the
// account list, the rest (names, owners, regions) are typed.
const CROSS_LABEL_VALUES: Record<string, string[]> = {
  crown_jewel: ['true', 'false'],
  data_classification: ['public', 'internal', 'restricted', 'secret'],
  env: ['prod', 'staging', 'dev'],
  is_internet_exposed: ['true', 'false'],
};
const MAX_COVERAGE_RECORDS = 10_000;
const PROPERTY_SAMPLE = 500;
const MAX_PROPERTIES = 200;
const VALUE_SAMPLE = 5_000;
const MAX_VALUES = 50;
const LABEL_COUNT_TIMEOUT_MS = 120_000;
const ATTACK_PATH_TIMEOUT_MS = 5_000;
const SECRET_READERS_TIMEOUT_MS = 10_000;
const MAX_HOP_EXPANSION = 50;

const ACCESS_EDGES = ['EXPOSES', 'HAS_IAM_ROLE', 'ATTACHED_TO', 'CONTAINS', 'GRANTS'];

export type AttackPathStart = 'any' | 'internet' | 'outside' | 'resource';
export type AttackPathTarget = 'restricted' | 'crown' | 'secrets' | 'admin' | 'resource';

export interface AttackPathSearch {
  // "any" is answered by the route as an internet search plus an outside search.
  from: Exclude<AttackPathStart, 'any'>;
  to: AttackPathTarget;
  // Required when from / to is 'resource'; always a vertex id, never a label.
  fromResource?: string;
  toResource?: string;
  maxPathLength: number;
  limit: number;
  account?: string;
}

const START_PRESETS: Record<
  Exclude<AttackPathStart, 'resource' | 'any'>,
  (g: GraphTraversalSource) => GraphTraversal
> = {
  internet: (g) => g.V().has('is_internet_exposed', true),
  outside: (g) => g.V().hasLabel('IamRole').has('has_cross_account_trust', true),
};

const TARGET_PRESETS: Record<Exclude<AttackPathTarget, 'resource'>, () => GraphTraversal> = {
  restricted: () => __.has('data_classification', P.within('restricted', 'secret')),
  crown: () => __.has('crown_jewel', true),
  secrets: () => __.hasLabel('Secret'),
  admin: () => __.hasLabel('IamRole').or(__.has('is_admin_role', true), __.has('is_admin', true)),
};

function attackPathOptions(): NeptuneQueryOptions {
  return { timeoutMs: ATTACK_PATH_TIMEOUT_MS, maxAttempts: 1 };
}

export class NeptuneClient {
  private readonly runtime: Pick<NeptuneRuntimeClient, 'close' | 'execute'>;

  constructor(config: NeptuneConfig, dependencies: NeptuneClientDependencies = {}) {
    this.runtime =
      dependencies.runtime ||
      new NeptuneRuntimeClient({
        endpoint: config.endpoint,
        region: config.region,
        timeoutMs: config.timeout,
        maxAttempts: config.maxAttempts,
      });
  }

  async close(): Promise<void> {
    await this.runtime.close();
  }

  async healthCheck(timeout = 1_500): Promise<void> {
    await this.executeTraversal((g) => g.V().limit(1).count(), {
      timeoutMs: timeout,
      maxAttempts: 1,
    });
  }

  async executeStaticQuery(query: string, options: QueryOptions = {}): Promise<unknown[]> {
    if (!/^\s*g\s*\./.test(query)) throw new Error('Gremlin query must be rooted at g');
    return this.runtime.execute(query, toRuntimeOptions(options));
  }

  // Starts and targets are closed presets, never caller-supplied labels, and the
  // walk follows only relationships that grant reach, not containment.
  async searchAttackPaths(
    search: AttackPathSearch
  ): Promise<Array<{ nodes: GraphVertex[]; edges: GraphEdge[] }>> {
    const start = (g: GraphTraversalSource) =>
      search.from === 'resource' ? g.V(search.fromResource) : START_PRESETS[search.from](g);
    const target = () =>
      search.to === 'resource' ? __.hasId(search.toResource) : TARGET_PRESETS[search.to]();
    const results = await this.executeTraversal((g) => {
      const found = start(g)
        .repeat(
          __.outE(...ACCESS_EDGES)
            .inV()
            // A Deny statement still has GRANTS edges in the graph; it is not a path.
            .or(__.not(__.hasLabel('IamPolicyStatement')), __.has('effect', 'Allow'))
            .simplePath()
            .limit(MAX_HOP_EXPANSION)
        )
        .until(__.or(target(), __.loops().is(P.gte(search.maxPathLength))))
        .where(target());
      // Filter before the limit, so an account never looks empty because
      // other accounts' paths filled the page.
      const scoped = search.account
        ? found.where(__.path().unfold().has('account_id', search.account))
        : found;
      return scoped.path().by(__.elementMap()).limit(search.limit);
    }, attackPathOptions());
    return results.map(extractPath);
  }

  async listAccounts(): Promise<Array<{ id: string; name: string }>> {
    const results = await this.executeTraversal((g) =>
      g
        .V()
        .hasLabel('AwsAccount')
        .limit(1000)
        .project('id', 'name')
        .by('account_id')
        .by(__.coalesce(__.values('name'), __.constant('')))
    );
    return results
      .map((row) => ({
        id: String(getMapValue(row, 'id') ?? ''),
        name: String(getMapValue(row, 'name') ?? ''),
      }))
      .filter((account) => account.id);
  }

  // The collector writes one CollectionCoverage vertex per account, region and
  // service with the outcome of its last run.
  async listCollectionCoverage(): Promise<GraphVertex[]> {
    const results = await this.executeTraversal((g) =>
      g.V().hasLabel('CollectionCoverage').limit(MAX_COVERAGE_RECORDS).elementMap()
    );
    return results.filter(isRawMap).map(extractVertex);
  }

  // The collector writes these per account and region: one hub, detector,
  // recorder or analyzer each (a synthetic "missing" one when absent).
  async listDetectionSources(): Promise<GraphVertex[]> {
    const results = await this.executeTraversal((g) =>
      g
        .V()
        .hasLabel('SecurityHub', 'GuardDutyDetector', 'ConfigRecorder', 'AccessAnalyzer')
        .limit(MAX_COVERAGE_RECORDS)
        .elementMap()
    );
    return results.filter(isRawMap).map(extractVertex);
  }

  // How many vertices a job left under one label, and the newest timestamp
  // among them; jobs stamp their output with a run or observation time.
  async latestOutput(
    label: string,
    property: string
  ): Promise<{ count: number; latest: string | null }> {
    const results = await this.executeTraversal((g) =>
      g
        .V()
        .hasLabel(label)
        .fold()
        .project('count', 'latest')
        .by(__.count(Gremlin.process.scope.local))
        .by(__.coalesce(__.unfold().values(property).max(), __.constant('')))
    );
    const row = results[0];
    const latest = stringValue(getMapValue(row, 'latest'));
    return { count: Number(unwrapValue(getMapValue(row, 'count'))) || 0, latest: latest || null };
  }

  // How many vertices per account carry property = value (e.g. env = prod).
  async countByAccount(property: string, value: string): Promise<Record<string, number>> {
    const results = await this.executeTraversal((g) =>
      g.V().has(property, value).has('account_id').groupCount().by('account_id')
    );
    const row = results[0];
    if (!isRawMap(row)) return {};
    return Object.fromEntries(
      mapEntries(row).map(([account, count]) => [String(account), Number(unwrapValue(count))])
    );
  }

  // One row: a map of vertex label to how many vertices carry it.
  async listResourceLabels(): Promise<Array<{ label: string; count: number }>> {
    // Reads every vertex, which can outlast the default query timeout on a
    // large graph; one long attempt beats retries that each time out.
    const results = await this.executeTraversal((g) => g.V().groupCount().by(t.label), {
      timeoutMs: LABEL_COUNT_TIMEOUT_MS,
      maxAttempts: 1,
    });
    const row = results[0];
    if (!isRawMap(row)) return [];
    return mapEntries(row)
      .map(([label, count]) => ({ label: String(label), count: Number(unwrapValue(count)) }))
      .filter((entry) => entry.label && Number.isFinite(entry.count) && entry.count > 0)
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  }

  // Property names on a label, read from a sample: vertices of one label carry
  // the same collector-written keys, so the first few hundred show them all.
  async listResourceProperties(label: string): Promise<string[]> {
    if (label === ALL_LABELS) return CROSS_LABEL_PROPERTIES;
    const results = await this.executeTraversal((g) =>
      g.V().hasLabel(label).limit(PROPERTY_SAMPLE).properties().key().dedup().limit(MAX_PROPERTIES)
    );
    return results.map(stringValue).filter(Boolean).sort();
  }

  // The most common values of one property, with counts, from a sample.
  // `more` says the property has more distinct values than are listed.
  async listPropertyValues(
    label: string,
    property: string
  ): Promise<{
    values: Array<{ value: string; count: number; name?: string }>;
    more: boolean;
  }> {
    // Across every label a sample would be dominated by the biggest one, so
    // values come from fixed sets or the account list instead.
    if (label === ALL_LABELS) {
      if (property === 'account_id') {
        const accounts = await this.listAccounts();
        return {
          values: accounts
            .map((account) => ({ value: account.id, count: 0, name: account.name }))
            .sort((a, b) => (a.name || a.value).localeCompare(b.name || b.value)),
          more: false,
        };
      }
      const known = CROSS_LABEL_VALUES[property];
      return known
        ? { values: known.map((value) => ({ value, count: 0 })), more: false }
        : { values: [], more: true };
    }
    const results = await this.executeTraversal((g) =>
      g.V().hasLabel(label).has(property).limit(VALUE_SAMPLE).values(property).groupCount()
    );
    const row = results[0];
    if (!isRawMap(row)) return { values: [], more: false };
    const values = mapEntries(row)
      .map(([value, count]) => ({ value: stringValue(value), count: Number(unwrapValue(count)) }))
      .filter((entry) => entry.value !== '' && Number.isFinite(entry.count))
      .sort((a, b) => b.count - a.count || a.value.localeCompare(b.value));
    return { values: values.slice(0, MAX_VALUES), more: values.length > MAX_VALUES };
  }

  async getResource(arn: string): Promise<GraphVertex | null> {
    // Vertex ids are ARNs, so this is an index lookup rather than a property scan.
    const results = await this.executeTraversal((g) => g.V(arn).limit(1).elementMap());
    return results.length && isRawMap(results[0]) ? extractVertex(results[0]) : null;
  }

  // One index lookup for many ids; ids not in the graph are simply absent.
  async getResources(ids: string[]): Promise<GraphVertex[]> {
    if (ids.length === 0) return [];
    const results = await this.executeTraversal((g) =>
      g
        .V(...ids)
        .limit(ids.length)
        .elementMap()
    );
    return results.filter(isRawMap).map(extractVertex);
  }

  // Secrets and SecureString parameters, as a fixed set of fields: never the
  // description, tags, key ARN or policy text. The key ARN is read only to tell
  // an AWS-managed key from a customer one.
  async listSecrets(limit: number): Promise<{ items: SecretRecord[]; truncated: boolean }> {
    const [secrets, parameters, plaintext] = await Promise.all([
      this.executeTraversal((g) =>
        projectSecret(
          g
            .V()
            .hasLabel('Secret')
            .order()
            .by(t.id)
            .limit(limit + 1)
        )
      ),
      this.executeTraversal((g) =>
        projectParameter(
          g
            .V()
            .hasLabel('Parameter')
            .has('type', 'SecureString')
            .order()
            .by(t.id)
            .limit(limit + 1)
        )
      ),
      // Names only, matched below; a bounded scan of the plain-text parameters.
      this.executeTraversal((g) =>
        projectParameter(
          g
            .V()
            .hasLabel('Parameter')
            .has('type', P.within(...PLAINTEXT_TYPES))
            .order()
            .by(t.id)
            .limit(MAX_PLAINTEXT_SCAN + 1)
        )
      ),
    ]);
    const suspicious = plaintext
      .slice(0, MAX_PLAINTEXT_SCAN)
      .map(plaintextRecord)
      .filter((item) => looksLikeSecret(item.name));
    const truncated =
      secrets.length > limit ||
      parameters.length > limit ||
      plaintext.length > MAX_PLAINTEXT_SCAN ||
      suspicious.length > limit;
    const items = [
      ...secrets.slice(0, limit).map(secretRecord),
      ...parameters.slice(0, limit).map(parameterRecord),
      ...suspicious.slice(0, limit),
    ];
    return { items: items.filter((item) => item.id), truncated };
  }

  // Secrets Manager secret ids and their accounts only, for the reader counts.
  async listSecretAccounts(
    limit: number
  ): Promise<{ secrets: Array<{ id: string; accountId: string }>; truncated: boolean }> {
    const results = await this.executeTraversal((g) =>
      g
        .V()
        .hasLabel('Secret')
        .order()
        .by(t.id)
        .limit(limit + 1)
        .project('id', 'account')
        .by(t.id)
        .by(textValue('account_id'))
    );
    const secrets = results.slice(0, limit).map((row) => ({
      id: stringValue(getMapValue(row, 'id')),
      accountId: stringValue(getMapValue(row, 'account')),
    }));
    return { secrets: secrets.filter((secret) => secret.id), truncated: results.length > limit };
  }

  // One secret or SecureString parameter by id, with the same fields as the
  // list. Any other vertex is not found, so this never reads other resources.
  async getSecret(id: string): Promise<SecretRecord | null> {
    const secrets = await this.executeTraversal((g) =>
      projectSecret(g.V(id).hasLabel('Secret').limit(1))
    );
    if (secrets.length) return secretRecord(secrets[0]);
    const parameters = await this.executeTraversal((g) =>
      projectParameter(g.V(id).hasLabel('Parameter').limit(1))
    );
    const row = parameters[0];
    if (!row) return null;
    const type = stringValue(getMapValue(row, 'type'));
    if (type === 'SecureString') return parameterRecord(row);
    // A plain-text parameter only when its name is one the list shows.
    const record = plaintextRecord(row);
    return PLAINTEXT_TYPES.includes(type) && looksLikeSecret(record.name) ? record : null;
  }

  // Every statement attached to a role, user or group in one account that could
  // bear on reading a secret: Allows that grant a secret read or use NotAction,
  // and Denies. Matching against the secret happens in the caller.
  async secretReaderRows(
    accountId: string,
    limit: number
  ): Promise<{
    rows: ReaderRow[];
    truncated: boolean;
  }> {
    const results = await this.executeTraversal(
      (g) =>
        g
          .V()
          .hasLabel('IamRole', 'IamUser', 'IamGroup')
          .has('account_id', accountId)
          .as('principal')
          .out('ATTACHED_TO')
          .coalesce(
            __.hasLabel('IamPolicyDocument'),
            __.out('CONTAINS').hasLabel('IamPolicyDocument')
          )
          .as('doc')
          .out('CONTAINS')
          .hasLabel('IamPolicyStatement')
          .or(__.has('grants_secret_read', true), __.has('not_actions'), __.has('effect', 'Deny'))
          .as('statement')
          .limit(limit + 1)
          .select('principal', 'doc', 'statement')
          .by(
            __.project('id', 'label', 'name', 'admin', 'adminRole')
              .by(t.id)
              .by(t.label)
              .by(textValue('id'))
              .by(textValue('is_admin'))
              .by(textValue('is_admin_role'))
          )
          .by(
            __.project('type', 'arn', 'name')
              .by(textValue('policy_type'))
              .by(textValue('policy_arn'))
              .by(textValue('id'))
          )
          .by(
            __.project(
              'id',
              'effect',
              'actions',
              'notActions',
              'resources',
              'notResources',
              'conditions'
            )
              .by(t.id)
              .by(textValue('effect'))
              .by(textValue('actions'))
              .by(textValue('not_actions'))
              .by(textValue('resources'))
              .by(textValue('not_resources'))
              .by(textValue('conditions_json'))
          ),
      { timeoutMs: SECRET_READERS_TIMEOUT_MS, maxAttempts: 1 }
    );
    const text = (row: unknown, key: string) => stringValue(getMapValue(row, key));
    const rows = results.slice(0, limit).map((result) => {
      const principal = getMapValue(result, 'principal');
      const doc = getMapValue(result, 'doc');
      const statement = getMapValue(result, 'statement');
      return {
        principal: {
          id: text(principal, 'id'),
          label: text(principal, 'label'),
          name: text(principal, 'name'),
          admin:
            optionalBoolean(getMapValue(principal, 'admin')) === true ||
            optionalBoolean(getMapValue(principal, 'adminRole')) === true,
        },
        policy: { type: text(doc, 'type'), arn: text(doc, 'arn'), name: text(doc, 'name') },
        statement: {
          id: text(statement, 'id'),
          effect: text(statement, 'effect'),
          actions: text(statement, 'actions') || null,
          notActions: text(statement, 'notActions') || null,
          resources: text(statement, 'resources') || null,
          notResources: text(statement, 'notResources') || null,
          conditional: text(statement, 'conditions') !== '',
        },
      };
    });
    return { rows, truncated: results.length > limit };
  }

  // The two collectors write TRUSTS in opposite directions, so follow both.
  async getTrustedPrincipals(roleArn: string, limit = 5): Promise<GraphVertex[]> {
    const results = await this.executeTraversal((g) =>
      g.V(roleArn).bothE('TRUSTS').otherV().dedup().limit(limit).elementMap()
    );
    return results.filter(isRawMap).map(extractVertex);
  }

  async getNeighbors(
    arn: string,
    limit = 200
  ): Promise<{ nodes: GraphVertex[]; edges: GraphEdge[] }> {
    const results = await this.executeTraversal((g) =>
      g
        .V(arn)
        .bothE()
        .limit(limit)
        .project('edge', 'neighbor', 'from', 'to')
        .by(__.elementMap())
        .by(__.otherV().elementMap())
        .by(__.outV().id())
        .by(__.inV().id())
    );

    const nodes = new Map<string, GraphVertex>();
    const edges = new Map<string, GraphEdge>();
    for (const row of results) {
      const neighbor = getMapValue(row, 'neighbor');
      const edge = getMapValue(row, 'edge');
      const from = stringValue(getMapValue(row, 'from'));
      const to = stringValue(getMapValue(row, 'to'));
      if (!isRawMap(neighbor) || !isRawMap(edge) || !from || !to) continue;
      const parsedNode = extractVertex(neighbor);
      const parsedEdge = extractEdge(edge, from, to);
      nodes.set(parsedNode.id, parsedNode);
      edges.set(parsedEdge.id, parsedEdge);
    }
    return { nodes: [...nodes.values()], edges: [...edges.values()] };
  }

  async searchResources(options: {
    label: string;
    property?: string;
    value?: string;
    limit: number;
    nextToken?: string;
  }): Promise<{ resources: GraphVertex[]; nextToken?: string }> {
    const afterArn = options.nextToken
      ? decodeCursor(options.nextToken, 'resource-search')
      : undefined;
    const { resources, lastArn } = await this.arnPage({ ...options, afterArn });
    return {
      resources,
      nextToken: lastArn ? encodeCursor('resource-search', lastArn) : undefined,
    };
  }

  // Every label with no filter, one label at a time in name order, so each
  // query is the same per-label read as browsing that label alone. A page
  // reads at most MAX_LABELS_PER_PAGE labels and may come back short; the
  // cursor holds the label and ARN to continue from.
  async browseAllLabels(options: {
    labels: string[];
    limit: number;
    nextToken?: string;
  }): Promise<{ resources: GraphVertex[]; nextToken?: string }> {
    const labels = [...new Set(options.labels)].sort();
    let start = 0;
    let afterArn: string | undefined;
    if (options.nextToken) {
      const cursor = decodeCursor(options.nextToken, 'all-labels');
      const split = cursor.indexOf(' ');
      start = labels.indexOf(split < 0 ? cursor : cursor.slice(0, split));
      if (start < 0) throw new Error('Invalid pagination token');
      afterArn = split < 0 ? undefined : cursor.slice(split + 1);
    }

    const resources: GraphVertex[] = [];
    const end = Math.min(labels.length, start + MAX_LABELS_PER_PAGE);
    let next = start;
    while (next < end && resources.length < options.limit) {
      const page = await this.arnPage({
        label: labels[next],
        limit: options.limit - resources.length,
        afterArn: next === start ? afterArn : undefined,
      });
      resources.push(...page.resources);
      if (page.lastArn) {
        return {
          resources,
          nextToken: encodeCursor('all-labels', `${labels[next]} ${page.lastArn}`),
        };
      }
      next += 1;
    }
    return {
      resources,
      nextToken: next < labels.length ? encodeCursor('all-labels', labels[next]) : undefined,
    };
  }

  // One page of a label (or every label) in ARN order. lastArn is set only
  // when more remain after this page.
  private async arnPage(options: {
    label: string;
    property?: string;
    value?: string;
    limit: number;
    afterArn?: string;
  }): Promise<{ resources: GraphVertex[]; lastArn?: string }> {
    const results = await this.executeTraversal((g) => {
      let traversal = options.label === ALL_LABELS ? g.V() : g.V().hasLabel(options.label);
      if (options.property && options.value !== undefined) {
        traversal = traversal.has(options.property, P.within(...typedValues(options.value)));
      }
      if (options.afterArn) traversal = traversal.has('arn', P.gt(options.afterArn));
      return traversal
        .order()
        .by('arn')
        .limit(options.limit + 1)
        .elementMap();
    });
    const resources = results.filter(isRawMap).map(extractVertex);
    const page = resources.slice(0, options.limit);
    const lastArn = stringValue(page.at(-1)?.properties.arn);
    return {
      resources: page,
      lastArn: resources.length > options.limit && lastArn ? lastArn : undefined,
    };
  }

  async getEffectivePermissions(principalArn: string): Promise<Record<string, unknown> | null> {
    // Id step rather than a label scan: the derived permission vertex is keyed
    // by the deterministic `eff-perm:<principal>` id, so this is an index hit
    // instead of scanning every EffectivePermission vertex per request.
    const results = await this.executeTraversal((g) =>
      g.V(effectivePermissionId(principalArn)).limit(1).elementMap()
    );
    return results.length && isRawMap(results[0]) ? extractVertex(results[0]).properties : null;
  }

  async getEscalationPaths(filters: {
    sourceAccount?: string;
    targetRole?: string;
    escalationType?: string;
    riskLevel?: string;
  }): Promise<Record<string, unknown>[]> {
    const results = await this.executeTraversal((g) => {
      let traversal = g.V().hasLabel('EscalationPath');
      if (filters.escalationType) {
        traversal = traversal.has('escalation_type', filters.escalationType);
      }
      if (filters.riskLevel) traversal = traversal.has('risk_level', filters.riskLevel);
      if (filters.sourceAccount) {
        traversal = traversal.has('source_arn', TextP.containing(filters.sourceAccount));
      }
      if (filters.targetRole) traversal = traversal.has('target_arn', filters.targetRole);
      return traversal.limit(100).elementMap();
    });
    return results.filter(isRawMap).map((result) => {
      const vertex = extractVertex(result);
      return { id: vertex.id, ...vertex.properties };
    });
  }

  async getTrustGraph(options: {
    accountId?: string;
    limit: number;
    nextToken?: string;
  }): Promise<{ nodes: GraphVertex[]; edges: GraphEdge[]; nextToken?: string }> {
    const afterId = options.nextToken ? decodeCursor(options.nextToken, 'trust-graph') : undefined;
    const results = await this.executeTraversal((g) => {
      let traversal = g.E().hasLabel('TRUSTS');
      if (options.accountId) {
        traversal = traversal.where(
          __.or(
            __.outV().has('account_id', options.accountId),
            __.inV().has('account_id', options.accountId)
          )
        );
      }
      if (afterId) traversal = traversal.hasId(P.gt(afterId));
      return traversal
        .order()
        .by(t.id)
        .limit(options.limit + 1)
        .project('edge', 'from', 'to')
        .by(__.elementMap())
        .by(__.outV().elementMap())
        .by(__.inV().elementMap());
    });

    const nodes = new Map<string, GraphVertex>();
    const edges: GraphEdge[] = [];
    for (const row of results.slice(0, options.limit)) {
      const edge = getMapValue(row, 'edge');
      const from = getMapValue(row, 'from');
      const to = getMapValue(row, 'to');
      if (!isRawMap(edge) || !isRawMap(from) || !isRawMap(to)) continue;
      const source = extractVertex(from);
      const target = extractVertex(to);
      nodes.set(source.id, source);
      nodes.set(target.id, target);
      edges.push(extractEdge(edge, source.id, target.id));
    }
    return {
      nodes: [...nodes.values()],
      edges,
      nextToken:
        results.length > options.limit && edges.length
          ? encodeCursor('trust-graph', edges[edges.length - 1].id)
          : undefined,
    };
  }

  private async executeTraversal(
    build: (source: GraphTraversalSource) => GraphTraversal,
    options: NeptuneQueryOptions = {}
  ): Promise<unknown[]> {
    return this.runtime.execute(build(graph.traversal()).getBytecode(), options);
  }
}

// The driver keys T.id / T.label with EnumValue tokens; collector nodes also
// carry a plain `id` property (the resource's short name), which must stay a
// property or it would overwrite the ARN id. Only a plain-object result (no
// tokens possible) reads `id` / `label` from string keys.
export function extractVertex(value: NeptuneRawMap): GraphVertex {
  const properties: Record<string, unknown> = {};
  const tokensPossible = value instanceof Map;
  let id = '';
  let label = 'unknown';
  for (const [rawKey, rawValue] of mapEntries(value)) {
    const key = mapKeyName(rawKey);
    const isToken = typeof rawKey !== 'string' || !tokensPossible;
    if (isToken && key === 'id') id = stringValue(rawValue);
    else if (isToken && key === 'label') label = stringValue(rawValue) || 'unknown';
    else properties[key] = unwrapValue(rawValue);
  }
  return { id, label, properties };
}

function extractEdge(value: NeptuneRawMap, from: string, to: string): GraphEdge {
  const parsed = extractVertex(value);
  return {
    id: parsed.id,
    label: parsed.label === 'unknown' ? 'CONNECTED' : parsed.label,
    from,
    to,
    properties: parsed.properties,
  };
}

function extractPath(value: unknown): { nodes: GraphVertex[]; edges: GraphEdge[] } {
  const objects =
    value && typeof value === 'object' && 'objects' in value
      ? (value as { objects: unknown }).objects
      : [];
  const items = Array.isArray(objects) ? objects : [];
  const nodes = items
    .filter((_, index) => index % 2 === 0)
    .filter(isRawMap)
    .map(extractVertex);
  const edges = items
    .filter((_, index) => index % 2 === 1)
    .filter(isRawMap)
    .map((edge, index) => extractEdge(edge, nodes[index]?.id || '', nodes[index + 1]?.id || ''));
  return { nodes, edges };
}

export interface SecretShare {
  anyone: boolean;
  orgRestricted: boolean;
  named: number;
  collected: number;
}

export interface SecretRecord {
  // ssm-plaintext: a String parameter whose name looks like a credential.
  kind: 'secrets-manager' | 'ssm-parameter' | 'ssm-plaintext';
  id: string;
  name: string;
  accountId: string;
  customerManagedKey: boolean;
  // From the resource's tags; null when untagged.
  env: string | null;
  owner: string | null;
  rotationEnabled: boolean | null;
  lastRotated: string | null;
  createdAt: string | null;
  // AWS records last access to the day; null when never read.
  lastAccessed: string | null;
  lastModified: string | null;
  collectionRestricted: boolean;
  shares: SecretShare[];
  // Distinct collected accounts the shares name.
  sharedAccounts: number;
}

// The cross-account Allow statements of a secret's resource policy, read the
// way RULE-010, RULE-032 and RULE-033 read them.
function shareStatements(): GraphTraversal {
  return __.outE('HAS_RESOURCE_POLICY')
    .inV()
    .hasLabel('IamPolicyDocument')
    .outE('CONTAINS')
    .inV()
    .hasLabel('IamPolicyStatement')
    .has('effect', 'Allow')
    .has('has_cross_account_principal', true)
    .has('principal_account_count');
}

function secretShares(): GraphTraversal {
  return shareStatements()
    .project('anyone', 'org', 'named', 'collected')
    .by(__.coalesce(__.values('principal_is_anyone'), __.constant(false)))
    .by(__.coalesce(__.values('principal_org_restricted'), __.constant(false)))
    .by(__.values('principal_account_count'))
    .by(__.out('SHARES_WITH').hasLabel('AwsAccount').count())
    .fold();
}

// Distinct collected accounts across every statement, counted in the graph so
// no account id leaves it.
function sharedAccountCount(): GraphTraversal {
  return shareStatements().out('SHARES_WITH').hasLabel('AwsAccount').dedup().count();
}

function textValue(key: string): GraphTraversal {
  return __.coalesce(__.values(key), __.constant(''));
}

function projectSecret(traversal: GraphTraversal): GraphTraversal {
  return traversal
    .project(
      'id',
      'name',
      'account',
      'rotation',
      'rotated',
      'created',
      'accessed',
      'key',
      'restricted',
      'shares',
      'sharedAccounts',
      'env',
      'owner'
    )
    .by(t.id)
    .by(textValue('name'))
    .by(textValue('account_id'))
    .by(textValue('rotation_enabled'))
    .by(textValue('last_rotated'))
    .by(textValue('created_at'))
    .by(textValue('last_accessed'))
    .by(textValue('kms_key_id'))
    .by(textValue('collection_restricted'))
    .by(secretShares())
    .by(sharedAccountCount())
    .by(textValue('env'))
    .by(textValue('owner'));
}

function projectParameter(traversal: GraphTraversal): GraphTraversal {
  return traversal
    .project('id', 'name', 'account', 'modified', 'key', 'type', 'env', 'owner')
    .by(t.id)
    .by(textValue('name'))
    .by(textValue('account_id'))
    .by(textValue('last_modified'))
    .by(textValue('key_id'))
    .by(textValue('type'))
    .by(textValue('env'))
    .by(textValue('owner'));
}

const PLAINTEXT_TYPES = ['String', 'StringList'];
const MAX_PLAINTEXT_SCAN = 20_000;
// Names people give credentials. Matched on the name only; values are never read.
const SECRET_NAME = /(password|passwd|secret|token|api[-_.]?key|private[-_.]?key|credential)/i;

export function looksLikeSecret(name: string): boolean {
  return SECRET_NAME.test(name);
}

function plaintextRecord(row: unknown): SecretRecord {
  return { ...parameterRecord(row), kind: 'ssm-plaintext', customerManagedKey: false };
}

function secretRecord(row: unknown): SecretRecord {
  return {
    kind: 'secrets-manager',
    ...commonSecretFields(row),
    rotationEnabled: optionalBoolean(getMapValue(row, 'rotation')),
    lastRotated: stringValue(getMapValue(row, 'rotated')) || null,
    createdAt: stringValue(getMapValue(row, 'created')) || null,
    lastAccessed: stringValue(getMapValue(row, 'accessed')) || null,
    lastModified: null,
    collectionRestricted: optionalBoolean(getMapValue(row, 'restricted')) === true,
    sharedAccounts: Number(unwrapValue(getMapValue(row, 'sharedAccounts'))) || 0,
    shares: listValue(getMapValue(row, 'shares')).map((share) => ({
      anyone: optionalBoolean(getMapValue(share, 'anyone')) === true,
      orgRestricted: optionalBoolean(getMapValue(share, 'org')) === true,
      named: Number(unwrapValue(getMapValue(share, 'named'))) || 0,
      collected: Number(unwrapValue(getMapValue(share, 'collected'))) || 0,
    })),
  };
}

function parameterRecord(row: unknown): SecretRecord {
  return {
    kind: 'ssm-parameter',
    ...commonSecretFields(row),
    rotationEnabled: null,
    lastRotated: null,
    createdAt: null,
    lastAccessed: null,
    lastModified: stringValue(getMapValue(row, 'modified')) || null,
    collectionRestricted: false,
    sharedAccounts: 0,
    shares: [],
  };
}

// No key, or an alias/aws/ key, is the service's AWS-managed key.
function isCustomerManagedKey(key: string): boolean {
  return key !== '' && !key.includes('alias/aws/');
}

function commonSecretFields(row: unknown) {
  return {
    id: stringValue(getMapValue(row, 'id')),
    name: stringValue(getMapValue(row, 'name')),
    accountId: stringValue(getMapValue(row, 'account')),
    customerManagedKey: isCustomerManagedKey(stringValue(getMapValue(row, 'key'))),
    env: stringValue(getMapValue(row, 'env')) || null,
    owner: stringValue(getMapValue(row, 'owner')) || null,
  };
}

function optionalBoolean(value: unknown): boolean | null {
  const unwrapped = unwrapValue(value);
  if (unwrapped === true || unwrapped === 'true') return true;
  if (unwrapped === false || unwrapped === 'false') return false;
  return null;
}

// A folded list stays a list even with one entry, unlike unwrapValue.
function listValue(value: unknown): unknown[] {
  const list = value && typeof value === 'object' && 'value' in value ? value.value : value;
  return Array.isArray(list) ? list.filter(isRawMap) : [];
}

function isRawMap(value: unknown): value is NeptuneRawMap {
  return value instanceof Map || (typeof value === 'object' && value !== null);
}

function getMapValue(value: unknown, key: string): unknown {
  if (value instanceof Map) return value.get(key);
  return typeof value === 'object' && value !== null
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

function mapEntries(value: NeptuneRawMap): Array<[unknown, unknown]> {
  return value instanceof Map ? [...value.entries()] : Object.entries(value);
}

function mapKeyName(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object' && 'elementName' in value) {
    return String((value as { elementName: unknown }).elementName).toLowerCase();
  }
  return String(value);
}

function unwrapValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    const values = value.map(unwrapValue);
    return values.length === 1 ? values[0] : values;
  }
  if (value instanceof Map) {
    return Object.fromEntries(
      [...value.entries()].map(([key, item]) => [mapKeyName(key), unwrapValue(item)])
    );
  }
  if (value && typeof value === 'object' && 'value' in value) {
    return unwrapValue((value as { value: unknown }).value);
  }
  return value;
}

function stringValue(value: unknown): string {
  const unwrapped = unwrapValue(value);
  return unwrapped === undefined || unwrapped === null ? '' : String(unwrapped);
}

// A filter value arrives as text, but the collector writes booleans and
// numbers as such; match the text and its typed form.
function typedValues(value: string): unknown[] {
  if (value === 'true') return [value, true];
  if (value === 'false') return [value, false];
  if (/^-?\d+(\.\d+)?$/.test(value) && Number.isSafeInteger(Math.trunc(Number(value)))) {
    return [value, Number(value)];
  }
  return [value];
}

function encodeCursor(kind: string, value: string): string {
  return Buffer.from(JSON.stringify({ kind, value })).toString('base64url');
}

function decodeCursor(token: string, expectedKind: string): string {
  if (token.length > 2_048) throw new Error('Invalid pagination token');
  try {
    const value = JSON.parse(Buffer.from(token, 'base64url').toString('utf8')) as {
      kind?: unknown;
      value?: unknown;
    };
    if (value.kind !== expectedKind || typeof value.value !== 'string') throw new Error();
    return value.value;
  } catch {
    throw new Error('Invalid pagination token');
  }
}

function toRuntimeOptions(options: QueryOptions): NeptuneQueryOptions {
  return { timeoutMs: options.timeout, maxAttempts: options.maxAttempts };
}
