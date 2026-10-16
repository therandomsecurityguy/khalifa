import { getEnabledRules } from './rules';
import { computeRiskScore, getRemediationHint, riskInputFromPath } from './scoring';
import { DynamoDBIssueRepository, SYSTEM_ACTOR, type IssueKey } from './issue-repository';
import {
  createNeptuneRuntimeClient,
  isNeptuneRetryable,
  type NeptuneQueryClient,
} from './neptune-client';
import type {
  RiskRule,
  Issue,
  RuleExecutionResult,
  RiskScoreInput,
  GraphVertex,
  Severity,
} from './types';

// Neptune Serverless rejects every path query with MemoryLimitExceededException
// for a minute or two after a burst of heavy ones (measured 2026-09-19: the same
// RULE-018 query answered in 0.5 s, then failed instantly five times in a row,
// then answered in 0.5 s again). The shared client's sub-second retries cannot
// outlast that, so a rule waits these long before trying again.
export const RULE_RETRY_DELAYS_MS = [5_000, 15_000, 30_000, 60_000, 60_000];

// Resources listed on one issue; matchCount keeps the full number.
const MAX_ISSUE_RESOURCES = 200;

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export class RiskRuleRunner {
  constructor(
    neptuneEndpoint: string,
    private readonly issueStore: DynamoDBIssueRepository = new DynamoDBIssueRepository(),
    private readonly neptuneClient: NeptuneQueryClient = createNeptuneRuntimeClient(
      neptuneEndpoint
    ),
    private readonly sleep: (ms: number) => Promise<void> = (ms) =>
      new Promise((resolve) => setTimeout(resolve, ms))
  ) {}

  async initialize(): Promise<void> {
    await this.neptuneClient.connect();
  }

  async shutdown(): Promise<void> {
    await this.neptuneClient.close();
  }

  async runRule(rule: RiskRule): Promise<RuleExecutionResult> {
    const startTime = Date.now();
    const errors: string[] = [];
    let issuesCreated = 0;
    let issuesResolved = 0;

    try {
      const results = await this.queryWithRecovery(rule);
      const paths = results.map((match) => this.extractPathFromMatch(match));
      if (
        paths.some(
          (path) =>
            path.vertices.length === 0 ||
            [...path.vertices, ...path.edges].some(
              (element) => !String(element.id ?? '').trim() || !element.label.trim()
            )
        )
      ) {
        throw new Error('Neptune returned a malformed risk-rule path');
      }

      const activeIssueIds = new Set<string>();

      for (const { identity, resources, path, matchCount } of this.groupPaths(rule, paths)) {
        const existingIssue = await this.issueStore.getIssueByRuleAndResources(rule.id, identity);

        if (existingIssue) {
          let currentIssue = existingIssue;
          if (existingIssue.status === 'resolved') {
            const reopened = await this.issueStore.reopenIssue(existingIssue, {
              by: SYSTEM_ACTOR,
              reason: `Matched again by ${rule.id}`,
            });
            if (!reopened) continue;
            currentIssue = { ...existingIssue, status: 'open' };
          }
          const refreshed = await this.refreshExistingIssue(
            currentIssue,
            rule,
            path,
            resources,
            matchCount
          );
          if (refreshed.status === 'suppressed') {
            await this.endSuppressionIfDue(refreshed, existingIssue.resourcesInvolved);
          }
          activeIssueIds.add(existingIssue.id);
        } else {
          const issue = this.createIssueFromMatch(rule, path, resources, identity, matchCount);
          const created = await this.issueStore.createIssue(issue);
          if (created) {
            issuesCreated++;
            await this.emitToIntegrations(issue, rule);
          } else {
            const concurrentIssue = await this.issueStore.getIssue(this.issueKey(issue));
            if (concurrentIssue) {
              await this.refreshExistingIssue(concurrentIssue, rule, path, resources, matchCount);
            }
          }
          activeIssueIds.add(issue.id);
        }
      }

      // Suppressed issues resolve too: a suppression hides a live problem, and
      // once the problem is gone the issue is fixed, not still accepted.
      const activeIssues = await this.issueStore.getActiveIssuesByRule(rule.id);
      for (const issue of activeIssues) {
        if (!activeIssueIds.has(issue.id)) {
          const resolved = await this.issueStore.resolveIssue(issue, {
            by: SYSTEM_ACTOR,
            reason: `No longer matched by ${rule.id}`,
          });
          if (resolved) issuesResolved++;
        }
      }
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }

    return {
      ruleId: rule.id,
      executionTime: Date.now() - startTime,
      matches: [],
      issuesCreated,
      issuesResolved,
      errors: errors.length > 0 ? errors : undefined,
    };
  }

  async runAllRules(): Promise<RuleExecutionResult[]> {
    const rules = getEnabledRules();
    const results: RuleExecutionResult[] = [];

    for (const rule of rules) {
      const result = await this.runRule(rule);
      results.push(result);
    }

    await this.snapshotTrends(results);

    return results;
  }

  private async snapshotTrends(results: RuleExecutionResult[]): Promise<void> {
    const { PostureTrendStore } = await import('./posture-trend-store');
    const store = new PostureTrendStore();

    let totalOpen = 0;
    let created = 0;
    let resolved = 0;
    const byRule = new Map<string, number>();
    const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const result of results) {
      const openIssues = await this.issueStore.getOpenIssuesByRule(result.ruleId);
      totalOpen += openIssues.length;
      byRule.set(result.ruleId, (byRule.get(result.ruleId) ?? 0) + openIssues.length);
      for (const issue of openIssues) {
        if (issue.severity in bySeverity) bySeverity[issue.severity] += 1;
      }
      created += result.issuesCreated;
      resolved += result.issuesResolved;
    }

    await store.recordMany([
      // The value is the total open count; the severity split rides in `sample`.
      {
        metric: 'openIssuesBySeverity',
        value: totalOpen,
        accountIds: [],
        sample: { bySeverity },
      },
      { metric: 'publicBuckets', value: byRule.get('RULE-007') ?? 0, accountIds: [] },
      { metric: 'crossAccountTrusts', value: byRule.get('RULE-006') ?? 0, accountIds: [] },
      { metric: 'usersWithoutMfa', value: byRule.get('RULE-015') ?? 0, accountIds: [] },
    ]);
    await store.increment('issuesCreated', created);
    await store.increment('issuesResolved', resolved);
  }

  // Rule traversals step through outE()/inV(), so a path alternates vertex,
  // edge, vertex, …; a single-hop rule yields one vertex.
  private async queryWithRecovery(rule: RiskRule): Promise<unknown[]> {
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await this.neptuneClient.executeQuery(rule.gremlinQueryTemplate);
      } catch (error) {
        const delay = RULE_RETRY_DELAYS_MS[attempt];
        if (delay === undefined || !isNeptuneRetryable(error)) throw error;
        console.warn(
          `${rule.id}: Neptune rejected the query (${error instanceof Error ? error.message.slice(0, 120) : String(error)}); retrying in ${delay / 1000}s`
        );
        await this.sleep(delay);
      }
    }
  }

  private extractPathFromMatch(match: unknown): RulePath {
    const objects = Array.isArray(match) ? match : (match as { objects?: unknown } | null)?.objects;
    const elements = Array.isArray(objects) ? objects.map(toVertex) : [];
    const alternating = elements.length % 2 === 1;
    return {
      vertices: alternating ? elements.filter((_, index) => index % 2 === 0) : elements,
      edges: alternating ? elements.filter((_, index) => index % 2 === 1) : [],
    };
  }

  // Paths that differ only in a rule's route labels describe one problem: they
  // share an identity, the issue lists every resource they touched, and the
  // highest-scoring path stands for the group.
  private groupPaths(
    rule: RiskRule,
    paths: RulePath[]
  ): Array<{
    identity: string[];
    resources: Issue['resourcesInvolved'];
    path: RulePath;
    matchCount: number;
  }> {
    const route = new Set(rule.routeLabels ?? []);
    const groups = new Map<
      string,
      {
        identity: string[];
        byId: Map<string, Issue['resourcesInvolved'][number]>;
        paths: RulePath[];
      }
    >();
    for (const path of paths) {
      const resources = this.extractResourcesFromPath(path.vertices);
      if (resources.length === 0) continue;
      const core = resources.filter((r) => !route.has(r.resourceType));
      const identity = [
        ...new Set((core.length ? core : resources).map((r) => r.resourceId)),
      ].sort();
      const key = JSON.stringify(identity);
      const group = groups.get(key) ?? { identity, byId: new Map(), paths: [] as RulePath[] };
      for (const resource of resources) group.byId.set(resource.resourceId, resource);
      group.paths.push(path);
      groups.set(key, group);
    }
    return [...groups.values()].map(({ identity, byId, paths: grouped }) => {
      // The problem's own resources first, then the routes, capped so one
      // noisy host cannot grow an item past DynamoDB's size limit.
      const all = [...byId.values()];
      const resources = [
        ...all.filter((r) => identity.includes(r.resourceId)),
        ...all.filter((r) => !identity.includes(r.resourceId)),
      ].slice(0, MAX_ISSUE_RESOURCES);
      const scored = grouped.map((p) => ({
        p,
        score: computeRiskScore(riskInputFromPath(p.vertices)).score,
      }));
      const path = scored.reduce((best, next) => (next.score > best.score ? next : best)).p;
      return { identity, resources, path, matchCount: grouped.length };
    });
  }

  private extractResourcesFromPath(
    path: GraphVertex[]
  ): { resourceId: string; resourceType: string; resourceName?: string }[] {
    return path
      .filter((v) => v.label && !['Internet', 'IAMRole', 'IAMPolicy'].includes(v.label))
      .map((v) => ({
        resourceId: this.canonicalVertexId(v),
        resourceType: v.label,
        resourceName: v.properties?.name || v.properties?.Name,
      }));
  }

  private createIssueFromMatch(
    rule: RiskRule,
    path: RulePath,
    resources: { resourceId: string; resourceType: string; resourceName?: string }[],
    identity: string[],
    matchCount: number
  ): Issue {
    const now = new Date().toISOString();
    const riskInput = this.buildRiskInput(path.vertices);
    const scoreResult = computeRiskScore(riskInput);

    return {
      id: this.issueStore.generateIssueId(rule.id, identity),
      ruleId: rule.id,
      resourcesInvolved: resources,
      pathSummary: this.pathSegments(path),
      riskScore: scoreResult.score,
      severity: scoreResult.severity,
      status: 'open',
      createdAt: now,
      updatedAt: now,
      owningTeam: rule.ownerTeam,
      remediationHint: getRemediationHint(rule.id, {}),
      metadata: {
        scoringFactors: scoreResult.factors,
        ruleName: rule.name,
        ruleDescription: rule.description,
        environment: riskInput.environment,
        matchCount,
      },
    };
  }

  private buildRiskInput(path: GraphVertex[]): RiskScoreInput {
    return riskInputFromPath(path);
  }

  private async refreshExistingIssue(
    existing: Issue,
    rule: RiskRule,
    path: RulePath,
    resources: Issue['resourcesInvolved'],
    matchCount: number
  ): Promise<Issue> {
    const riskInput = this.buildRiskInput(path.vertices);
    const scoreResult = computeRiskScore(riskInput);
    const updatedAt = new Date().toISOString();

    const refreshed: Issue = {
      ...existing,
      resourcesInvolved: resources,
      pathSummary: this.pathSegments(path),
      riskScore: scoreResult.score,
      severity: scoreResult.severity,
      remediationHint: getRemediationHint(rule.id, {}),
      updatedAt,
      metadata: {
        ...existing.metadata,
        scoringFactors: scoreResult.factors,
        ruleName: rule.name,
        ruleDescription: rule.description,
        environment: riskInput.environment,
        matchCount,
        lastRefreshedAt: updatedAt,
      },
    };

    const updated = await this.issueStore.updateIssue(refreshed);
    if (updated) await this.emitToIntegrations(refreshed, rule);
    return refreshed;
  }

  // Suppressions made before reasons and expiries were recorded have no
  // `suppression`; they reopen so someone re-suppresses them with both.
  private async endSuppressionIfDue(
    issue: Issue,
    previous: Issue['resourcesInvolved'] = []
  ): Promise<void> {
    const suppression = issue.suppression;
    // A grouped issue gains resources as new matches land (another finding on
    // the same host); accepting the old ones does not accept those.
    const known = new Set(previous.map((resource) => resource.resourceId));
    const added = previous.length
      ? issue.resourcesInvolved.find((resource) => !known.has(resource.resourceId))
      : undefined;
    let reason: string | undefined;
    if (added) {
      reason = `New ${added.resourceType} matched while suppressed`;
    } else if (!suppression) {
      reason = 'Suppression had no recorded reason or expiry';
    } else if (Date.parse(suppression.until) <= Date.now()) {
      reason = `Suppression by ${suppression.by} expired`;
    } else if (SEVERITY_RANK[issue.severity] > SEVERITY_RANK[suppression.severity]) {
      reason = `Severity rose from ${suppression.severity} to ${issue.severity} while suppressed`;
    }
    if (reason) await this.issueStore.reopenIssue(issue, { by: SYSTEM_ACTOR, reason });
  }

  private async emitToIntegrations(issue: Issue, rule: RiskRule): Promise<void> {
    if (!rule.autoTicketConfig?.enabled) return;
    if (issue.status === 'suppressed') return;

    const { IssueIntegrationsOrchestrator } = await import('@khalifa/integrations');
    const orchestrator = new IssueIntegrationsOrchestrator();
    let refs;
    try {
      refs = await orchestrator.emit(issue, rule);
    } catch (error) {
      console.error('Issue integration delivery failed:', error);
      return;
    }
    if (refs.length > 0) {
      const existing = issue.externalRefs || [];
      const merged = [...existing, ...refs].filter(
        (ref, idx, arr) => arr.findIndex((r) => r.system === ref.system && r.id === ref.id) === idx
      );
      const updated = await this.issueStore.updateExternalRefs(this.issueKey(issue), merged);
      if (!updated) {
        throw new Error(`Issue disappeared before external references were persisted: ${issue.id}`);
      }
    }
  }

  private issueKey(issue: Pick<Issue, 'id' | 'ruleId'>): IssueKey {
    return { id: issue.id, ruleId: issue.ruleId };
  }

  private canonicalVertexId(vertex: GraphVertex): string {
    const arn = vertex.properties?.arn;
    if (typeof arn === 'string' && arn.length > 0) return arn;
    if (Array.isArray(arn) && typeof arn[0] === 'string' && arn[0].length > 0) return arn[0];
    return vertex.id;
  }

  private pathSegments(path: RulePath): Issue['pathSummary'] {
    return path.vertices.slice(0, -1).map((from, index) => ({
      from: this.canonicalVertexId(from),
      to: this.canonicalVertexId(path.vertices[index + 1]),
      edgeType: path.edges[index]?.label ?? 'CONNECTED',
    }));
  }
}

interface RulePath {
  vertices: GraphVertex[];
  edges: GraphVertex[];
}

// The driver deserializes each `path().by(valueMap(true, …))` element as a Map
// keyed by the T.id / T.label enum values plus property names, with every
// valueMap() value wrapped in a list. Plain objects are accepted too.
function toVertex(element: unknown): GraphVertex {
  const vertex: GraphVertex = { id: '', label: '', properties: {} };
  for (const [key, raw] of entries(element)) {
    const name = keyName(key);
    const value = unwrap(raw);
    if (name === 'id') vertex.id = String(value);
    else if (name === 'label') vertex.label = String(value);
    else vertex.properties[name] = value;
  }
  return vertex;
}

function entries(value: unknown): Array<[unknown, unknown]> {
  if (value instanceof Map) return [...value.entries()];
  return value && typeof value === 'object' ? Object.entries(value) : [];
}

function keyName(key: unknown): string {
  if (typeof key === 'string') return key;
  if (key && typeof key === 'object' && 'elementName' in key) {
    return String((key as { elementName: unknown }).elementName);
  }
  return String(key);
}

// A single-valued property comes back as a one-element list; multi-valued
// properties stay lists. `{ value }` wrappers from older result shapes unwrap too.
function unwrap(value: unknown): unknown {
  if (Array.isArray(value)) {
    const items = value.map(unwrap);
    return items.length === 1 ? items[0] : items;
  }
  if (value && typeof value === 'object' && !(value instanceof Map) && 'value' in value) {
    return unwrap((value as { value: unknown }).value);
  }
  return value;
}
