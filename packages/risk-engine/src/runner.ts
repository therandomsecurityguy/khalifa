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
import { extractRulePath, type RulePath } from './rule-path';
import { pathLikelihood } from './likelihood';
import { pathIndicators, ThreatIndicatorStore, type ThreatIndicator } from './threat-intel';
import { techniquesForRule } from './attack-techniques';

// Neptune Serverless rejects every path query with MemoryLimitExceededException
// for a minute or two after a burst of heavy ones (measured 2026-09-19: the same
// RULE-018 query answered in 0.5 s, then failed instantly five times in a row,
// then answered in 0.5 s again). The shared client's sub-second retries cannot
// outlast that, so a rule waits these long before trying again.
export const RULE_RETRY_DELAYS_MS = [5_000, 15_000, 30_000, 60_000, 60_000];

// Resources listed on one issue; matchCount keeps the full number.
const MAX_ISSUE_RESOURCES = 200;

const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function cappedSeverity(rule: RiskRule, severity: Severity): Severity {
  const max = rule.maxSeverity;
  return max && SEVERITY_RANK[severity] > SEVERITY_RANK[max] ? max : severity;
}

export class RiskRuleRunner {
  constructor(
    neptuneEndpoint: string,
    private readonly issueStore: DynamoDBIssueRepository = new DynamoDBIssueRepository(),
    private readonly neptuneClient: NeptuneQueryClient = createNeptuneRuntimeClient(
      neptuneEndpoint
    ),
    private readonly sleep: (ms: number) => Promise<void> = (ms) =>
      new Promise((resolve) => setTimeout(resolve, ms)),
    private readonly threatStore: ThreatIndicatorStore = new ThreatIndicatorStore()
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
      const paths = results.map((match) => extractRulePath(match));
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

      // Customer threat-intel matches for anything this rule's paths touch
      // (anomaly source IPs, trusted external accounts). Failure-tolerant: a
      // missing table or grant means no matches, never a failed run.
      let threatIntel: ThreatIndicator[] = [];
      try {
        threatIntel = await this.threatStore.find(paths.flatMap((path) => pathIndicators(path)));
      } catch (error) {
        console.warn(
          `${rule.id}: threat-intel lookup failed; scoring without it (${error instanceof Error ? error.message : String(error)})`
        );
      }
      const matchesFor = (path: RulePath): ThreatIndicator[] => {
        const candidates = pathIndicators(path);
        return threatIntel.filter((indicator) =>
          candidates.some(
            (candidate) => candidate.type === indicator.type && candidate.value === indicator.value
          )
        );
      };

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
            matchCount,
            matchesFor(path)
          );
          if (refreshed.status === 'suppressed') {
            await this.endSuppressionIfDue(refreshed, existingIssue.resourcesInvolved);
          }
          activeIssueIds.add(existingIssue.id);
        } else {
          const issue = this.createIssueFromMatch(
            rule,
            path,
            resources,
            identity,
            matchCount,
            matchesFor(path)
          );
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
    let openRiskScore = 0;
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
        if (typeof issue.riskScore === 'number' && Number.isFinite(issue.riskScore)) {
          openRiskScore += issue.riskScore;
        }
      }
      created += result.issuesCreated;
      resolved += result.issuesResolved;
    }

    // The two series that need more than the run's own results: mean time to
    // resolution over recently resolved issues, and the admin-principal count.
    // Both are optional — an unreadable source skips the day's point rather
    // than failing the trend snapshot.
    const mttrHours = await this.meanResolutionHours();
    const adminPrincipals = await this.countAdminPrincipals();

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
      // Open risk score: the backlog's sum, so a few criticals weigh more than
      // many lows.
      { metric: 'openRiskScore', value: Math.round(openRiskScore * 10) / 10, accountIds: [] },
      ...(mttrHours !== undefined
        ? [{ metric: 'mttrHours' as const, value: mttrHours, accountIds: [] }]
        : []),
      ...(adminPrincipals !== undefined
        ? [{ metric: 'adminPrincipals' as const, value: adminPrincipals, accountIds: [] }]
        : []),
    ]);
    await store.increment('issuesCreated', created);
    await store.increment('issuesResolved', resolved);
  }

  // Mean hours from creation to resolution for issues resolved in the last 30
  // days, over one bounded page of the resolved status. Undefined when nothing
  // resolved recently or the store is unreadable.
  private async meanResolutionHours(now: Date = new Date()): Promise<number | undefined> {
    try {
      const page = await this.issueStore.listIssues({ status: ['resolved'], limit: 100 });
      const cutoff = now.getTime() - 30 * 24 * 60 * 60 * 1000;
      const durations = page.items
        .filter((issue) => issue.resolvedAt && Date.parse(issue.resolvedAt) >= cutoff)
        .map((issue) => (Date.parse(issue.resolvedAt!) - Date.parse(issue.createdAt)) / 3_600_000)
        .filter((hours) => Number.isFinite(hours) && hours >= 0);
      if (durations.length === 0) return undefined;
      return Math.round((durations.reduce((a, b) => a + b, 0) / durations.length) * 10) / 10;
    } catch {
      return undefined;
    }
  }

  // Admins the policy evaluator marked this collection window; a leading
  // indicator of blast-radius growth. Failures skip the point.
  private async countAdminPrincipals(): Promise<number | undefined> {
    try {
      const rows = await this.neptuneClient.executeQuery(
        `g.V().hasLabel(within('IamUser', 'IamRole')).has('is_admin', true).count()`
      );
      const first = rows[0] as unknown;
      const value =
        first && typeof first === 'object' && 'value' in (first as Record<string, unknown>)
          ? (first as { value: unknown }).value
          : first;
      const count = Number(value);
      return Number.isFinite(count) ? count : undefined;
    } catch {
      return undefined;
    }
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
    matchCount: number,
    threatIntel: ThreatIndicator[] = []
  ): Issue {
    const now = new Date().toISOString();
    const riskInput = this.riskInputWithThreatIntel(path, threatIntel);
    const scoreResult = computeRiskScore(riskInput);
    const likelihood = pathLikelihood(riskInput);

    return {
      id: this.issueStore.generateIssueId(rule.id, identity),
      ruleId: rule.id,
      resourcesInvolved: resources,
      pathSummary: this.pathSegments(path),
      riskScore: scoreResult.score,
      severity: cappedSeverity(rule, scoreResult.severity),
      status: 'open',
      createdAt: now,
      updatedAt: now,
      owningTeam: rule.ownerTeam,
      remediationHint: getRemediationHint(rule.id, {}),
      metadata: {
        scoringFactors: scoreResult.factors,
        likelihood: likelihood.value,
        likelihoodFactors: likelihood.factors,
        ruleName: rule.name,
        ruleDescription: rule.description,
        environment: riskInput.environment,
        matchCount,
        ...(threatIntel.length > 0 ? { threatIntelMatches: threatIntel } : {}),
        attackTechniques: techniquesForRule(rule.id),
      },
    };
  }

  // The path's risk input plus customer threat-intel matches, when any.
  private riskInputWithThreatIntel(path: RulePath, threatIntel: ThreatIndicator[]): RiskScoreInput {
    const riskInput = this.buildRiskInput(path.vertices);
    if (threatIntel.length === 0) return riskInput;
    return {
      ...riskInput,
      threatIntel: {
        indicators: threatIntel.map((indicator) => `${indicator.type}:${indicator.value}`),
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
    matchCount: number,
    threatIntel: ThreatIndicator[] = []
  ): Promise<Issue> {
    const riskInput = this.riskInputWithThreatIntel(path, threatIntel);
    const scoreResult = computeRiskScore(riskInput);
    const likelihood = pathLikelihood(riskInput);
    const updatedAt = new Date().toISOString();

    const refreshed: Issue = {
      ...existing,
      resourcesInvolved: resources,
      pathSummary: this.pathSegments(path),
      riskScore: scoreResult.score,
      severity: cappedSeverity(rule, scoreResult.severity),
      remediationHint: getRemediationHint(rule.id, {}),
      updatedAt,
      metadata: metadataWithThreatIntel(
        {
          ...existing.metadata,
          scoringFactors: scoreResult.factors,
          likelihood: likelihood.value,
          likelihoodFactors: likelihood.factors,
          ruleName: rule.name,
          ruleDescription: rule.description,
          environment: riskInput.environment,
          matchCount,
          lastRefreshedAt: updatedAt,
          attackTechniques: techniquesForRule(rule.id),
        },
        threatIntel
      ),
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

// A refresh clears yesterday's matches when the indicator is gone: metadata
// spread alone would keep a stale match forever.
function metadataWithThreatIntel(
  metadata: Record<string, unknown>,
  threatIntel: ThreatIndicator[]
): Record<string, unknown> {
  if (threatIntel.length > 0) {
    metadata.threatIntelMatches = threatIntel;
  } else {
    delete metadata.threatIntelMatches;
  }
  return metadata;
}
