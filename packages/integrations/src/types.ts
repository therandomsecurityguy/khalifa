export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type IssueStatus = 'open' | 'resolved' | 'suppressed';

export interface ExternalRef {
  system: string;
  id: string;
  url?: string;
  emittedAt: string;
}

export interface ResourceInvolved {
  resourceId: string;
  resourceType: string;
  resourceName?: string;
  accountId?: string;
  region?: string;
}

export interface PathSegment {
  from: string;
  to: string;
  edgeType: string;
  label?: string;
}

export interface IssueLike {
  id: string;
  ruleId: string;
  resourcesInvolved: ResourceInvolved[];
  pathSummary: PathSegment[];
  riskScore: number;
  severity: Severity;
  status: IssueStatus;
  createdAt: string;
  updatedAt: string;
  owningTeam: string;
  remediationHint: string;
  metadata: Record<string, unknown>;
  externalRefs?: ExternalRef[];
}

export interface AutoTicketConfig {
  enabled: boolean;
  projectKey?: string;
  assignee?: string;
  priority?: string;
}

export interface RuleLike {
  id: string;
  name: string;
  description: string;
  severityHint: Severity;
  ownerTeam: string;
  enabled: boolean;
  autoTicketConfig: AutoTicketConfig;
}

// Issue lifecycle transitions delivered to sinks. `issue.created` and
// `issue.updated` come from the rule runner; `issue.resolved` and
// `issue.suppressed` are transitions beyond detection (the runner resolves an
// issue that stopped matching; an analyst suppresses one through the API).
export type IssueEvent = 'issue.created' | 'issue.updated' | 'issue.resolved' | 'issue.suppressed';

export interface IssueActionSink {
  readonly system: string;
  emit(issue: IssueLike, rule: RuleLike, event?: IssueEvent): Promise<ExternalRef | null>;
  healthCheck(): Promise<boolean>;
}

export interface RemediationAction {
  readonly actionId: string;
  canHandle(ruleId: string): boolean;
  remediate(issue: IssueLike, rule: RuleLike): Promise<{ status: string; details?: string }>;
}

export interface SinkFactory {
  create(): IssueActionSink;
}

const SINK_REGISTRY = new Map<string, SinkFactory>();

export function registerSink(name: string, factory: SinkFactory): void {
  SINK_REGISTRY.set(name, factory);
}

export function getSink(name: string): IssueActionSink | null {
  const factory = SINK_REGISTRY.get(name);
  if (!factory) return null;
  return factory.create();
}

export function listRegisteredSinks(): string[] {
  return [...SINK_REGISTRY.keys()];
}
