export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type IssueStatus = 'open' | 'resolved' | 'suppressed';

export interface Issue {
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
  resolvedAt?: string;
  resolvedReason?: string;
  suppression?: Suppression;
  statusHistory?: StatusChange[];
}

export interface StatusChange {
  from: IssueStatus;
  to: IssueStatus;
  at: string;
  by: string;
  reason: string;
}

export interface Suppression {
  by: string;
  at: string;
  reason: string;
  until: string;
  severity: Severity;
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

export interface IssueListResponse {
  items: Issue[];
  nextToken?: string;
  totalCount: number;
}

export interface GraphVertex {
  id: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  id: string;
  label: string;
  from: string;
  to: string;
  properties?: Record<string, unknown>;
}

export type AttackPathEntry = { kind: 'internet' } | { kind: 'trust'; principals: GraphVertex[] };

export interface IssueDetail extends Issue {
  attackPath: {
    nodes: GraphVertex[];
    edges: GraphEdge[];
    entry?: AttackPathEntry;
  };
  // Involved resources off the drawn path, as currently in the graph.
  involvedResources?: GraphVertex[];
}

export interface IssueFilters {
  severity?: Severity[];
  team?: string[];
  status?: IssueStatus[];
  limit?: number;
  nextToken?: string;
}

export type SeverityStatusCounts = Record<Severity, Record<IssueStatus, number>>;

export interface IssueStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  byTeam: Record<string, number>;
  byRule: Record<string, number>;
}

export interface IamPolicyStatement {
  sid?: string;
  effect: 'Allow' | 'Deny';
  actions: string[];
  resources: string[];
}

export interface LeastPrivilegeFinding {
  accountId: string;
  principalArn: string;
  principalType: 'role' | 'user';
  allowedActionCount: number;
  removedActionCount: number;
  keptActionCount: number;
  removedActions: string[];
  keptActions: string[];
  recommendedPolicy: IamPolicyStatement[];
  riskLevel: 'low' | 'medium' | 'high';
  confidence: number;
  isAdmin: boolean;
  blastRadius: number;
  lastSweptAt: string;
}

export interface LeastPrivilegeListResponse {
  items: LeastPrivilegeFinding[];
  nextToken?: string;
  totalCount: number;
}

export interface LeastPrivilegeSummary {
  accountsSwept: number;
  principalsSwept: number;
  byRiskLevel: Record<'low' | 'medium' | 'high', number>;
  totalRemovedActions: number;
}

export interface Session {
  email: string | null;
  role: 'Admin' | 'Analyst' | 'Viewer' | null;
  canManageIssues: boolean;
}

export interface ResourceLabelCount {
  label: string;
  count: number;
}

export interface ResourceSearchResponse {
  label: string;
  resources: GraphVertex[];
  nextToken?: string;
}

export interface ResourceDetail {
  resource: GraphVertex;
  neighbors: GraphVertex[];
  edges: GraphEdge[];
  issues: Issue[];
}

export type AttackPathStart = 'any' | 'internet' | 'outside' | 'resource';
export type AttackPathTarget = 'restricted' | 'crown' | 'secrets' | 'admin' | 'resource';

export interface AttackPathSearchParams {
  from: AttackPathStart;
  to: AttackPathTarget;
  fromResource?: string;
  toResource?: string;
  account?: string;
  maxPathLength?: number;
}

export interface PathLikelihoodFactors {
  exposure: number;
  privilege: number;
  exploitability: number;
  reachability: number;
  /** Freshness tempering (1 fresh/unknown, 0.8 aging, 0.5 stale); absent on old issues. */
  coverage?: number;
}

export type CoverageLevel = 'fresh' | 'aging' | 'stale' | 'unknown';

export interface CoverageStatement {
  level: CoverageLevel;
  latestSuccessAt?: string;
  ageHours?: number;
  note: string;
}

export interface ScoredPath {
  nodes: GraphVertex[];
  edges: GraphEdge[];
  score: number;
  severity: Severity;
  /** Explainable 0..1 path likelihood (product of the factors). */
  likelihood: number;
  likelihoodFactors: PathLikelihoodFactors;
}

export interface AttackPathSimulationEdge {
  id: string;
  label: string;
  from: string;
  to: string;
  /** Matched paths that traverse this edge. */
  pathsUsing: number;
  /** Matched paths the rule would still return without the edge. */
  remainingPaths: number;
  /** Likelihood of the worst path the edge clears, 0..1. */
  worstLikelihood: number;
}

export interface AttackPathSimulationResponse {
  ruleId: string;
  ruleName: string;
  totalPaths: number;
  truncated: boolean;
  edges: AttackPathSimulationEdge[];
  coverage: CoverageStatement;
}

export interface AttackPathSearchResponse {
  from: AttackPathStart;
  to: AttackPathTarget;
  maxPathLength: number;
  coverage: CoverageStatement;
  paths: ScoredPath[];
  entries: Record<string, AttackPathEntry>;
  truncated: boolean;
}

export interface ServiceCoverage {
  service: string;
  region: string;
  status: string;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  error: string | null;
  failureType: string | null;
  nodes: number | null;
}

export type DetectionState = 'on' | 'truncated' | 'off' | 'missing' | 'unknown';

export interface DetectionCoverage {
  securityHub: DetectionState;
  guardDuty: DetectionState;
  config: DetectionState;
  accessAnalyzer: DetectionState;
}

export interface JobOutput {
  id: string;
  name: string;
  everyHours: number;
  lastOutputAt: string | null;
  produced: string;
  quietWhenClean: boolean;
}

export interface AccountCoverage {
  id: string;
  name: string;
  resources: number | null;
  prod: number;
  collectedAt: string | null;
  status: 'ok' | 'failing' | 'not-collected';
  services: ServiceCoverage[];
  detection: DetectionCoverage;
}

export interface AccountSummary {
  id: string;
  name: string;
}

export interface ResourceGraph {
  nodes: GraphVertex[];
  edges: GraphEdge[];
}

export interface ConditionalGrant {
  action: string;
  resource: string;
  conditions: Record<string, unknown>;
}

export interface EffectivePermissions {
  principal: string;
  allowedActions: string[];
  deniedActions: string[];
  conditionalGrants: ConditionalGrant[];
  policiesEvaluated: string[];
  isAdmin: boolean;
  blastRadius: number;
  evaluatedAt: string;
}

export interface EscalationPath {
  id: string;
  sourceArn: string;
  targetArn: string;
  path: PathSegment[];
  pathLength: number;
  riskLevel: Severity;
  escalationType: string;
  conditions: Record<string, unknown>;
  detectedAt: string;
}

export interface ServiceActions {
  service: string;
  actions: string[];
}

export interface UnusedPermissions {
  principalArn: string;
  unusedActions: ServiceActions[];
  usedActions: ServiceActions[];
  lastAnalyzed: string;
}

export interface RightsizingRecommendation {
  principalArn: string;
  currentPolicy: IamPolicyStatement[];
  recommendedPolicy: IamPolicyStatement[];
  removedActions: string[];
  keptActions: string[];
  riskLevel: 'low' | 'medium' | 'high';
  confidence: number;
}

export interface TrendPoint {
  date: string;
  value: number;
  accountIds?: string[];
  recordedAt?: string;
  bySeverity?: Record<'critical' | 'high' | 'medium' | 'low', number>;
}

export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
}

export interface AttackScenarioStep {
  ruleId: string;
  ruleName: string;
  description: string;
}

export interface AttackScenarioDetail {
  id: string;
  name: string;
  description: string;
  techniques: AttackTechnique[];
  steps: AttackScenarioStep[];
}

export interface ScenarioStepRunResult {
  ruleId: string;
  description: string;
  matchedPaths: number;
  resources: string[];
  truncated: boolean;
  error?: string;
}

export interface AttackScenarioRunResponse {
  scenarioId: string;
  name: string;
  matchedSteps: number;
  totalSteps: number;
  steps: ScenarioStepRunResult[];
  coverage: CoverageStatement;
}

export interface RuleQualityItem {
  ruleId: string;
  name: string;
  ownerTeam: string;
  severityHint: Severity | null;
  enabled: boolean;
  autoTicket: boolean;
  inCatalogue: boolean;
  open: number;
  suppressed: number;
  resolved: number;
  handled: number;
  dismissalRate: number | null;
  corroborated?: number;
  labeled?: number;
  corroborationRate: number | null;
  verdict: 'insufficient-data' | 'reliable' | 'mixed' | 'noisy';
}

export interface RuleQualityResponse {
  rules: RuleQualityItem[];
  thresholds: { minHandled: number; reliableDismissalRate: number; noisyDismissalRate: number };
  generatedAt: string;
}

export interface TrendForecastProjection {
  days: number;
  date: string;
  value: number;
  lower: number;
  upper: number;
}

export interface TrendForecast {
  basisDays: number;
  slopePerDay: number;
  confidence: 'high' | 'medium' | 'low';
  projected: TrendForecastProjection[];
  /** Present when the series itself lowered the confidence. */
  note?: string;
}

export interface TrendSeries {
  metric: string;
  points: TrendPoint[];
  forecast?: TrendForecast;
}

export interface IntegrationsStatus {
  configuredSinks: string[];
  health: Record<string, boolean>;
}

export interface IssueLifecycleResponse {
  id: string;
  status: IssueStatus;
  reason?: string;
  expiresAt?: string;
}

export interface CatalogRule {
  id: string;
  name: string;
  description: string;
  severityHint: Severity;
  ownerTeam: string;
  enabled: boolean;
}

// Metadata only: the API never returns a secret's description, tags, key ARN
// or policy text, and Khalifa never collects its value.
export interface SecretSharing {
  scope: 'account' | 'collected' | 'org' | 'outside';
  accounts: number;
}

export interface SecretInventoryItem {
  id: string;
  // ssm-plaintext: a String parameter whose name looks like a credential.
  kind: 'secrets-manager' | 'ssm-parameter' | 'ssm-plaintext';
  name: string;
  accountId: string;
  region: string;
  encryption: 'aws-managed' | 'customer-managed' | 'none';
  // From the resource's tags; null when untagged.
  env: string | null;
  owner: string | null;
  rotationEnabled: boolean | null;
  lastRotated: string | null;
  // Null before the collector recorded dates; lastAccessed is null when never read.
  createdAt: string | null;
  lastAccessed: string | null;
  lastModified: string | null;
  collectionRestricted: boolean;
  sharing: SecretSharing | null;
  // Filled in on the page from the reader counts: undefined while they load,
  // null when not evaluated (parameters, or an account that could not be read).
  readers?: SecretReaderCount | null;
  issues: Array<{
    id: string;
    ruleId: string;
    severity: Severity;
    title: string;
    openedAt: string;
  }>;
}

export interface SecretReaderCount {
  total: number;
  broad: number;
  // The account had more policy rows than were read: the count is a minimum.
  partial: boolean;
}

export interface SecretReaderCounts {
  counts: Record<string, SecretReaderCount>;
  unavailableAccounts: number;
  partialAccounts: number;
  truncated: boolean;
}

export interface SecretInventory {
  items: SecretInventoryItem[];
  truncated: boolean;
  issuesUnavailable: boolean;
}

export interface SecretReaderGrant {
  policyName: string;
  policyKind: 'inline' | 'managed' | 'aws-managed';
  // By the secret's own ARN, a pattern, every resource, or all but some.
  scope: 'secret' | 'pattern' | 'all' | 'not-resource';
  notAction: boolean;
  conditional: boolean;
}

export interface SecretReader {
  id: string;
  name: string;
  type: 'role' | 'user' | 'group';
  admin: boolean;
  mayBeDenied: boolean;
  grants: SecretReaderGrant[];
}

export interface SecretDetail {
  item: SecretInventoryItem;
  issuesUnavailable: boolean;
  // Null for SSM parameters, which this does not evaluate.
  readers: { items: SecretReader[]; truncated: boolean; unavailable: boolean } | null;
}
