export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type IssueStatus = 'open' | 'resolved' | 'suppressed';
export type ExposureLevel = 'internet' | 'cross-account' | 'internal';
export type DataClassification = 'public' | 'internal' | 'restricted' | 'secret';
export type Environment = 'prod' | 'staging' | 'dev';

export interface RiskFactor {
  name: string;
  weight: number;
  value: number;
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
  externalRefs?: ExternalRef[];
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

export interface ResourceQuery {
  arn: string;
  includeNeighbors?: boolean;
  includeIssues?: boolean;
}

export interface IssueDetailResponse extends Issue {
  attackPath: AttackPathDetail;
  // Involved resources off the drawn path, as currently in the graph.
  involvedResources: GraphVertex[];
}

// Where an attacker gets onto the path, when the path itself does not start there.
export type AttackPathEntry = { kind: 'internet' } | { kind: 'trust'; principals: GraphVertex[] };

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

// Metadata only: the API never returns a secret's description, tags, key ARN
// or policy text, and Khalifa never collects its value.
export interface SecretSharing {
  scope: 'account' | 'collected' | 'org' | 'outside';
  // How many collected accounts, when scope is 'collected'.
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
  // Null for parameters, and for secrets whose policy Khalifa could not read.
  sharing: SecretSharing | null;
  issues: Array<{
    id: string;
    ruleId: string;
    severity: Severity;
    title: string;
    openedAt: string;
  }>;
}

export interface AttackPathDetail {
  nodes: GraphVertex[];
  edges: GraphEdge[];
  entry?: AttackPathEntry;
}

export interface ResourceResponse {
  resource: GraphVertex;
  neighbors?: GraphVertex[];
  edges?: GraphEdge[];
  issues?: Issue[];
}

export interface RiskRule {
  id: string;
  name: string;
  description: string;
  severityHint: Severity;
  riskFactors: RiskFactor[];
  gremlinQueryTemplate: string;
  ownerTeam: string;
  enabled: boolean;
}

export interface ExternalRef {
  system: string;
  id: string;
  url?: string;
  emittedAt: string;
}

export interface TrendPoint {
  metric: string;
  date: string;
  value: number;
  accountIds?: string[];
  recordedAt: string;
  bySeverity?: SeverityCounts;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
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

// Single source of truth lives with the likelihood it tempers.
import type { CoverageLevel } from '@khalifa/risk-engine';
export type { CoverageLevel };

export interface CoverageStatement {
  level: CoverageLevel;
  latestSuccessAt?: string;
  ageHours?: number;
  note: string;
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
  /** Issues an independent detector (Security Hub / GuardDuty) corroborated. */
  corroborated?: number;
  /** Issues the runner could label at all. */
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

export interface TrendResponse {
  metric: string;
  points: TrendPoint[];
  forecast?: TrendForecast;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

export type IamPolicyType = 'inline' | 'managed' | 'aws-managed';

export interface IamPolicyStatement {
  sid?: string;
  effect: 'Allow' | 'Deny';
  actions: string[];
  resources: string[];
  conditions?: IamConditionBlock;
  notActions?: string[];
  notResources?: string[];
}

export interface IamConditionBlock {
  [operator: string]: {
    [key: string]: string | string[];
  };
}

export interface IamPolicyDocument {
  id: string;
  arn: string;
  policyArn: string;
  defaultVersionId: string;
  documentJson: string;
  policyType: IamPolicyType;
  accountId: string;
  version: string;
}

export interface EffectivePermission {
  id: string;
  principalArn: string;
  allowedActions: string[];
  deniedActions: string[];
  conditionalGrants: ConditionalGrant[];
  policiesEvaluated: string[];
  evaluatedAt: string;
  isAdmin: boolean;
  blastRadius: number;
}

export interface ConditionalGrant {
  action: string;
  resource: string;
  conditions: IamConditionBlock;
}

export type EscalationType = 'admin' | 'privilege_escalation' | 'lateral_movement';

export interface EscalationPath {
  id: string;
  sourceArn: string;
  targetArn: string;
  path: PathSegment[];
  pathLength: number;
  riskLevel: Severity;
  escalationType: EscalationType;
  conditions: IamConditionBlock;
  detectedAt: string;
}

export interface UnusedPermissions {
  principalArn: string;
  unusedActions: ServiceActions[];
  usedActions: ServiceActions[];
  lastAnalyzed: string;
}

export interface ServiceActions {
  service: string;
  actions: string[];
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

export interface TrustRelationship {
  id: string;
  roleArn: string;
  trustedPrincipal: string;
  principalType: 'AWS' | 'Service' | 'Federated';
  isCrossAccount: boolean;
  conditions: IamConditionBlock;
  allowsAssumeRole: boolean;
}

export interface EffectivePermissionsResponse {
  principal: string;
  allowedActions: string[];
  deniedActions: string[];
  conditionalGrants: ConditionalGrant[];
  policiesEvaluated: string[];
  isAdmin: boolean;
  blastRadius: number;
  evaluatedAt: string;
}

export interface EscalationPathsResponse {
  paths: EscalationPath[];
  total: number;
}

export interface UnusedPermissionsResponse {
  principalArn: string;
  unusedActions: ServiceActions[];
  usedActions: ServiceActions[];
  lastAnalyzed: string;
}

export interface RightsizingResponse {
  principalArn: string;
  currentPolicy: IamPolicyStatement[];
  recommendedPolicy: IamPolicyStatement[];
  removedActions: string[];
  keptActions: string[];
  riskLevel: 'low' | 'medium' | 'high';
  confidence: number;
}

export interface TrustGraphResponse {
  nodes: GraphVertex[];
  edges: GraphEdge[];
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
  lastSweptAt: string | null;
}
