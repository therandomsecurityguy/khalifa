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

export interface AutoTicketConfig {
  enabled: boolean;
  projectKey?: string;
  assignee?: string;
  priority?: string;
}

export interface RiskRule {
  id: string;
  name: string;
  description: string;
  severityHint: Severity;
  // Highest severity the rule's issues get, whatever the path scores.
  maxSeverity?: Severity;
  riskFactors: RiskFactor[];
  gremlinQueryTemplate: string;
  ownerTeam: string;
  enabled: boolean;
  autoTicketConfig: AutoTicketConfig;
  // Vertex labels that are how a match was reached rather than the problem
  // itself (a finding, a security group rule, a policy statement). Matches
  // that differ only in these become one issue listing all of them.
  routeLabels?: string[];
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

export interface ExternalRef {
  system: string;
  id: string;
  url?: string;
  emittedAt: string;
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
  metadata: Record<string, any>;
  externalRefs?: ExternalRef[];
  resolvedAt?: string;
  resolvedReason?: string;
  suppression?: Suppression;
  statusHistory?: StatusChange[];
}

export interface RuleExecutionResult {
  ruleId: string;
  executionTime: number;
  matches: any[];
  issuesCreated: number;
  issuesResolved: number;
  errors?: string[];
}

export interface GremlinQueryResult {
  vertices: GraphVertex[];
  edges: GraphEdge[];
}

export interface GraphVertex {
  id: string;
  label: string;
  properties: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  label: string;
  from: string;
  to: string;
  properties?: Record<string, any>;
}

export interface IdentityBlastRadius {
  type: 'admin' | 'wildcard' | 'cross-account' | 'service-linked';
  scope: number;
}

export interface PathExploitability {
  /** Highest CVSS base score among the path's vulnerability vertices. */
  cvssBaseScore?: number;
  /** An Amazon Inspector finding on the path reports a known exploit. */
  exploitAvailable?: boolean;
}

export interface RiskScoreInput {
  exposureLevel: ExposureLevel;
  identityBlastRadius?: IdentityBlastRadius;
  dataClassification: DataClassification;
  environment: Environment;
  attackPathLength?: number;
  isCrownJewel: boolean;
  /** Set when the path carries Amazon Inspector vulnerability vertices. */
  exploitability?: PathExploitability;
  /** A path vertex marks exposure or state as unreadable (restricted reads). */
  reachabilityRestricted?: boolean;
}

export interface RiskScoreOutput {
  score: number;
  severity: Severity;
  factors: {
    exposureContribution: number;
    identityContribution: number;
    dataClassificationContribution: number;
    environmentContribution: number;
    crownJewelContribution: number;
    exploitabilityContribution: number;
  };
}
