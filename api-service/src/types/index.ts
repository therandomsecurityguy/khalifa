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

export interface IssueListQuery {
  severity?: Severity[];
  team?: string[];
  env?: Environment[];
  status?: IssueStatus[];
  ruleId?: string;
  limit?: number;
  nextToken?: string;
}

export interface AttackPathQuery {
  fromSelector: string;
  toSelector: string;
  maxPathLength?: number;
}

export interface ResourceQuery {
  arn: string;
  includeNeighbors?: boolean;
  includeIssues?: boolean;
}

export interface IssueListResponse {
  items: Issue[];
  nextToken?: string;
  totalCount: number;
}

export interface IssueDetailResponse extends Issue {
  attackPath: AttackPathDetail;
}

export interface AttackPathDetail {
  nodes: GraphVertex[];
  edges: GraphEdge[];
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
