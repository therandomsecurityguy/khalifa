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
  metadata: Record<string, any>;
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
  details?: Record<string, any>;
}
