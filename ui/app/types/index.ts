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
  metadata: Record<string, any>;
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
  properties: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  label: string;
  from: string;
  to: string;
  properties?: Record<string, any>;
}

export interface IssueDetail extends Issue {
  attackPath: {
    nodes: GraphVertex[];
    edges: GraphEdge[];
  };
}

export interface IssueFilters {
  severity?: Severity[];
  team?: string[];
  status?: IssueStatus[];
  limit?: number;
  nextToken?: string;
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface IssueStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  byTeam: Record<string, number>;
  byRule: Record<string, number>;
}
