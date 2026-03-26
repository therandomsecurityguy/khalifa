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
    riskFactors: RiskFactor[];
    gremlinQueryTemplate: string;
    ownerTeam: string;
    enabled: boolean;
    autoTicketConfig: AutoTicketConfig;
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
export interface CvssScore {
    baseScore: number;
    exploitabilitySubScore: number;
    impactSubScore: number;
    vectorString: string;
}
export interface IdentityBlastRadius {
    type: 'admin' | 'wildcard' | 'cross-account' | 'service-linked';
    scope: number;
}
export interface RiskScoreInput {
    cvss?: CvssScore;
    exploitabilityFlags?: {
        hasExploit: boolean;
        hasPublicExploit: boolean;
        malwareAvailable: boolean;
    };
    exposureLevel: ExposureLevel;
    identityBlastRadius?: IdentityBlastRadius;
    dataClassification: DataClassification;
    environment: Environment;
    attackPathLength?: number;
    isCrownJewel: boolean;
}
export interface RiskScoreOutput {
    score: number;
    severity: Severity;
    factors: {
        cvssContribution: number;
        exposureContribution: number;
        identityContribution: number;
        dataClassificationContribution: number;
        environmentContribution: number;
        crownJewelContribution: number;
    };
}
//# sourceMappingURL=types.d.ts.map