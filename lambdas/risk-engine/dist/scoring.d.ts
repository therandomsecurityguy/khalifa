import { RiskScoreInput, RiskScoreOutput } from './types';
export declare function computeRiskScore(input: RiskScoreInput): RiskScoreOutput;
export declare function extractResourcesFromPath(path: any[]): {
    resourceIds: string[];
    resourceTypes: string[];
};
export declare function calculatePathSummary(path: any[]): {
    segments: {
        from: string;
        to: string;
        edgeType: string;
    }[];
};
export declare function getRemediationHint(ruleId: string, context: Record<string, any>): string;
//# sourceMappingURL=scoring.d.ts.map