import { RiskRule, RuleExecutionResult } from './types';
export declare class RiskRuleRunner {
    private neptuneClient;
    private issueStore;
    constructor(neptuneEndpoint: string);
    initialize(): Promise<void>;
    shutdown(): Promise<void>;
    runRule(rule: RiskRule): Promise<RuleExecutionResult>;
    runAllRules(): Promise<RuleExecutionResult[]>;
    private extractPathFromMatch;
    private extractProperties;
    private extractResourcesFromPath;
    private createIssueFromMatch;
    private buildRiskInput;
}
export declare function resolveStaleIssues(neptuneEndpoint: string): Promise<number>;
//# sourceMappingURL=runner.d.ts.map