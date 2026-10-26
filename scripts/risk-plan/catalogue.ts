// The catalogue entries plan findings attribute to, kept local so the CLI needs
// no build of the risk engine at runtime. catalogue.test.ts asserts every entry
// still matches the engine's catalogue (name and severity hint), so drift fails
// CI instead of shipping a wrong label.
export type PlanSeverity = 'critical' | 'high' | 'medium' | 'low';

export const RULE_CATALOGUE: Record<string, { name: string; severity: PlanSeverity }> = {
  'RULE-002': { name: 'Security Groups Open to the Internet on SSH/RDP', severity: 'high' },
  'RULE-006': {
    name: 'Cross-Account IAM Trust with Wildcard Resource Access',
    severity: 'critical',
  },
  'RULE-007': { name: 'Public S3 Buckets with Sensitive Data', severity: 'critical' },
  'RULE-008': { name: 'RDS with Public Access and Sensitive Data', severity: 'critical' },
  'RULE-009': {
    name: 'Internet-Exposed Lambda Whose Role Reaches Sensitive Data',
    severity: 'medium',
  },
  'RULE-010': {
    name: 'Secret Shared Outside Collected Accounts by Its Resource Policy',
    severity: 'high',
  },
  'RULE-019': {
    name: 'EKS Cluster with Public API Endpoint Open to the World',
    severity: 'critical',
  },
  'RULE-024': { name: 'EC2 Instance with IMDSv1 and an IAM Role', severity: 'medium' },
};

export const SEVERITY_RANK: Record<PlanSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function isSeverity(value: string): value is PlanSeverity {
  return value in SEVERITY_RANK;
}
