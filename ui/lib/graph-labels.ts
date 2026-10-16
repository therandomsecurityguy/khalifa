import type { GraphVertex } from '@/types';

const TYPE_LABELS: Record<string, string> = {
  Internet: 'Internet',
  InternetGateway: 'Internet gateway',
  LoadBalancer: 'Load balancer',
  SecurityGroup: 'Security group',
  SecurityGroupRule: 'SG rule',
  Ec2Instance: 'EC2 instance',
  EC2Instance: 'EC2 instance',
  NetworkInterface: 'ENI',
  LambdaFunction: 'Lambda',
  Lambda: 'Lambda',
  LambdaAlias: 'Lambda alias',
  IamRole: 'IAM role',
  IAMRole: 'IAM role',
  IamUser: 'IAM user',
  IAMUser: 'IAM user',
  IamGroup: 'IAM group',
  IamPolicy: 'IAM policy',
  IamPolicyDocument: 'IAM policy document',
  IamPolicyStatement: 'IAM statement',
  AccessKey: 'Access key',
  S3Bucket: 'S3 bucket',
  Secret: 'Secret',
  RdsInstance: 'RDS instance',
  RDSInstance: 'RDS instance',
  DataClassificationFinding: 'Secret finding',
  ExternalAccount: 'External account',
  Account: 'Account',
  GuardDutyDetector: 'GuardDuty detector',
  SecurityHubFinding: 'Security Hub finding',
  SecurityHub: 'Security Hub',
  CloudTrailAnomaly: 'CloudTrail anomaly',
  EksCluster: 'EKS cluster',
  Missing: 'Not in graph',
};

export function formatNodeLabel(label: string): string {
  if (!label) return 'Unknown';
  if (TYPE_LABELS[label]) return TYPE_LABELS[label];
  return label
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/_/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

export function nodeName(node: GraphVertex): string {
  const name = node.properties?.name;
  if (typeof name === 'string' && name) return name;
  const parts = node.id.split(/[:/]/);
  return parts[parts.length - 1] || node.id;
}
