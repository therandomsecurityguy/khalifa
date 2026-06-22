import type { RiskRule, RiskFactor } from './types';

const baseRiskFactors: RiskFactor[] = [
  { name: 'cvss', weight: 0.25, value: 0 },
  { name: 'exposure', weight: 0.2, value: 0 },
  { name: 'identity', weight: 0.2, value: 0 },
  { name: 'dataClassification', weight: 0.2, value: 0 },
  { name: 'environment', weight: 0.15, value: 0 },
];

export const riskRules: RiskRule[] = [
  {
    id: 'RULE-001',
    name: 'Internet-Exposed EC2 with High-Privilege IAM Role to Restricted S3',
    description:
      'Detects EC2 instances exposed to the internet that have IAM roles allowing access to S3 buckets tagged data_classification=restricted',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'Ec2Instance')
        .has('is_internet_exposed', true)
        .as('ec2')
        .out('HAS_IAM_ROLE')
        .as('iamRole')
        .out('ATTACHED_TO').has('label', 'IamPolicyDocument')
        .out('CONTAINS').has('label', 'IamPolicyStatement')
        .out('GRANTS').has('label', 'S3Bucket')
        .has('data_classification', 'restricted')
        .as('s3Bucket')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'cloud-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P1',
    },
  },
  {
    id: 'RULE-002',
    name: 'Security Groups with 0.0.0.0/0 on SSH/RDP',
    description:
      'Detects security group rules that allow unrestricted SSH (port 22) or RDP (port 3389) access to EC2 instances',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'SecurityGroupRule')
        .has('cidr_block', '0.0.0.0/0')
        .has('protocol', within('tcp', '-1'))
        .or(has('port_from', 22), has('port_from', 3389), has('port_from', 0))
        .as('rule')
        .out('PART_OF').has('label', 'SecurityGroup').as('sg')
        .out('PROTECTS')
        .out('ATTACHED_TO').has('label', 'Ec2Instance').as('ec2')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'network-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P2',
    },
  },
  {
    id: 'RULE-003',
    name: 'Container Images with Critical CVEs on Internet-Exposed Workloads',
    description:
      'Detects container images with critical severity CVEs running on pods or instances exposed to the internet. Disabled until vulnerability scanning is implemented.',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'ContainerImage')
        .as('image')
        .out('HAS_CVE')
        .has('severity', 'CRITICAL')
        .has('cvss_base_score', gte(9.0))
        .as('cve')
        .in_('RUNS_ON')
        .has('label', within('Ec2Instance', 'KubernetesPod'))
        .has('is_internet_exposed', true)
        .as('workload')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'container-security',
    enabled: false,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P1',
    },
  },
  {
    id: 'RULE-004',
    name: 'Over-Privileged IAM Roles with Internet-Reachable Workloads',
    description:
      'Detects IAM roles with excessive attached policies connected to internet-reachable EC2 or Lambda',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', within('Ec2Instance', 'LambdaFunction'))
        .has('is_internet_exposed', true)
        .as('workload')
        .out('HAS_IAM_ROLE')
        .as('role')
        .where(out('ATTACHED_TO').count().is(gt(5)))
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'iam-security',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-005',
    name: 'Crown Jewel Attack Path from Internet',
    description:
      'Detects attack paths of length <= N from special Internet node to nodes tagged crown_jewel=true',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'Internet')
        .as('start')
        .repeat(
          out().simplePath()
        ).times(4)
        .until(
          has('crown_jewel', true)
        )
        .has('crown_jewel', true)
        .as('target')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'red-team',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P0',
    },
  },
  {
    id: 'RULE-006',
    name: 'Cross-Account IAM Trust with Wildcard Resource Access',
    description:
      'Detects IAM roles with cross-account trust relationships that have policy statements granting access to all resources (Resource: *)',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'IamRole')
        .as('role')
        .where(out('TRUSTS'))
        .out('ATTACHED_TO').has('label', 'IamPolicyDocument')
        .out('CONTAINS').has('label', 'IamPolicyStatement')
        .has('effect', 'Allow')
        .has('has_wildcard_resource', true)
        .as('statement')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'iam-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P1',
    },
  },
  {
    id: 'RULE-007',
    name: 'Public S3 Buckets with Sensitive Data',
    description:
      'Detects S3 buckets with public access that are tagged data_classification=restricted or secret',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'S3Bucket')
        .has('is_publicly_accessible', true)
        .has('data_classification', within('restricted', 'secret'))
        .as('bucket')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'data-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P1',
    },
  },
  {
    id: 'RULE-008',
    name: 'RDS with Public Access and Sensitive Data',
    description:
      'Detects RDS instances with public access that are tagged with sensitive data classification',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'RdsInstance')
        .has('is_publicly_accessible', true)
        .has('data_classification', within('restricted', 'secret'))
        .as('rds')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'data-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P1',
    },
  },
  {
    id: 'RULE-009',
    name: 'Lambda with VPC and Internet Access to Sensitive Resources',
    description:
      'Detects Lambda functions in VPCs with internet access whose IAM role grants access to sensitive S3 or DynamoDB',
    severityHint: 'medium',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'LambdaFunction')
        .has('is_in_vpc', true)
        .has('has_internet_access', true)
        .as('lambda')
        .out('HAS_IAM_ROLE').as('role')
        .out('ATTACHED_TO').has('label', 'IamPolicyDocument')
        .out('CONTAINS').has('label', 'IamPolicyStatement')
        .out('GRANTS').has('label', within('S3Bucket', 'DynamoDBTable'))
        .has('data_classification', within('internal', 'restricted', 'secret'))
        .as('resource')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'app-security',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-010',
    name: 'Secrets Manager Secrets with Overly Permissive IAM',
    description:
      'Detects AWS Secrets Manager secrets accessible by IAM policy statements that grant access to all resources (Resource: *)',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().has('label', 'Secret')
        .has('secret_type', 'database')
        .as('secret')
        .in_('GRANTS').has('label', 'IamPolicyStatement')
        .has('effect', 'Allow')
        .has('has_wildcard_resource', true)
        .as('statement')
        .in_('CONTAINS').has('label', 'IamPolicyDocument').as('policy')
        .in_('ATTACHED_TO').has('label', 'IamRole').as('role')
        .path()
          .by(valueMap(true))
    `,
    ownerTeam: 'iam-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P2',
    },
  },
];

export function getEnabledRules(): RiskRule[] {
  return riskRules.filter((rule) => rule.enabled);
}

export function getRuleById(id: string): RiskRule | undefined {
  return riskRules.find((rule) => rule.id === id);
}
