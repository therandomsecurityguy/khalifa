"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.riskRules = void 0;
exports.getEnabledRules = getEnabledRules;
exports.getRuleById = getRuleById;
const baseRiskFactors = [
    { name: 'cvss', weight: 0.25, value: 0 },
    { name: 'exposure', weight: 0.2, value: 0 },
    { name: 'identity', weight: 0.2, value: 0 },
    { name: 'dataClassification', weight: 0.2, value: 0 },
    { name: 'environment', weight: 0.15, value: 0 },
];
exports.riskRules = [
    {
        id: 'RULE-001',
        name: 'Internet-Exposed EC2 with High-Privilege IAM Role to Restricted S3',
        description: 'Detects EC2 instances exposed to the internet that have IAM roles allowing access to S3 buckets tagged data_classification=restricted',
        severityHint: 'critical',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'EC2Instance')
        .has('isInternetExposed', true)
        .as('ec2')
        .out('HAS_IAM_ROLE')
        .as('iamRole')
        .out('ALLOWS_ACCESS_TO')
        .has('label', 'S3Bucket')
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
        description: 'Detects security groups that allow unrestricted SSH (port 22) or RDP (port 3389) access',
        severityHint: 'high',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'SecurityGroup')
        .as('sg')
        .out('ALLOWS_INGRESS')
        .has('protocol', within('tcp', 'all'))
        .has('portRange', within(22, 3389))
        .has('cidrBlock', '0.0.0.0/0')
        .in_('ATTACHED_TO')
        .has('label', 'EC2Instance')
        .as('ec2')
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
        description: 'Detects container images with critical severity CVEs running on pods or instances exposed to the internet',
        severityHint: 'critical',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'ContainerImage')
        .as('image')
        .out('HAS_CVE')
        .has('severity', 'CRITICAL')
        .has('cvssBaseScore', gte(9.0))
        .as('cve')
        .in_('RUNS_ON')
        .has('label', within('EC2Instance', 'KubernetesPod'))
        .has('isInternetExposed', true)
        .as('workload')
        .path()
          .by(valueMap(true))
    `,
        ownerTeam: 'container-security',
        enabled: true,
        autoTicketConfig: {
            enabled: true,
            projectKey: 'SEC',
            priority: 'P1',
        },
    },
    {
        id: 'RULE-004',
        name: 'Over-Privileged IAM Roles with Internet-Reachable Workloads',
        description: 'Detects IAM roles with excessive permissions (many ALLOWS_ACCESS_TO edges) attached to internet-reachable EC2 or Lambda',
        severityHint: 'high',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'IAMRole')
        .as('role')
        .out('ALLOWS_ACCESS_TO')
        .count()
        .as('permissionCount')
        .filter(gt(50))
        .in_('HAS_IAM_ROLE')
        .has('label', within('EC2Instance', 'Lambda'))
        .has('isInternetExposed', true)
        .as('workload')
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
        description: 'Detects attack paths of length <= N from special Internet node to nodes tagged crown_jewel=true',
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
        name: 'Cross-Account IAM Trust with Admin Privileges',
        description: 'Detects IAM roles with cross-account trust relationships that grant administrative privileges',
        severityHint: 'critical',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'IAMRole')
        .as('role')
        .out('TRUSTS')
        .has('label', 'AWSAccount')
        .where(neq(__.in('BELONGS_TO')))
        .as('trustedAccount')
        .in_('HAS_IAM_ROLE')
        .out('ALLOWS_ACCESS_TO')
        .out('CONTAINS')
        .has('label', 'IAMPolicy')
        .has('isAdminPolicy', true)
        .as('policy')
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
        description: 'Detects S3 buckets with public access that contain data_classification=restricted or secret',
        severityHint: 'critical',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'S3Bucket')
        .has('isPubliclyAccessible', true)
        .as('bucket')
        .out('STORES')
        .has('data_classification', within('restricted', 'secret'))
        .as('data')
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
        description: 'Detects RDS instances exposed to the internet containing databases tagged with sensitive data',
        severityHint: 'critical',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'RDSInstance')
        .has('isPubliclyAccessible', true)
        .as('rds')
        .out('CONTAINS')
        .has('label', 'Database')
        .has('data_classification', within('restricted', 'secret'))
        .as('db')
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
        name: 'Lambda with VPC and Internet Gateway to Sensitive Resources',
        description: 'Detects Lambda functions in VPCs with internet access that can reach sensitive S3 or DynamoDB',
        severityHint: 'medium',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'Lambda')
        .has('isInVpc', true)
        .has('hasInternetAccess', true)
        .as('lambda')
        .out('ALLOWS_ACCESS_TO')
        .has('label', within('S3Bucket', 'DynamoDBTable'))
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
        description: 'Detects AWS Secrets Manager secrets accessible by broad IAM policies',
        severityHint: 'high',
        riskFactors: [...baseRiskFactors],
        gremlinQueryTemplate: `
      g.V().has('label', 'Secret')
        .has('secretType', 'database')
        .as('secret')
        .in_('ALLOWS_ACCESS_TO')
        .has('label', 'IAMPolicy')
        .as('policy')
        .out('CONTAINS')
        .has('label', 'IAMStatement')
        .has('effect', 'Allow')
        .has('resource', contains('*'))
        .as('statement')
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
function getEnabledRules() {
    return exports.riskRules.filter(rule => rule.enabled);
}
function getRuleById(id) {
    return exports.riskRules.find(rule => rule.id === id);
}
//# sourceMappingURL=rules.js.map