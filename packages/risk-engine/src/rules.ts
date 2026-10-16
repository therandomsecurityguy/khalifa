import type { RiskRule, RiskFactor } from './types';
import { ADMIN_PORT_RANGE_PREDICATE } from './admin-ports';

// Weights mirror FACTOR_WEIGHTS in scoring.ts and sum to 1.0. CVSS was
// removed: no vulnerability source feeds this system (RULE-003 is disabled
// until one exists), so the factor could never fire and its 0.25 weight
// permanently depressed every score, leaving the critical threshold
// unreachable for rules that advertise severityHint 'critical'.
const baseRiskFactors: RiskFactor[] = [
  { name: 'exposure', weight: 0.3, value: 0 },
  { name: 'identity', weight: 0.25, value: 0 },
  { name: 'dataClassification', weight: 0.25, value: 0 },
  { name: 'environment', weight: 0.2, value: 0 },
];

// The runner reads only these vertex properties (arn, display name, and the
// scoring inputs). Projecting them keeps path() payloads small on Neptune
// Serverless and keeps policy documents out of rule results.
const PATH_PROJECTION =
  "path().by(valueMap(true, 'arn', 'name', 'Name', 'is_internet_exposed', 'data_classification', 'crown_jewel', 'env', 'is_admin', 'is_admin_role', 'has_cross_account_trust', 'is_cross_account'))";

export const riskRules: RiskRule[] = [
  {
    id: 'RULE-001',
    name: 'Internet-Exposed EC2 with High-Privilege IAM Role to Restricted S3',
    description:
      'Detects EC2 instances exposed to the internet that have IAM roles allowing access to S3 buckets tagged data_classification=restricted',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('Ec2Instance')
        .has('is_internet_exposed', true)
        .as('ec2')
        .outE('HAS_IAM_ROLE').inV()
        .as('iamRole')
        .outE('ATTACHED_TO').inV()
        .optional(outE('CONTAINS').inV().hasLabel('IamPolicyDocument'))
        .hasLabel('IamPolicyDocument')
        .outE('CONTAINS').inV().hasLabel('IamPolicyStatement')
        .has('effect', 'Allow')
        .outE('GRANTS').inV().hasLabel('S3Bucket')
        .has('data_classification', 'restricted')
        .as('s3Bucket')
        .${PATH_PROJECTION}
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
    name: 'Security Groups Open to the Internet on SSH/RDP',
    description:
      'Detects security group rules that allow unrestricted SSH (port 22) or RDP (port 3389) access to EC2 instances from 0.0.0.0/0 or ::/0. An administration port reachable from the IPv6 internet is exactly as exposed as one reachable from the IPv4 internet',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('SecurityGroupRule')
        .has('direction', 'ingress')
        .has('cidr_block', within('0.0.0.0/0', '::/0'))
        .has('protocol', within('tcp', '-1'))
        .${ADMIN_PORT_RANGE_PREDICATE}
        .as('rule')
        .outE('PART_OF').inV().hasLabel('SecurityGroup').as('sg')
        .outE('PROTECTS').inV()
        .outE('ATTACHED_TO').inV().hasLabel('Ec2Instance').as('ec2')
        .${PATH_PROJECTION}
    `,
    routeLabels: ['SecurityGroupRule', 'SecurityGroup', 'NetworkInterface'],
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
      g.V().hasLabel('ContainerImage')
        .as('image')
        .outE('HAS_CVE').inV()
        .has('severity', 'CRITICAL')
        .has('cvss_base_score', gte(9.0))
        .as('cve')
        .inE('RUNS_ON').outV()
        .hasLabel(within('Ec2Instance', 'KubernetesPod'))
        .has('is_internet_exposed', true)
        .as('workload')
        .${PATH_PROJECTION}
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
    name: 'Admin IAM Role on an Internet-Reachable Workload',
    description:
      'Detects internet-reachable EC2 instances or Lambda functions whose role is admin (the policy evaluator found * or iam:* allowed), so compromising the workload compromises the account. Replaces the old count of more than five attached policies, which said nothing about what the policies grant',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel(within('Ec2Instance', 'LambdaFunction'))
        .has('is_internet_exposed', true)
        .as('workload')
        .outE('HAS_IAM_ROLE').inV()
        .has('is_admin', true)
        .as('role')
        .${PATH_PROJECTION}
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
      g.V().hasLabel('Internet')
        .as('start')
        .repeat(outE().inV().simplePath())
        .until(or(has('crown_jewel', true), loops().is(4)))
        .has('crown_jewel', true)
        .as('target')
        .${PATH_PROJECTION}
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
      'Detects IAM roles trusted by an account Khalifa does not collect that have policy statements granting access to all resources (Resource: *)',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    // Trusts between collected accounts (e.g. the collector role trusted by
    // the hub account) are not outside access.
    gremlinQueryTemplate: `
      g.V().hasLabel('IamRole')
        .as('role')
        .where(
          out('TRUSTS').hasLabel('ExternalAccount')
            .values('account_id').as('trusted')
            .not(V().hasLabel('AwsAccount').values('account_id').where(eq('trusted')))
        )
        .outE('ATTACHED_TO').inV()
        .optional(outE('CONTAINS').inV().hasLabel('IamPolicyDocument'))
        .hasLabel('IamPolicyDocument')
        .outE('CONTAINS').inV().hasLabel('IamPolicyStatement')
        .has('effect', 'Allow')
        .has('has_wildcard_resource', true)
        .as('statement')
        .${PATH_PROJECTION}
    `,
    routeLabels: ['IamPolicy', 'IamPolicyDocument', 'IamPolicyStatement'],
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
      g.V().hasLabel('S3Bucket')
        .has('is_publicly_accessible', true)
        .has('data_classification', within('restricted', 'secret'))
        .as('bucket')
        .${PATH_PROJECTION}
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
      g.V().hasLabel('RdsInstance')
        .has('is_publicly_accessible', true)
        .has('data_classification', within('restricted', 'secret'))
        .as('rds')
        .${PATH_PROJECTION}
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
      g.V().hasLabel('LambdaFunction')
        .has('is_in_vpc', true)
        .has('has_internet_access', true)
        .as('lambda')
        .outE('HAS_IAM_ROLE').inV().as('role')
        .outE('ATTACHED_TO').inV()
        .optional(outE('CONTAINS').inV().hasLabel('IamPolicyDocument'))
        .hasLabel('IamPolicyDocument')
        .outE('CONTAINS').inV().hasLabel('IamPolicyStatement')
        .has('effect', 'Allow')
        .outE('GRANTS').inV().hasLabel(within('S3Bucket', 'DynamoDBTable'))
        .has('data_classification', within('internal', 'restricted', 'secret'))
        .as('resource')
        .${PATH_PROJECTION}
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
      'Detects Secrets Manager secrets granted by policy statements with wildcard resources or cross-account principals, via identity policies attached to roles or via secret resource policies',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('Secret')
        .has('secret_type', 'database')
        .as('secret')
        .inE('GRANTS').outV().hasLabel('IamPolicyStatement')
        .has('effect', 'Allow')
        .or(
          has('has_wildcard_resource', true),
          has('has_cross_account_principal', true)
        )
        .as('statement')
        .inE('CONTAINS').outV().hasLabel('IamPolicyDocument').as('policy')
        .or(
          in('ATTACHED_TO').hasLabel('IamRole'),
          inE('CONTAINS').outV().hasLabel('IamPolicy').inE('ATTACHED_TO').outV().hasLabel('IamRole'),
          in('HAS_RESOURCE_POLICY')
        )
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'iam-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P2',
    },
  },
  {
    id: 'RULE-011',
    name: 'Public S3 Bucket with PII Detected by DSPM Scanner',
    // S3 only. The query also matched RdsInstance, so the rule mapped to both an
    // S3 and an RDS control and each showed the other's findings. The DSPM
    // scanner only classifies S3 buckets, so the RDS branch never matched.
    description:
      'Detects publicly accessible S3 buckets that have a DataClassificationFinding showing PII or secrets',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('S3Bucket')
        .has('is_publicly_accessible', true)
        .as('resource')
        .inE('CLASSIFIES').outV().hasLabel('DataClassificationFinding')
        .has('data_classification', within('restricted', 'secret'))
        .as('finding')
        .${PATH_PROJECTION}
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
    id: 'RULE-012',
    name: 'Secret Committed in S3 Object or Lambda Environment',
    description:
      'Detects DataClassificationFinding vertices with secrets (private keys, AWS keys, high-entropy) on S3 buckets or in Lambda function environment variables regardless of public access',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('DataClassificationFinding')
        .has('secret_count', gt(0))
        .as('finding')
        .outE('CLASSIFIES').inV().hasLabel(within('S3Bucket', 'LambdaFunction'))
        .as('resource')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'data-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P2',
    },
  },
  {
    id: 'RULE-013',
    name: 'IAM User with Active Access Key Older Than 90 Days',
    description:
      'Detects active IAM user access keys that were created more than 90 days ago. Long-lived static keys are the primary exfiltration vector; convert users to roles or short-lived credentials',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('AccessKey')
        .has('status', 'Active')
        .has('key_age_days', gt(90))
        .as('key')
        .inE('HAS_ACCESS_KEY').outV().hasLabel('IamUser')
        .as('user')
        .${PATH_PROJECTION}
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
    id: 'RULE-014',
    name: 'IAM Access Key Unused for 90+ Days',
    description:
      'Detects active IAM user access keys with no recorded usage in the last 90 days. Unused keys are pure credential-sprawl risk and should be deleted, not rotated',
    severityHint: 'medium',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('AccessKey')
        .has('status', 'Active')
        .has('last_used_days_ago', gt(90))
        .as('key')
        .inE('HAS_ACCESS_KEY').outV().hasLabel('IamUser')
        .as('user')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'iam-security',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-015',
    name: 'IAM User with Console Access and No MFA',
    description:
      'Detects IAM users that can sign in to the AWS console without any MFA device registered. A phished password yields full console access',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('IamUser')
        .has('password_enabled', true)
        .has('mfa_enabled', false)
        .as('user')
        .${PATH_PROJECTION}
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
    id: 'RULE-016',
    name: 'Wildcard Secrets Manager Access Granted to a Principal',
    description:
      'Detects identity policy statements attached to users, roles, or groups that allow secretsmanager GetSecretValue or BatchGetSecretValue against wildcard resources. GetSecretValue on * is the credential-exfiltration pattern; scope grants to explicit secret ARNs',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('IamPolicyStatement')
        .has('effect', 'Allow')
        .has('grants_secret_read', true)
        .has('secret_grant_scope', 'wildcard')
        .as('statement')
        .inE('CONTAINS').outV().hasLabel('IamPolicyDocument').as('policy')
        .optional(inE('CONTAINS').outV().hasLabel('IamPolicy'))
        .inE('ATTACHED_TO').outV().hasLabel(within('IamRole', 'IamUser', 'IamGroup')).as('principal')
        .${PATH_PROJECTION}
    `,
    routeLabels: ['IamPolicy', 'IamPolicyDocument', 'IamPolicyStatement'],
    ownerTeam: 'iam-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P1',
    },
  },
  {
    id: 'RULE-017',
    name: 'GuardDuty Disabled or Missing in a Collected Region',
    description:
      'Detects regions with a disabled GuardDuty detector or no detector at all (synthetic MISSING vertex). GuardDuty absent is how a cluster-admin token used from another country produces no signal',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('GuardDutyDetector')
        .has('status', within('DISABLED', 'MISSING'))
        .as('detector')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'detection-response',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P1',
    },
  },
  {
    id: 'RULE-018',
    name: 'Critical Security Hub Finding on an Internet-Exposed Resource',
    description:
      'Detects active critical or high Security Hub findings linked to resources the graph derives as internet-exposed, joining detection signals to exposure',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('SecurityHubFinding')
        .has('severity', within('CRITICAL', 'HIGH'))
        .has('record_state', 'ACTIVE')
        .not(has('workflow_state', within('SUPPRESSED', 'RESOLVED')))
        .as('finding')
        .outE('DETECTS_ON').inV()
        .has('is_internet_exposed', true)
        .as('resource')
        .${PATH_PROJECTION}
    `,
    routeLabels: ['SecurityHubFinding'],
    ownerTeam: 'detection-response',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P1',
    },
  },
  {
    id: 'RULE-019',
    name: 'EKS Cluster with Public API Endpoint Open to the World',
    description:
      'Detects EKS clusters whose Kubernetes API endpoint is publicly reachable from any CIDR (0.0.0.0/0 or unrestricted). Public control planes let any internet host attempt authentication; move endpoints private or allowlist specific CIDRs',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('EksCluster')
        .has('endpoint_public_access', true)
        .has('endpoint_world_open', true)
        .as('cluster')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'container-security',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P0',
    },
  },
  {
    id: 'RULE-020',
    name: 'Root Identity Activity in CloudTrail',
    description:
      'Detects CloudTrail activity by the root identity from the daily analyzer. Routine work should never run as root; every root event is either an emergency or an attacker',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('CloudTrailAnomaly')
        .has('anomaly_type', 'ROOT_USAGE')
        .as('anomaly')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'detection-response',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P2',
    },
  },
  {
    id: 'RULE-021',
    name: 'Secrets Read from a Previously Unseen Source IP',
    description:
      'Detects Secrets Manager reads (GetSecretValue, BatchGetSecretValue) from source IPs that first appeared within 7 days for a principal with a longer activity history. Secrets exfiltration from new infrastructure is the incident pattern',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('CloudTrailAnomaly')
        .has('anomaly_type', 'SECRET_READ_NEW_SOURCE_IP')
        .as('anomaly')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'detection-response',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P0',
    },
  },
  {
    id: 'RULE-022',
    name: 'AccessDenied Spike from a Principal',
    description:
      'Detects principals generating bursts of AccessDenied errors, which typically precede or accompany credential probing and boundary exploration',
    severityHint: 'medium',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('CloudTrailAnomaly')
        .has('anomaly_type', 'ACCESS_DENIED_SPIKE')
        .as('anomaly')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'detection-response',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-023',
    name: 'Canary Credential Used',
    description:
      'Detects any CloudTrail activity from a canary credential. Canary keys are planted decoys with no legitimate use, so any use is a security incident: an attacker found and tried the credential',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('CloudTrailAnomaly')
        .has('anomaly_type', 'CANARY_USED')
        .as('anomaly')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'detection-response',
    enabled: true,
    autoTicketConfig: {
      enabled: true,
      projectKey: 'SEC',
      priority: 'P0',
    },
  },
  {
    id: 'RULE-024',
    name: 'EC2 Instance with IMDSv1 and an IAM Role',
    description:
      'Detects running EC2 instances that still allow IMDSv1 (metadata_http_tokens optional) while holding an instance profile. A single SSRF bug leaks the role credentials; require IMDSv2',
    severityHint: 'medium',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('Ec2Instance')
        .has('metadata_http_tokens', 'optional')
        .not(has('state', within('terminated', 'shutting-down')))
        .as('ec2')
        .outE('HAS_IAM_ROLE').inV()
        .as('role')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'cloud-security',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-025',
    name: 'IAM Access Analyzer Not Active',
    description:
      'Detects IAM Access Analyzer instances that exist but are not ACTIVE. An inactive analyzer stops reporting resources shared with an external entity, so cross-account exposure accumulates unseen. Note this cannot detect an account with no analyzer at all: unlike GuardDuty, the collector emits no synthetic MISSING vertex for Access Analyzer',
    severityHint: 'high',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('AccessAnalyzer')
        .not(has('status', 'ACTIVE'))
        .as('analyzer')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'cloud-security',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-026',
    name: 'Customer-Managed KMS Key Without Rotation',
    description:
      'Detects enabled customer-managed KMS keys with automatic rotation disabled. Rotation bounds how much data a single key version protects, so a compromised key version has a limited blast radius. AWS-managed keys rotate on their own and are excluded',
    severityHint: 'medium',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('KmsKey')
        .has('key_manager', 'CUSTOMER')
        .has('key_state', 'Enabled')
        .or(has('rotation_enabled', false), hasNot('rotation_enabled'))
        .as('key')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'cloud-security',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-027',
    name: 'VPC Without Flow Logs Enabled',
    description:
      'Detects VPCs with no flow logs. Without them there is no record of accepted or rejected network traffic, so lateral movement and exfiltration leave no evidence to investigate after the fact',
    severityHint: 'medium',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('Vpc')
        .has('flow_logs_enabled', false)
        .as('vpc')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'network-security',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-028',
    name: 'AWS Config Recorder Not Recording',
    description:
      'Detects AWS Config recorders that exist but are not recording. Config is the configuration-history source for drift and post-incident reconstruction; a stopped recorder means that history silently ends. Cannot detect a region with no recorder at all, since the collector emits no synthetic MISSING vertex for Config',
    severityHint: 'medium',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('ConfigRecorder')
        .has('recording', false)
        .as('recorder')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'cloud-security',
    enabled: true,
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-029',
    name: 'Active GuardDuty Attack Finding on an Internet-Exposed Resource',
    description:
      'Detects unarchived GuardDuty findings of an attack class (unauthorized access, backdoor, credential access, and similar) on a resource the graph derives as internet-exposed. Findings come from the delegated administrator, so this covers every member account and region with a detector. Recon and Policy findings are excluded, and so is LOW severity: an exposed port being probed or brute-forced is what exposure already says (in September 2026 every SSHBruteForce finding was LOW, with the instance as TARGET), and Policy findings are configuration, not attack',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel('GuardDutyFinding')
        .has('finding_class', within('Backdoor', 'CredentialAccess', 'CryptoCurrency', 'DefenseEvasion', 'Discovery', 'Execution', 'Exfiltration', 'Impact', 'InitialAccess', 'Persistence', 'PrivilegeEscalation', 'Stealth', 'Trojan', 'UnauthorizedAccess'))
        .has('severity', gte(4))
        .as('finding')
        .outE('DETECTS_ON').inV()
        .has('is_internet_exposed', true)
        .as('resource')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'detection-response',
    enabled: true,
    // No tickets until its firing rate has been observed on real data.
    autoTicketConfig: {
      enabled: false,
    },
  },
  {
    id: 'RULE-030',
    name: 'Principal Can Escalate to an Admin or Privilege-Escalation Role',
    description:
      'Detects a principal that can assume its way, in up to three hops, to an admin role or to a role holding privilege-escalation actions. The policy evaluator writes CAN_ESCALATE_TO for these paths daily and removes it when the path is gone. A source ending in :root is an account: any user or role there whose own policy allows sts:AssumeRole. Follows trust policies only; escalation through iam:PassRole or policy edits is not traced',
    severityHint: 'critical',
    riskFactors: [...baseRiskFactors],
    gremlinQueryTemplate: `
      g.V().hasLabel(within('AwsAccount', 'IamRole', 'IamUser'))
        .as('source')
        .outE('CAN_ESCALATE_TO').has('risk_level', within('critical', 'high')).inV()
        .hasLabel('IamRole')
        .as('target')
        .${PATH_PROJECTION}
    `,
    ownerTeam: 'iam-security',
    enabled: true,
    // No tickets until its firing rate has been observed on real data.
    autoTicketConfig: {
      enabled: false,
    },
  },
];

export function getEnabledRules(): RiskRule[] {
  return riskRules.filter((rule) => rule.enabled);
}

export function getRuleById(id: string): RiskRule | undefined {
  return riskRules.find((rule) => rule.id === id);
}
