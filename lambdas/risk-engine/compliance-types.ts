export type ComplianceFramework = 'CIS_AWS_FOUNDATIONS' | 'SOC2' | 'ISO27001';

export type ComplianceControlStatus = 'PASS' | 'FAIL' | 'MANUAL' | 'NOT_APPLICABLE' | 'NOT_EVALUATED';

export interface ComplianceControl {
  id: string;
  framework: ComplianceFramework;
  section: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  automated: boolean;
  relatedRules: string[];
  evidenceRequirements: string[];
  remediationGuidance: string;
}

export interface ComplianceEvidence {
  controlId: string;
  resourceId: string;
  resourceType: string;
  status: ComplianceControlStatus;
  details: Record<string, any>;
  collectedAt: string;
  collectedBy: string;
}

export interface ComplianceReport {
  framework: ComplianceFramework;
  generatedAt: string;
  summary: {
    totalControls: number;
    passed: number;
    failed: number;
    manual: number;
    notApplicable: number;
    notEvaluated: number;
    coveragePercent: number;
  };
  controls: ComplianceControlResult[];
}

export interface ComplianceControlResult {
  control: ComplianceControl;
  status: ComplianceControlStatus;
  evidence: ComplianceEvidence[];
  issues: string[];
  lastEvaluated: string;
}

export interface ComplianceFrameworkSummary {
  framework: ComplianceFramework;
  version: string;
  totalControls: number;
  automatedControls: number;
  manualControls: number;
  coveragePercent: number;
  lastAssessment: string;
}

export const CIS_AWS_FOUNDATIONS_V3_CONTROLS: ComplianceControl[] = [
  {
    id: '1.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Maintain current contact details for the AWS account',
    description: 'Ensure the contact information for the AWS account is current and maps to more than one individual.',
    severity: 'low',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Account contact information'],
    remediationGuidance: 'Update account contact information in AWS Account Settings to include multiple individuals.'
  },
  {
    id: '1.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure security contact information is registered',
    description: 'Ensure security contact information is registered for the AWS account.',
    severity: 'low',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Security contact information'],
    remediationGuidance: 'Register security contact information in AWS Account Settings.'
  },
  {
    id: '1.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure security questions are registered',
    description: 'Ensure security questions are registered for the AWS account.',
    severity: 'low',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Security questions registered'],
    remediationGuidance: 'Register security questions in AWS Account Settings.'
  },
  {
    id: '1.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure no root account access key exists',
    description: 'Ensure no access keys exist for the root user.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['IAM credential report showing no root access keys'],
    remediationGuidance: 'Delete any root access keys. Use IAM users/roles instead.'
  },
  {
    id: '1.5',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure MFA is enabled for the root account',
    description: 'Ensure multi-factor authentication (MFA) is enabled for the root user.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['IAM credential report showing root MFA enabled'],
    remediationGuidance: 'Enable MFA for the root account in IAM console.'
  },
  {
    id: '1.6',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure hardware MFA is enabled for the root account',
    description: 'Ensure hardware MFA is enabled for the root user.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['IAM credential report showing hardware MFA for root'],
    remediationGuidance: 'Enable hardware MFA (e.g., YubiKey) for root account.'
  },
  {
    id: '1.7',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure MFA is enabled for all IAM users with console password',
    description: 'Ensure MFA is enabled for all IAM users that have a console password.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['IAM credential report showing MFA for all console users'],
    remediationGuidance: 'Enforce MFA for all IAM users with console access.'
  },
  {
    id: '1.8',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure hardware MFA is enabled for all IAM users with console password',
    description: 'Ensure hardware MFA is enabled for all IAM users that have a console password.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['IAM credential report showing hardware MFA for console users'],
    remediationGuidance: 'Enforce hardware MFA for all IAM users with console access.'
  },
  {
    id: '1.9',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure root account hardware MFA is enabled',
    description: 'Ensure root account uses hardware MFA.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['Root account MFA type is hardware'],
    remediationGuidance: 'Replace virtual MFA with hardware MFA for root account.'
  },
  {
    id: '1.10',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure access keys are rotated every 90 days or less',
    description: 'Ensure IAM user access keys are rotated every 90 days.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['IAM credential report showing key age <= 90 days'],
    remediationGuidance: 'Rotate access keys older than 90 days. Implement automated rotation.'
  },
  {
    id: '1.11',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM users have no unused access keys',
    description: 'Remove access keys that have not been used in 90 days.',
    severity: 'medium',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['IAM credential report showing no unused keys > 90 days'],
    remediationGuidance: 'Delete unused access keys. Monitor key usage regularly.'
  },
  {
    id: '1.12',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure no IAM users have inline policies',
    description: 'Ensure IAM users do not have inline policies attached.',
    severity: 'medium',
    automated: true,
    relatedRules: ['RULE-004', 'RULE-006'],
    evidenceRequirements: ['IAM users with no inline policies'],
    remediationGuidance: 'Move inline policies to managed policies. Use managed policies for all users.'
  },
  {
    id: '1.13',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM password policy requires minimum length of 14',
    description: 'Ensure IAM password policy requires minimum password length of 14.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM password policy MinPasswordLength >= 14'],
    remediationGuidance: 'Update IAM password policy to require minimum 14 characters.'
  },
  {
    id: '1.14',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM password policy prevents password reuse',
    description: 'Ensure IAM password policy prevents password reuse (at least 24 generations).',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM password policy PasswordReusePrevention >= 24'],
    remediationGuidance: 'Update IAM password policy to prevent reuse of last 24 passwords.'
  },
  {
    id: '1.15',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM password policy expires passwords within 90 days',
    description: 'Ensure IAM password policy expires passwords within 90 days.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM password policy MaxPasswordAge <= 90'],
    remediationGuidance: 'Set password expiration to 90 days or less.'
  },
  {
    id: '1.16',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure no root account access key exists',
    description: 'Ensure no access keys exist for the root user.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['No root access keys in credential report'],
    remediationGuidance: 'Delete any root access keys immediately.'
  },
  {
    id: '1.17',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure MFA is enabled for the root account',
    description: 'Ensure multi-factor authentication (MFA) is enabled for the root user.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['Root MFA enabled in credential report'],
    remediationGuidance: 'Enable MFA for root account.'
  },
  {
    id: '1.18',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure hardware MFA is enabled for the root account',
    description: 'Ensure hardware MFA is enabled for the root user.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['Root MFA type is hardware'],
    remediationGuidance: 'Use hardware MFA device for root account.'
  },
  {
    id: '1.19',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM users are in at least one group',
    description: 'Ensure all IAM users are members of at least one IAM group.',
    severity: 'low',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['All IAM users have at least one group membership'],
    remediationGuidance: 'Assign all IAM users to appropriate groups.'
  },
  {
    id: '1.20',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM policies are attached only to groups or roles',
    description: 'Ensure IAM policies are attached only to groups or roles, not users.',
    severity: 'medium',
    automated: true,
    relatedRules: ['RULE-004', 'RULE-006'],
    evidenceRequirements: ['No policies attached directly to users'],
    remediationGuidance: 'Move user-attached policies to groups or roles.'
  },
  {
    id: '1.21',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure a support role has been created to manage incidents',
    description: 'Ensure a support role exists for incident management.',
    severity: 'low',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Support role with appropriate permissions exists'],
    remediationGuidance: 'Create a support role with least-privilege permissions for incident response.'
  },
  {
    id: '1.22',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM instance roles are used for AWS resource access from instances',
    description: 'Ensure EC2 instances use IAM roles instead of access keys.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-001', 'RULE-004'],
    evidenceRequirements: ['No EC2 instances with access keys in user data or metadata'],
    remediationGuidance: 'Attach IAM roles to EC2 instances. Remove hardcoded credentials.'
  },
  {
    id: '2.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure S3 buckets are not publicly accessible',
    description: 'Ensure S3 buckets do not allow public read or write access.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-007'],
    evidenceRequirements: ['S3 bucket public access block enabled, no public bucket policies'],
    remediationGuidance: 'Enable S3 Block Public Access. Review and remove public bucket policies/ACLs.'
  },
  {
    id: '2.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure S3 buckets have versioning enabled',
    description: 'Ensure S3 buckets have versioning enabled to protect against accidental deletion.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['S3 bucket versioning status = Enabled'],
    remediationGuidance: 'Enable versioning on all S3 buckets.'
  },
  {
    id: '2.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure S3 buckets have server-side encryption enabled',
    description: 'Ensure S3 buckets have default server-side encryption (SSE-S3 or SSE-KMS).',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-007'],
    evidenceRequirements: ['S3 bucket default encryption configured'],
    remediationGuidance: 'Enable default encryption on all S3 buckets. Use SSE-KMS for sensitive data.'
  },
  {
    id: '2.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure S3 bucket access logging is enabled',
    description: 'Ensure S3 buckets have access logging enabled to a target bucket.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['S3 bucket logging configuration present'],
    remediationGuidance: 'Configure access logging for all S3 buckets to a centralized log bucket.'
  },
  {
    id: '2.5',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure S3 bucket replication is enabled for critical data',
    description: 'Ensure critical S3 buckets have cross-region replication enabled.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Cross-region replication configured for critical buckets'],
    remediationGuidance: 'Enable CRR for buckets containing critical data.'
  },
  {
    id: '2.6',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure EBS volumes are encrypted',
    description: 'Ensure all EBS volumes are encrypted at rest.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['All EBS volumes have Encrypted=true'],
    remediationGuidance: 'Enable encryption by default for EBS. Encrypt existing unencrypted volumes.'
  },
  {
    id: '2.7',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure RDS instances are encrypted',
    description: 'Ensure all RDS instances have storage encryption enabled.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-008'],
    evidenceRequirements: ['RDS instances have StorageEncrypted=true'],
    remediationGuidance: 'Enable encryption for RDS instances. Recreate unencrypted instances from encrypted snapshots.'
  },
  {
    id: '2.8',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure RDS instances have backup retention >= 7 days',
    description: 'Ensure RDS instances have automated backup retention of at least 7 days.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['RDS BackupRetentionPeriod >= 7'],
    remediationGuidance: 'Set automated backup retention to 7 days or more.'
  },
  {
    id: '2.9',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure RDS instances are not publicly accessible',
    description: 'Ensure RDS instances do not have public accessibility enabled.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-008'],
    evidenceRequirements: ['RDS PubliclyAccessible=false'],
    remediationGuidance: 'Disable public accessibility on RDS instances. Use VPC and security groups.'
  },
  {
    id: '2.10',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure RDS instances have deletion protection enabled',
    description: 'Ensure RDS instances have deletion protection enabled.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['RDS DeletionProtection=true'],
    remediationGuidance: 'Enable deletion protection on all RDS instances.'
  },
  {
    id: '2.11',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure Redshift clusters are encrypted',
    description: 'Ensure Redshift clusters have encryption enabled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Redshift clusters have Encrypted=true'],
    remediationGuidance: 'Enable encryption for Redshift clusters. Recreate from encrypted snapshots if needed.'
  },
  {
    id: '2.12',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure Redshift clusters are not publicly accessible',
    description: 'Ensure Redshift clusters do not have public accessibility enabled.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Redshift PubliclyAccessible=false'],
    remediationGuidance: 'Disable public accessibility on Redshift clusters.'
  },
  {
    id: '2.13',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure Elasticache clusters are encrypted in transit and at rest',
    description: 'Ensure ElastiCache clusters have encryption in transit and at rest.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['ElastiCache TransitEncryptionEnabled=true, AtRestEncryptionEnabled=true'],
    remediationGuidance: 'Enable encryption in transit and at rest for ElastiCache clusters.'
  },
  {
    id: '2.14',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure OpenSearch domains are encrypted at rest',
    description: 'Ensure OpenSearch domains have encryption at rest enabled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['OpenSearch EncryptionAtRestOptions.Enabled=true'],
    remediationGuidance: 'Enable encryption at rest for OpenSearch domains.'
  },
  {
    id: '2.15',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure OpenSearch domains enforce HTTPS',
    description: 'Ensure OpenSearch domains enforce HTTPS for all traffic.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['OpenSearch DomainEndpointOptions.EnforceHTTPS=true'],
    remediationGuidance: 'Enforce HTTPS on OpenSearch domain endpoints.'
  },
  {
    id: '2.16',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure OpenSearch domains have node-to-node encryption',
    description: 'Ensure OpenSearch domains have node-to-node encryption enabled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['OpenSearch NodeToNodeEncryptionOptions.Enabled=true'],
    remediationGuidance: 'Enable node-to-node encryption for OpenSearch domains.'
  },
  {
    id: '3.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure CloudTrail is enabled in all regions',
    description: 'Ensure CloudTrail trails are enabled in all regions.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail trails exist in all regions, IsMultiRegionTrail=true'],
    remediationGuidance: 'Create multi-region CloudTrail trail. Enable in all regions.'
  },
  {
    id: '3.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure CloudTrail log file validation is enabled',
    description: 'Ensure CloudTrail log file integrity validation is enabled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail LogFileValidationEnabled=true'],
    remediationGuidance: 'Enable log file validation on all CloudTrail trails.'
  },
  {
    id: '3.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure CloudTrail logs are encrypted with KMS',
    description: 'Ensure CloudTrail logs are encrypted using KMS keys.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail KmsKeyId configured'],
    remediationGuidance: 'Configure KMS encryption for CloudTrail logs.'
  },
  {
    id: '3.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure CloudTrail logs are sent to CloudWatch Logs',
    description: 'Ensure CloudTrail logs are delivered to CloudWatch Logs for monitoring.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail CloudWatchLogsLogGroupArn configured'],
    remediationGuidance: 'Configure CloudTrail to send logs to CloudWatch Logs.'
  },
  {
    id: '3.5',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure S3 bucket used for CloudTrail logs is not public',
    description: 'Ensure the S3 bucket storing CloudTrail logs is not publicly accessible.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-007'],
    evidenceRequirements: ['CloudTrail S3 bucket has Block Public Access enabled'],
    remediationGuidance: 'Enable Block Public Access on CloudTrail log bucket.'
  },
  {
    id: '3.6',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure CloudTrail trail is integrated with CloudWatch Logs',
    description: 'Ensure CloudTrail trail is integrated with CloudWatch Logs.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn configured'],
    remediationGuidance: 'Integrate CloudTrail with CloudWatch Logs.'
  },
  {
    id: '3.7',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure VPC flow logs are enabled for all VPCs',
    description: 'Ensure VPC flow logs are enabled for all VPCs.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['All VPCs have flow logs enabled'],
    remediationGuidance: 'Enable VPC flow logs for all VPCs. Send to CloudWatch Logs or S3.'
  },
  {
    id: '3.8',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure S3 bucket access logging is enabled on CloudTrail bucket',
    description: 'Ensure access logging is enabled on the S3 bucket used for CloudTrail.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail S3 bucket has logging configured'],
    remediationGuidance: 'Enable access logging on CloudTrail S3 bucket.'
  },
  {
    id: '3.9',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure Config is enabled in all regions',
    description: 'Ensure AWS Config is enabled in all regions.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Config recorder exists in all regions, recording all resource types'],
    remediationGuidance: 'Enable AWS Config in all regions. Record all resource types.'
  },
  {
    id: '3.10',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure Config records all resource types',
    description: 'Ensure AWS Config records configuration changes for all resource types.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Config recorder recordingStrategy includes all resource types'],
    remediationGuidance: 'Configure Config recorder to record all resource types.'
  },
  {
    id: '3.11',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure Config delivers to S3 bucket with encryption',
    description: 'Ensure AWS Config delivers configuration history to an encrypted S3 bucket.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Config delivery channel S3 bucket has encryption enabled'],
    remediationGuidance: 'Use encrypted S3 bucket for Config delivery.'
  },
  {
    id: '4.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure GuardDuty is enabled in all regions',
    description: 'Ensure Amazon GuardDuty is enabled in all regions.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['GuardDuty detector exists and is enabled in all regions'],
    remediationGuidance: 'Enable GuardDuty in all regions. Consider delegated administrator for multi-account.'
  },
  {
    id: '4.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure Security Hub is enabled in all regions',
    description: 'Ensure AWS Security Hub is enabled in all regions.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Security Hub enabled in all regions'],
    remediationGuidance: 'Enable Security Hub in all regions. Subscribe to standards (CIS, PCI DSS).'
  },
  {
    id: '4.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for unauthorized API calls',
    description: 'Ensure CloudWatch alarms exist for unauthorized API calls.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for UnauthorizedOperation events'],
    remediationGuidance: 'Create CloudWatch metric filter and alarm for unauthorized API calls.'
  },
  {
    id: '4.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for MFA deletion',
    description: 'Ensure CloudWatch alarms exist for MFA device deletion.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for DeleteVirtualMFADevice, DeactivateMFADevice'],
    remediationGuidance: 'Create CloudWatch alarm for MFA deletion events.'
  },
  {
    id: '4.5',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for root account usage',
    description: 'Ensure CloudWatch alarms exist for root account usage.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for root account ConsoleLogin'],
    remediationGuidance: 'Create CloudWatch alarm for root account console login.'
  },
  {
    id: '4.6',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for IAM policy changes',
    description: 'Ensure CloudWatch alarms exist for IAM policy changes.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for IAM policy change events'],
    remediationGuidance: 'Create CloudWatch alarm for IAM policy changes (CreatePolicy, AttachRolePolicy, etc.).'
  },
  {
    id: '4.7',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for CloudTrail changes',
    description: 'Ensure CloudWatch alarms exist for CloudTrail configuration changes.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for CloudTrail StopLogging, DeleteTrail, UpdateTrail'],
    remediationGuidance: 'Create CloudWatch alarm for CloudTrail configuration changes.'
  },
  {
    id: '4.8',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for VPC changes',
    description: 'Ensure CloudWatch alarms exist for VPC changes.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for VPC, subnet, SG, NACL, route table changes'],
    remediationGuidance: 'Create CloudWatch alarm for VPC configuration changes.'
  },
  {
    id: '4.9',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for S3 bucket policy changes',
    description: 'Ensure CloudWatch alarms exist for S3 bucket policy changes.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-007'],
    evidenceRequirements: ['CloudWatch alarm for PutBucketPolicy, PutBucketAcl, DeleteBucketPolicy'],
    remediationGuidance: 'Create CloudWatch alarm for S3 bucket policy/ACL changes.'
  },
  {
    id: '4.10',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for Config changes',
    description: 'Ensure CloudWatch alarms exist for AWS Config changes.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for Config StopConfigurationRecorder, DeleteDeliveryChannel'],
    remediationGuidance: 'Create CloudWatch alarm for Config configuration changes.'
  },
  {
    id: '4.11',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for Security Hub findings',
    description: 'Ensure CloudWatch alarms exist for Security Hub finding creation.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for Security Hub finding events'],
    remediationGuidance: 'Create CloudWatch alarm for new Security Hub findings.'
  },
  {
    id: '4.12',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for GuardDuty findings',
    description: 'Ensure CloudWatch alarms exist for GuardDuty finding creation.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for GuardDuty finding events'],
    remediationGuidance: 'Create CloudWatch alarm for new GuardDuty findings.'
  },
  {
    id: '5.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure no security groups allow 0.0.0.0/0 on port 22',
    description: 'Ensure no security groups allow unrestricted SSH access.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-002'],
    evidenceRequirements: ['No security groups with ingress 0.0.0.0/0 on port 22'],
    remediationGuidance: 'Restrict SSH access to specific CIDR ranges or bastion hosts.'
  },
  {
    id: '5.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure no security groups allow 0.0.0.0/0 on port 3389',
    description: 'Ensure no security groups allow unrestricted RDP access.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-002'],
    evidenceRequirements: ['No security groups with ingress 0.0.0.0/0 on port 3389'],
    remediationGuidance: 'Restrict RDP access to specific CIDR ranges or bastion hosts.'
  },
  {
    id: '5.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure default security group restricts all traffic',
    description: 'Ensure default security groups do not allow inbound/outbound traffic.',
    severity: 'medium',
    automated: true,
    relatedRules: ['RULE-002'],
    evidenceRequirements: ['Default security groups have no inbound/outbound rules'],
    remediationGuidance: 'Remove all rules from default security groups. Create specific SGs for resources.'
  },
  {
    id: '5.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure VPC flow logs are enabled',
    description: 'Ensure VPC flow logs are enabled for all VPCs.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['All VPCs have flow logs enabled'],
    remediationGuidance: 'Enable VPC flow logs for all VPCs.'
  },
  {
    id: '5.5',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure no NACLs allow 0.0.0.0/0 on sensitive ports',
    description: 'Ensure network ACLs do not allow unrestricted access to sensitive ports.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['No NACLs with 0.0.0.0/0 allow on ports 22, 3389, 1433, 3306, 5432'],
    remediationGuidance: 'Restrict NACL rules to specific CIDR ranges.'
  },
  {
    id: '5.6',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure restricted common ports on security groups',
    description: 'Ensure security groups restrict access to common sensitive ports.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-002'],
    evidenceRequirements: ['Security groups restrict ports 1433, 3306, 5432, 6379, 9200, 27017'],
    remediationGuidance: 'Restrict database and cache ports to application security groups only.'
  },
  {
    id: '5.7',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure VPC endpoints are used for AWS service access',
    description: 'Ensure VPC endpoints (Gateway/Interface) are used for private AWS service access.',
    severity: 'medium',
    automated: true,
    relatedRules: ['RULE-009'],
    evidenceRequirements: ['VPC endpoints exist for S3, DynamoDB, and other services used'],
    remediationGuidance: 'Create VPC endpoints for S3, DynamoDB, and other AWS services to avoid internet traversal.'
  },
  {
    id: '5.8',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure Transit Gateway routes are restricted',
    description: 'Ensure Transit Gateway route tables restrict cross-VPC traffic.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['TGW route tables have specific routes, no 0.0.0.0/0 blackhole'],
    remediationGuidance: 'Configure TGW route tables with least-privilege routes between VPCs.'
  }
];

export const SOC2_CONTROLS: ComplianceControl[] = [
  {
    id: 'CC6.1',
    framework: 'SOC2',
    section: 'CC6.1 - Logical Access Security',
    title: 'The entity implements logical access security software, infrastructure, and architectures',
    description: 'Logical access security measures protect information assets from unauthorized access.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-001', 'RULE-002', 'RULE-004', 'RULE-006', 'RULE-010'],
    evidenceRequirements: ['IAM policies, security groups, NACLs, encryption configs'],
    remediationGuidance: 'Implement least-privilege access. Enforce MFA. Encrypt data at rest and in transit.'
  },
  {
    id: 'CC6.2',
    framework: 'SOC2',
    section: 'CC6.2 - Access Credentials',
    title: 'Prior to issuing credentials, the entity registers and authorizes new users',
    description: 'User registration and authorization processes ensure only approved individuals receive credentials.',
    severity: 'high',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['User provisioning workflow, approval records'],
    remediationGuidance: 'Implement formal user provisioning with manager approval. Document authorization process.'
  },
  {
    id: 'CC6.3',
    framework: 'SOC2',
    section: 'CC6.3 - Access Removal',
    title: 'The entity modifies and removes access when no longer required',
    description: 'Access is revoked when users change roles or leave the organization.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['IAM credential report showing no stale users, offboarding workflow'],
    remediationGuidance: 'Automate access revocation on role change/termination. Review access quarterly.'
  },
  {
    id: 'CC6.4',
    framework: 'SOC2',
    section: 'CC6.4 - Access Review',
    title: 'The entity reviews access rights periodically',
    description: 'Periodic access reviews ensure permissions remain appropriate.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-004'],
    evidenceRequirements: ['Access review records, unused permission reports'],
    remediationGuidance: 'Conduct quarterly access reviews. Use IAM Access Analyzer for unused permissions.'
  },
  {
    id: 'CC6.5',
    framework: 'SOC2',
    section: 'CC6.5 - Network Segmentation',
    title: 'The entity restricts logical access through network segmentation',
    description: 'Network segmentation limits lateral movement and unauthorized access.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-002', 'RULE-005', 'RULE-009'],
    evidenceRequirements: ['VPC design, security groups, NACLs, TGW routes'],
    remediationGuidance: 'Implement network segmentation with separate VPCs/subnets per environment. Restrict inter-segment traffic.'
  },
  {
    id: 'CC6.6',
    framework: 'SOC2',
    section: 'CC6.6 - Encryption',
    title: 'The entity implements encryption to protect data',
    description: 'Encryption protects data confidentiality at rest and in transit.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-007', 'RULE-008', 'RULE-010'],
    evidenceRequirements: ['Encryption configs for S3, EBS, RDS, Redshift, ElastiCache, OpenSearch'],
    remediationGuidance: 'Enable encryption at rest for all data stores. Enforce TLS 1.2+ for all connections.'
  },
  {
    id: 'CC6.7',
    framework: 'SOC2',
    section: 'CC6.7 - Mobile/Remote Access',
    title: 'The entity restricts remote access to authorized personnel',
    description: 'Remote access is controlled and monitored.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-001', 'RULE-002'],
    evidenceRequirements: ['VPN/bastion configs, MFA enforcement, CloudTrail for remote logins'],
    remediationGuidance: 'Require MFA for all remote access. Use bastion hosts or SSM Session Manager. Log all sessions.'
  },
  {
    id: 'CC6.8',
    framework: 'SOC2',
    section: 'CC6.8 - Data Classification',
    title: 'The entity classifies data and applies appropriate protections',
    description: 'Data classification drives protection requirements.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-001', 'RULE-007', 'RULE-008'],
    evidenceRequirements: ['Data classification tags, DLP configs, access controls per classification'],
    remediationGuidance: 'Implement data classification tagging. Apply controls based on classification level.'
  },
  {
    id: 'CC7.1',
    framework: 'SOC2',
    section: 'CC7.1 - System Monitoring',
    title: 'The entity monitors system components for anomalies',
    description: 'Continuous monitoring detects anomalous activity.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['GuardDuty, Security Hub, CloudWatch alarms, CloudTrail'],
    remediationGuidance: 'Enable GuardDuty, Security Hub. Create CloudWatch alarms for critical events.'
  },
  {
    id: 'CC7.2',
    framework: 'SOC2',
    section: 'CC7.2 - Security Event Monitoring',
    title: 'The entity monitors and analyzes security events',
    description: 'Security events are collected, correlated, and analyzed.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['SIEM integration, CloudTrail log analysis, GuardDuty findings'],
    remediationGuidance: 'Centralize logs in SIEM. Correlate CloudTrail, VPC flow logs, GuardDuty findings.'
  },
  {
    id: 'CC7.3',
    framework: 'SOC2',
    section: 'CC7.3 - Vulnerability Management',
    title: 'The entity identifies and remediates vulnerabilities',
    description: 'Vulnerability scanning and remediation processes are in place.',
    severity: 'high',
    automated: false,
    relatedRules: ['RULE-003'],
    evidenceRequirements: ['Vulnerability scan reports, patch management records'],
    remediationGuidance: 'Implement continuous vulnerability scanning. Define SLAs for remediation by severity.'
  },
  {
    id: 'CC7.4',
    framework: 'SOC2',
    section: 'CC7.4 - Incident Response',
    title: 'The entity responds to security incidents',
    description: 'Incident response procedures are defined and tested.',
    severity: 'high',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['IR plan, runbooks, incident records, post-incident reviews'],
    remediationGuidance: 'Develop and test incident response plan. Define roles, communication, escalation.'
  },
  {
    id: 'CC7.5',
    framework: 'SOC2',
    section: 'CC7.5 - Monitoring Personnel',
    title: 'The entity monitors personnel with privileged access',
    description: 'Privileged user activity is monitored and reviewed.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-004', 'RULE-006'],
    evidenceRequirements: ['CloudTrail for admin actions, session recording, access reviews'],
    remediationGuidance: 'Monitor all privileged actions. Implement session recording for sensitive systems.'
  },
  {
    id: 'CC8.1',
    framework: 'SOC2',
    section: 'CC8.1 - Change Management',
    title: 'The entity manages changes to infrastructure and applications',
    description: 'Change management processes ensure authorized, tested changes.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Change management records, Config history, CloudTrail for infrastructure changes'],
    remediationGuidance: 'Implement IaC with PR reviews. Use Config for drift detection. Require approval for production changes.'
  }
];

export const ISO27001_CONTROLS: ComplianceControl[] = [
  {
    id: 'A.5.1',
    framework: 'ISO27001',
    section: 'A.5 - Information Security Policies',
    title: 'Policies for information security',
    description: 'A set of policies for information security shall be defined, approved, published and communicated.',
    severity: 'high',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Security policy documents, approval records, communication evidence'],
    remediationGuidance: 'Develop comprehensive information security policies. Get management approval. Communicate to all personnel.'
  },
  {
    id: 'A.6.1',
    framework: 'ISO27001',
    section: 'A.6 - Organization of Information Security',
    title: 'Internal organization',
    description: 'Roles and responsibilities for information security shall be defined and allocated.',
    severity: 'high',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Org chart with security roles, RACI matrix'],
    remediationGuidance: 'Define information security roles (CISO, security officers). Assign responsibilities.'
  },
  {
    id: 'A.8.1',
    framework: 'ISO27001',
    section: 'A.8 - Asset Management',
    title: 'Responsibility for assets',
    description: 'Assets shall be identified and ownership assigned.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Asset inventory, ownership tags, CMDB'],
    remediationGuidance: 'Maintain asset inventory with ownership. Tag all AWS resources with owner, environment, data classification.'
  },
  {
    id: 'A.8.2',
    framework: 'ISO27001',
    section: 'A.8 - Asset Management',
    title: 'Information classification',
    description: 'Information shall be classified based on criticality and sensitivity.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-001', 'RULE-007', 'RULE-008'],
    evidenceRequirements: ['Data classification scheme, classification tags on resources'],
    remediationGuidance: 'Define classification levels (Public, Internal, Restricted, Secret). Tag all data stores.'
  },
  {
    id: 'A.8.3',
    framework: 'ISO27001',
    section: 'A.8 - Asset Management',
    title: 'Media handling',
    description: 'Procedures for handling media shall be implemented.',
    severity: 'medium',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Media handling procedures, disposal records'],
    remediationGuidance: 'Implement procedures for media handling, storage, and secure disposal.'
  },
  {
    id: 'A.9.1',
    framework: 'ISO27001',
    section: 'A.9 - Access Control',
    title: 'Access control policy',
    description: 'An access control policy shall be established and documented.',
    severity: 'high',
    automated: false,
    relatedRules: ['RULE-004', 'RULE-006'],
    evidenceRequirements: ['Access control policy document'],
    remediationGuidance: 'Document access control policy covering least privilege, need-to-know, segregation of duties.'
  },
  {
    id: 'A.9.2',
    framework: 'ISO27001',
    section: 'A.9 - Access Control',
    title: 'User access management',
    description: 'User access shall be provisioned, reviewed, and revoked.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-004', 'RULE-006'],
    evidenceRequirements: ['Provisioning/deprovisioning workflow, access reviews, IAM credential reports'],
    remediationGuidance: 'Automate user lifecycle. Conduct regular access reviews. Revoke access promptly on termination.'
  },
  {
    id: 'A.9.3',
    framework: 'ISO27001',
    section: 'A.9 - Access Control',
    title: 'User responsibilities',
    description: 'Users shall be responsible for safeguarding their authentication information.',
    severity: 'medium',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Acceptable use policy, security awareness training records'],
    remediationGuidance: 'Communicate user responsibilities. Enforce MFA. Provide security awareness training.'
  },
  {
    id: 'A.9.4',
    framework: 'ISO27001',
    section: 'A.9 - Access Control',
    title: 'System and application access control',
    description: 'Access to systems and applications shall be restricted.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-001', 'RULE-002', 'RULE-004', 'RULE-009', 'RULE-010'],
    evidenceRequirements: ['IAM policies, security groups, NACLs, application RBAC'],
    remediationGuidance: 'Implement least-privilege access. Use IAM roles, security groups, application-level RBAC.'
  },
  {
    id: 'A.10.1',
    framework: 'ISO27001',
    section: 'A.10 - Cryptography',
    title: 'Cryptographic controls',
    description: 'Cryptographic controls shall be implemented to protect confidentiality and integrity.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-007', 'RULE-008', 'RULE-010'],
    evidenceRequirements: ['Encryption configs, key management procedures, certificate inventory'],
    remediationGuidance: 'Encrypt all data at rest and in transit. Manage keys with KMS. Rotate keys periodically.'
  },
  {
    id: 'A.12.1',
    framework: 'ISO27001',
    section: 'A.12 - Operations Security',
    title: 'Operational procedures and responsibilities',
    description: 'Operational procedures shall be documented and made available.',
    severity: 'high',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Runbooks, SOPs, operational procedures documentation'],
    remediationGuidance: 'Document operational procedures for all critical systems. Include incident response, backup, recovery.'
  },
  {
    id: 'A.12.2',
    framework: 'ISO27001',
    section: 'A.12 - Operations Security',
    title: 'Change management',
    description: 'Changes to systems shall be controlled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Change management records, Config history, IaC PR reviews'],
    remediationGuidance: 'Implement change management for all infrastructure. Use IaC with PR reviews. Track all changes.'
  },
  {
    id: 'A.12.3',
    framework: 'ISO27001',
    section: 'A.12 - Operations Security',
    title: 'Capacity management',
    description: 'Resource usage shall be monitored and tuned.',
    severity: 'medium',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Capacity planning reports, CloudWatch dashboards, auto-scaling configs'],
    remediationGuidance: 'Monitor resource utilization. Implement auto-scaling. Plan capacity based on trends.'
  },
  {
    id: 'A.12.4',
    framework: 'ISO27001',
    section: 'A.12 - Operations Security',
    title: 'Logging and monitoring',
    description: 'Event logs shall be produced, protected, and analyzed.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail, VPC flow logs, CloudWatch logs, GuardDuty, Security Hub'],
    remediationGuidance: 'Enable comprehensive logging. Protect log integrity. Implement centralized log analysis.'
  },
  {
    id: 'A.12.5',
    framework: 'ISO27001',
    section: 'A.12 - Operations Security',
    title: 'Control of operational software',
    description: 'Software installation shall be controlled.',
    severity: 'medium',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Software inventory, approved software list, installation controls'],
    remediationGuidance: 'Maintain approved software list. Control software installation. Scan for unauthorized software.'
  },
  {
    id: 'A.12.6',
    framework: 'ISO27001',
    section: 'A.12 - Operations Security',
    title: 'Technical vulnerability management',
    description: 'Technical vulnerabilities shall be identified and addressed.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-003'],
    evidenceRequirements: ['Vulnerability scan reports, patch management records, CVE tracking'],
    remediationGuidance: 'Implement continuous vulnerability scanning. Define remediation SLAs. Track CVE exposure.'
  },
  {
    id: 'A.13.1',
    framework: 'ISO27001',
    section: 'A.13 - Communications Security',
    title: 'Network controls',
    description: 'Networks shall be managed and controlled.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-002', 'RULE-005', 'RULE-009'],
    evidenceRequirements: ['VPC design, security groups, NACLs, TGW, VPN, Direct Connect configs'],
    remediationGuidance: 'Segment networks. Restrict traffic with security groups and NACLs. Monitor network traffic.'
  },
  {
    id: 'A.13.2',
    framework: 'ISO27001',
    section: 'A.13 - Communications Security',
    title: 'Information transfer',
    description: 'Information transfer shall be secured.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-007', 'RULE-008', 'RULE-009', 'RULE-010'],
    evidenceRequirements: ['Encryption in transit, SFTP/HTTPS enforcement, API gateway TLS'],
    remediationGuidance: 'Enforce TLS 1.2+ for all communications. Use VPC endpoints for AWS service access.'
  }
];

export function getAllControls(): ComplianceControl[] {
  return [...CIS_AWS_FOUNDATIONS_V3_CONTROLS, ...SOC2_CONTROLS, ...ISO27001_CONTROLS];
}

export function getControlsByFramework(framework: ComplianceFramework): ComplianceControl[] {
  switch (framework) {
    case 'CIS_AWS_FOUNDATIONS':
      return CIS_AWS_FOUNDATIONS_V3_CONTROLS;
    case 'SOC2':
      return SOC2_CONTROLS;
    case 'ISO27001':
      return ISO27001_CONTROLS;
  }
}

export function getControlById(id: string, framework: ComplianceFramework): ComplianceControl | undefined {
  return getControlsByFramework(framework).find(c => c.id === id);
}