// CIS and the Khalifa baseline are canonical: they own controls and
// evaluators. SOC2 and ISO27001 are mapped frameworks: their requirements
// cite canonical controls (see framework-citations.ts) and derive their
// status from those controls' assessments.
export type ComplianceFramework =
  'CIS_AWS_FOUNDATIONS' | 'KHALIFA_BASELINE' | 'SOC2' | 'ISO27001' | 'PCI_DSS' | 'NIST_800_53';

export type ComplianceControlStatus =
  'PASS' | 'FAIL' | 'MANUAL' | 'NOT_APPLICABLE' | 'NOT_EVALUATED';

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

export interface ComplianceAssessmentSummary {
  totalControls: number;
  passed: number;
  failed: number;
  manual: number;
  notApplicable: number;
  notEvaluated: number;
  coveragePercent: number;
}

export interface ComplianceReport {
  framework: ComplianceFramework;
  generatedAt: string;
  summary: ComplianceAssessmentSummary;
  controls: ComplianceControlResult[];
  /** Present on mapped-framework reports: the canonical frameworks they derived from. */
  derivedFrom?: ComplianceFramework[];
}

export interface MappedControlReference {
  controlId: string;
  framework: ComplianceFramework;
  status: ComplianceControlStatus;
  issues: string[];
}

export interface ComplianceControlResult {
  control: ComplianceControl;
  status: ComplianceControlStatus;
  evidence: ComplianceEvidence[];
  issues: string[];
  lastEvaluated: string;
  /** Present on mapped-framework requirements: the canonical controls behind it. */
  mappedControls?: MappedControlReference[];
  // Set for regional controls: the regions whose resources the result covers.
  // A PASS means PASS in these regions, not in every region the control names.
  regionsEvaluated?: string[];
}

export interface ComplianceFrameworkSummary {
  framework: ComplianceFramework;
  version: string;
  totalControls: number;
  automatedControls: number;
  manualControls: number;
  coveragePercent: number;
  lastAssessment: string;
  summary: ComplianceAssessmentSummary;
}

/**
 * Where a control id from stored ComplianceEvidence lives now.
 *
 * Production ran v1.49.0 until the v1.57.0 deploy on 2026-09-25, so evidence
 * written before then carries v1.49.0's ids -- several of which still exist
 * today with a different meaning (1.10 was key rotation, is now console MFA).
 * Read those rows through V1_49; unchanged ids are omitted.
 *
 * REMOVED covers ids deleted since as duplicates, which rows written after the
 * deploy may still carry. SOC 2 and ISO 27001 rows have no equivalent: that
 * framework was removed outright.
 *
 * A test asserts every target resolves to a current control, so a later
 * removal that would orphan one of these fails CI instead of going stale.
 */
export const LEGACY_CONTROL_IDS = {
  V1_49: {
    '1.7': '1.10',
    '1.8': 'KH-1.8',
    '1.10': '1.14',
    '1.11': '1.12',
    '1.12': '1.15',
    '1.13': '1.8',
    '1.14': '1.9',
    '1.15': 'KH-1.15',
    '1.19': 'KH-1.19',
    '1.20': '1.15',
    '1.21': '1.17',
    '1.22': 'KH-1.22',
    '2.1': '2.1.4',
    '2.2': 'KH-2.2',
    '2.3': 'KH-2.3',
    '2.4': 'KH-2.4',
    '2.5': 'KH-2.5',
    '2.6': 'KH-2.6',
    '2.7': '2.3.1',
    '2.8': 'KH-2.8',
    '2.9': '2.3.3',
    '2.10': 'KH-2.10',
    '2.11': 'KH-2.11',
    '2.12': 'KH-2.12',
    '2.13': 'KH-2.13',
    '2.14': 'KH-2.14',
    '2.15': 'KH-2.15',
    '2.16': 'KH-2.16',
    '3.3': '3.5',
    '3.4': 'KH-3.4',
    '3.5': 'KH-3.5',
    '3.6': 'KH-3.4',
    '3.8': '3.4',
    '3.9': '3.3',
    '3.10': 'KH-3.10',
    '3.11': 'KH-3.11',
    '4.1': 'KH-4.1',
    '4.2': '4.16',
    '4.3': '4.1',
    '4.4': 'KH-4.4',
    '4.5': '4.3',
    '4.6': '4.4',
    '4.7': '4.5',
    '4.8': '4.14',
    '4.9': '4.8',
    '4.10': '4.9',
    '4.11': 'KH-4.11',
    '4.12': 'KH-4.12',
    '5.1': '5.2',
    // Same id, wider meaning: v1.49.0's 5.2 was RDP only; 5.2 now covers SSH and RDP.
    '5.2': '5.2',
    '5.3': '5.4',
    '5.4': '3.7',
    '5.5': '5.1',
    '5.6': 'KH-5.6',
    '5.7': 'KH-5.7',
    '5.8': 'KH-5.8',
  } as Readonly<Record<string, string>>,
  REMOVED: {
    'KH-3.6': 'KH-3.4',
    'KH-5.2': '5.2',
    'KH-5.4': '3.7',
    'KH-1.20': '1.15',
    // EC2.21 covers ::/0 as well as 0.0.0.0/0, so 5.1 now does too.
    'KH-5.3': '5.1',
  } as Readonly<Record<string, string>>,
};

/**
 * CIS AWS Foundations Benchmark v3.0.0.
 *
 * Control ids follow the published v3.0.0 requirement numbers, including the
 * nested section 2 (2.1.x S3, 2.2.x EBS, 2.3.x RDS, 2.4.x EFS).
 *
 * `KH-` prefixed ids are Khalifa checks that are NOT v3.0.0 requirements. They
 * are kept because they remain useful, but must not be reported as CIS results.
 * Most were once numbered as if they were CIS controls; see LEGACY_CONTROL_IDS.
 */
export const CIS_AWS_FOUNDATIONS_V3_CONTROLS: ComplianceControl[] = [
  {
    id: '1.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Maintain current contact details for the AWS account',
    description:
      'Ensure the contact information for the AWS account is current and maps to more than one individual.',
    severity: 'low',
    automated: false,
    relatedRules: [],
    evidenceRequirements: ['Account contact information'],
    remediationGuidance:
      'Update account contact information in AWS Account Settings to include multiple individuals.',
  },
  {
    id: '1.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure security contact information is registered',
    description: 'Ensure security contact information is registered for the AWS account.',
    severity: 'low',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Security contact information'],
    remediationGuidance: 'Register security contact information in AWS Account Settings.',
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
    remediationGuidance: 'Register security questions in AWS Account Settings.',
  },
  {
    id: '1.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure no root account access key exists',
    description: 'Ensure no access keys exist for the root user.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM credential report showing no root access keys'],
    remediationGuidance: 'Delete any root access keys. Use IAM users/roles instead.',
  },
  {
    id: '1.5',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure MFA is enabled for the root account',
    description: 'Ensure multi-factor authentication (MFA) is enabled for the root user.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM credential report showing root MFA enabled'],
    remediationGuidance: 'Enable MFA for the root account in IAM console.',
  },
  {
    id: '1.6',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure hardware MFA is enabled for the root account',
    description: 'Ensure hardware MFA is enabled for the root user.',
    severity: 'high',
    automated: true,
    // RULE-004 was mapped here and detects over-privileged IAM roles on
    // internet-reachable workloads -- unrelated to root MFA. No rule measures
    // this, and no evaluator is possible either: the collector records
    // AccountMFAEnabled, a boolean that cannot distinguish hardware from
    // virtual MFA, which is the whole point of 1.6.
    relatedRules: [],
    evidenceRequirements: [
      'IAM credential report showing hardware MFA for root; needs ListVirtualMFADevices to distinguish hardware from virtual',
    ],
    remediationGuidance: 'Enable hardware MFA (e.g., YubiKey) for root account.',
  },
  {
    id: '1.10',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure MFA is enabled for all IAM users with console password',
    description: 'Ensure MFA is enabled for all IAM users that have a console password.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-015'],
    evidenceRequirements: ['IAM credential report showing MFA for all console users'],
    remediationGuidance: 'Enforce MFA for all IAM users with console access.',
  },
  {
    id: '1.14',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure access keys are rotated every 90 days or less',
    description: 'Ensure IAM user access keys are rotated every 90 days.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-013'],
    evidenceRequirements: ['IAM credential report showing key age <= 90 days'],
    remediationGuidance: 'Rotate access keys older than 90 days. Implement automated rotation.',
  },
  {
    id: '1.12',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure credentials unused for 45 days or greater are disabled',
    description:
      'Disable console passwords and deactivate access keys that have not been used for 45 days or more.',
    severity: 'medium',
    automated: true,
    relatedRules: ['RULE-014'],
    evidenceRequirements: [
      'No active access key unused for 45+ days, and no console password unused for 45+ days (credential report)',
    ],
    remediationGuidance:
      'Remove the console password, and deactivate or delete the access key, for any credential unused for 45 days.',
  },
  {
    id: '1.15',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM Users Receive Permissions Only Through Groups',
    description:
      'IAM.2. Any policy attached directly to a user, inline or managed, fails. Permissions granted through groups are easier to review and revoke together.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['No IamUser with an ATTACHED_TO edge to any policy, inline or managed.'],
    remediationGuidance:
      'Detach policies from users and grant them through IAM groups instead. Moving an inline policy to a managed one still fails if it stays attached to the user.',
  },
  {
    id: '1.7',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: "Eliminate use of the 'root' user for administrative and daily tasks",
    description:
      "CIS v3.0.0 1.7, Level 1. Security Hub has no check for it -- IAM.20 maps to v1.2.0's 1.1, which this replaced -- so it is absent from the Security Hub control list. RULE-020 is the evidence of use.",
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-020'],
    evidenceRequirements: [
      "Root activity in CloudTrail (RULE-020). The benchmark's audit reads root password_last_used and access key last-used dates from the credential report; the collector keeps root's password_last_used but not its key dates, and CIS sets no recency threshold, so there is no evaluator yet.",
    ],
    remediationGuidance:
      'Use root only for the tasks that require it. Grant day-to-day access through IAM roles, and remove root access keys.',
  },
  {
    id: '1.8',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM password policy requires minimum length of 14',
    description: 'Ensure IAM password policy requires minimum password length of 14.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM password policy MinPasswordLength >= 14'],
    remediationGuidance: 'Update IAM password policy to require minimum 14 characters.',
  },
  {
    id: '1.9',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM password policy prevents password reuse',
    description: 'Ensure IAM password policy prevents password reuse (at least 24 generations).',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM password policy PasswordReusePrevention >= 24'],
    remediationGuidance: 'Update IAM password policy to prevent reuse of last 24 passwords.',
  },
  {
    id: '1.17',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure a support role has been created to manage incidents',
    description: 'Ensure a support role exists for incident management.',
    severity: 'low',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'Per account with a completed IAM collection: an IamRole with an ATTACHED_TO edge to arn:aws:iam::aws:policy/AWSSupportAccess. A user holding the policy does not satisfy IAM.18.',
    ],
    remediationGuidance:
      'Create a support role with least-privilege permissions for incident response.',
  },
  // v3.0.0 section 2 is nested and section 3 runs to 3.9. These were absent
  // from the catalogue entirely. None can be evaluated yet -- each names the
  // collector data it needs in evidenceRequirements.
  {
    id: '2.1.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure S3 Bucket Policy is set to deny HTTP requests',
    description:
      'S3.5. Buckets must require TLS, denying any request that arrives over plain HTTP.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'S3Bucket vertices with a bucket policy denying aws:SecureTransport false; the collector does not currently fetch bucket policies',
    ],
    remediationGuidance: 'Attach a bucket policy with a Deny on aws:SecureTransport false.',
  },
  {
    id: '2.1.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure MFA Delete is enabled on S3 buckets',
    description:
      'S3.20. MFA Delete requires a second factor before an object version can be permanently removed.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'Versioned S3Bucket vertices with mfa_delete_enabled true. Unversioned buckets are out of scope, as in S3.20. Known gap: S3.20 also skips buckets with a lifecycle configuration, which the collector does not record.',
    ],
    remediationGuidance: 'Enable MFA Delete on versioned buckets via the root account.',
  },
  {
    id: '2.2.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure EBS volume encryption is enabled in all regions',
    description:
      'EC2.7. This is the account-level default-encryption setting, not per-volume encryption -- a new volume created without an explicit key is encrypted only if this is on.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'GetEbsEncryptionByDefault per region; the collector does not call it and creates no EbsVolume vertices either',
    ],
    remediationGuidance: 'Enable EBS encryption by default in every region in use.',
  },
  {
    id: '2.3.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure Auto Minor Version Upgrade feature is enabled for RDS instances',
    description:
      'RDS.13. Without it, security patches to the engine are not applied automatically.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['RdsInstance vertices with auto_minor_version_upgrade true.'],
    remediationGuidance: 'Enable auto minor version upgrade on each RDS instance.',
  },
  {
    id: '2.4.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure that encryption is enabled for EFS file systems',
    description: 'EFS.1. EFS is not collected at all, so this cannot be evaluated today.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'EfsFileSystem vertices with encryption state; no EFS collection stage exists',
    ],
    remediationGuidance:
      'Create EFS file systems with encryption at rest enabled; existing unencrypted ones must be recreated.',
  },
  {
    id: '3.8',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure that Object-level logging for write events is enabled for S3 bucket',
    description:
      'S3.22. Management-event CloudTrail does not record object writes; object-level logging is a separate trail setting.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'At least one multi-Region CloudTrail with logs_all_s3_object_writes true, derived from basic or advanced event selectors covering every bucket.',
    ],
    remediationGuidance:
      'Enable object-level write logging on the trail for buckets holding sensitive data.',
  },
  {
    id: '3.9',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure that Object-level logging for read events is enabled for S3 bucket',
    description: 'S3.23. The read-event counterpart of 3.8.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'At least one multi-Region CloudTrail with logs_all_s3_object_reads true, derived from basic or advanced event selectors covering every bucket.',
    ],
    remediationGuidance:
      'Enable object-level read logging on the trail for buckets holding sensitive data.',
  },
  {
    id: '2.1.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'",
    description:
      'Ensure every S3 bucket has all four Block Public Access settings on, at the bucket or the account level.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-007', 'RULE-011'],
    evidenceRequirements: [
      'BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy and RestrictPublicBuckets on for every bucket, or on at the account level',
    ],
    remediationGuidance:
      'Enable all four S3 Block Public Access settings at the account level, or on each bucket.',
  },
  {
    id: '2.3.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure RDS instances are encrypted',
    description: 'Ensure all RDS instances have storage encryption enabled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['RDS instances have StorageEncrypted=true'],
    remediationGuidance:
      'Enable encryption for RDS instances. Recreate unencrypted instances from encrypted snapshots.',
  },
  {
    id: '2.3.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '2. Storage',
    title: 'Ensure RDS instances are not publicly accessible',
    description: 'Ensure RDS instances do not have public accessibility enabled.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-008'],
    evidenceRequirements: ['RDS PubliclyAccessible=false'],
    remediationGuidance:
      'Disable public accessibility on RDS instances. Use VPC and security groups.',
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
    remediationGuidance: 'Create multi-region CloudTrail trail. Enable in all regions.',
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
    remediationGuidance: 'Enable log file validation on all CloudTrail trails.',
  },
  {
    id: '3.5',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure CloudTrail logs are encrypted with KMS',
    description: 'Ensure CloudTrail logs are encrypted using KMS keys.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail KmsKeyId configured'],
    remediationGuidance: 'Configure KMS encryption for CloudTrail logs.',
  },
  {
    id: '3.7',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure VPC flow logs are enabled for all VPCs',
    description: 'Ensure VPC flow logs are enabled for all VPCs.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-027'],
    evidenceRequirements: ['All VPCs have flow logs enabled'],
    remediationGuidance: 'Enable VPC flow logs for all VPCs. Send to CloudWatch Logs or S3.',
  },
  {
    id: '3.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure S3 bucket access logging is enabled on CloudTrail bucket',
    description: 'Ensure access logging is enabled on the S3 bucket used for CloudTrail.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail S3 bucket has logging configured'],
    remediationGuidance: 'Enable access logging on CloudTrail S3 bucket.',
  },
  {
    id: '3.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure Config is enabled in all regions',
    description: 'Ensure AWS Config is enabled in all regions.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-028'],
    evidenceRequirements: ['Config recorder exists in all regions, recording all resource types'],
    remediationGuidance: 'Enable AWS Config in all regions. Record all resource types.',
  },
  {
    id: '4.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for unauthorized API calls',
    description: 'Ensure CloudWatch alarms exist for unauthorized API calls.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for UnauthorizedOperation events'],
    remediationGuidance: 'Create CloudWatch metric filter and alarm for unauthorized API calls.',
  },
  {
    id: '4.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for root account usage',
    description: 'Ensure CloudWatch alarms exist for root account usage.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for root account ConsoleLogin'],
    remediationGuidance: 'Create CloudWatch alarm for root account console login.',
  },
  {
    id: '4.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for IAM policy changes',
    description: 'Ensure CloudWatch alarms exist for IAM policy changes.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for IAM policy change events'],
    remediationGuidance:
      'Create CloudWatch alarm for IAM policy changes (CreatePolicy, AttachRolePolicy, etc.).',
  },
  {
    id: '4.5',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for CloudTrail changes',
    description: 'Ensure CloudWatch alarms exist for CloudTrail configuration changes.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for CloudTrail StopLogging, DeleteTrail, UpdateTrail'],
    remediationGuidance: 'Create CloudWatch alarm for CloudTrail configuration changes.',
  },
  {
    id: '4.14',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for VPC changes',
    description: 'Ensure CloudWatch alarms exist for VPC changes.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for VPC, subnet, SG, NACL, route table changes'],
    remediationGuidance: 'Create CloudWatch alarm for VPC configuration changes.',
  },
  {
    id: '4.8',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for S3 bucket policy changes',
    description: 'Ensure CloudWatch alarms exist for S3 bucket policy changes.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'CloudWatch alarm for PutBucketPolicy, PutBucketAcl, DeleteBucketPolicy',
    ],
    remediationGuidance: 'Create CloudWatch alarm for S3 bucket policy/ACL changes.',
  },
  {
    id: '4.9',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for Config changes',
    description: 'Ensure CloudWatch alarms exist for AWS Config changes.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'CloudWatch alarm for Config StopConfigurationRecorder, DeleteDeliveryChannel',
    ],
    remediationGuidance: 'Create CloudWatch alarm for Config configuration changes.',
  },
  {
    id: '5.2',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title:
      'Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports',
    description:
      'EC2.53, the v3.0.0 definition, covers both administration ports under one control. This checked only port 22 until RDP was folded in, so a group open to the world on 3389 alone passed here while Security Hub failed it.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-002'],
    evidenceRequirements: ['No security groups with ingress 0.0.0.0/0 on port 22 or 3389'],
    remediationGuidance: 'Restrict SSH and RDP access to specific CIDR ranges or bastion hosts.',
  },
  {
    id: '5.4',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure default security group restricts all traffic',
    description: 'Ensure default security groups do not allow inbound/outbound traffic.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Default security groups have no inbound/outbound rules'],
    remediationGuidance:
      'Remove all rules from default security groups. Create specific SGs for resources.',
  },
  {
    id: '4.16',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '4. Monitoring',
    title: 'Ensure Security Hub is enabled in all regions',
    description: 'Ensure AWS Security Hub is enabled in all regions.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Security Hub enabled in all regions'],
    remediationGuidance:
      'Enable Security Hub in all regions. Subscribe to standards (CIS, PCI DSS).',
  },
  {
    id: '5.1',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure no Network ACLs allow ingress from 0.0.0.0/0 to port 22 or port 3389',
    description:
      'A network ACL that allows 0.0.0.0/0 inbound on an administration port exposes every subnet it is associated with, regardless of how tightly the security groups behind it are scoped. Scoped to ports 22 and 3389 to match EC2.21, the v3.0.0 definition of this control.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'NetworkAclEntry vertices with rule_action allow, direction ingress, cidr_block 0.0.0.0/0, protocol tcp/udp/-1, covering port 22 or 3389, on any NetworkAcl whether or not a Subnet uses it',
    ],
    remediationGuidance:
      'Restrict the offending NACL rule to specific CIDR ranges. Unlike KH-5.1 this control follows EC2.21: it evaluates every non-default NACL, attached or not, so an unused NACL with an open rule is still reported; delete it or narrow the rule to clear it.',
  },
  {
    id: '1.19',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed',
    description:
      'Expired certificates in IAM can be attached to a resource and cause a service outage or a trust failure.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM server certificate list showing no expired certificates'],
    remediationGuidance: 'Delete expired certificates with iam:DeleteServerCertificate.',
  },
  {
    id: '1.20',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure that IAM Access Analyzer is enabled for all regions',
    description: 'IAM Access Analyzer identifies resources shared with an external entity.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-025'],
    evidenceRequirements: ['AccessAnalyzer vertex present for each collected region'],
    remediationGuidance:
      'Enable IAM Access Analyzer with an account or organization zone of trust in every region.',
  },
  {
    id: '1.22',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '1. Identity and Access Management',
    title: 'Ensure access to AWSCloudShellFullAccess is restricted',
    description:
      'AWSCloudShellFullAccess grants file upload and download to and from an internet-connected shell, which can be used for exfiltration.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'No IamUser, IamRole or IamGroup with an ATTACHED_TO edge to arn:aws:iam::aws:policy/AWSCloudShellFullAccess.',
    ],
    remediationGuidance:
      'Detach AWSCloudShellFullAccess and grant a scoped CloudShell policy instead.',
  },
  {
    id: '3.6',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '3. Logging',
    title: 'Ensure rotation for customer-created symmetric CMKs is enabled',
    description: 'Key rotation limits the amount of data protected by a single key version.',
    severity: 'medium',
    automated: true,
    relatedRules: ['RULE-026'],
    evidenceRequirements: ['KmsKey vertices with rotation_enabled true for customer-managed keys'],
    remediationGuidance: 'Enable automatic key rotation on customer-managed symmetric CMKs.',
  },
  {
    id: '5.3',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title:
      'Ensure no security groups allow ingress from ::/0 to remote server administration ports',
    description:
      'The IPv6 equivalent of 5.2. A security group open to ::/0 on an administration port is reachable from the entire IPv6 internet.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-002'],
    evidenceRequirements: ['SecurityGroupRule vertices with cidr_block ::/0 on ports 22 or 3389'],
    remediationGuidance:
      'Remove ::/0 ingress rules on administration ports and scope to known prefixes.',
  },
  {
    id: '5.6',
    framework: 'CIS_AWS_FOUNDATIONS',
    section: '5. Networking',
    title: 'Ensure that EC2 Metadata Service only allows IMDSv2',
    description:
      'IMDSv1 is vulnerable to SSRF-based credential theft because it requires no session token.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-024'],
    evidenceRequirements: ['Ec2Instance vertices with metadata_http_tokens set to required'],
    remediationGuidance: 'Set HttpTokens to required with ec2:ModifyInstanceMetadataOptions.',
  },
];

/**
 * Khalifa baseline: checks that are not CIS AWS Foundations requirements.
 * Two groups. KH-<section>.<n> ids are controls that previously carried a CIS
 * number they were not entitled to. KH-<AREA>-<n> ids cover detections CIS says
 * nothing about at all: container vulnerabilities, attack paths, Secrets Manager,
 * Kubernetes exposure and credential tripwires.
 */
export const KHALIFA_BASELINE_CONTROLS: ComplianceControl[] = [
  {
    id: 'KH-1.8',
    framework: 'KHALIFA_BASELINE',
    section: '1. Identity and Access Management',
    title: 'Ensure hardware MFA is enabled for all IAM users with console password',
    description: 'Ensure hardware MFA is enabled for all IAM users that have a console password.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'Per-user hardware MFA. Not evaluable: the collector records mfa_enabled per user and AccountMFAEnabled for root, neither of which distinguishes hardware from virtual. Its RULE-004 mapping detects over-privileged roles on internet-reachable workloads and is unrelated to MFA.',
    ],
    remediationGuidance: 'Enforce hardware MFA for all IAM users with console access.',
  },
  {
    id: 'KH-1.15',
    framework: 'KHALIFA_BASELINE',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM password policy expires passwords within 90 days',
    description: 'Ensure IAM password policy expires passwords within 90 days.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['IAM password policy MaxPasswordAge <= 90'],
    remediationGuidance: 'Set password expiration to 90 days or less.',
  },
  {
    id: 'KH-1.19',
    framework: 'KHALIFA_BASELINE',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM users are in at least one group',
    description: 'Ensure all IAM users are members of at least one IAM group.',
    severity: 'low',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['All IAM users have at least one group membership'],
    remediationGuidance: 'Assign all IAM users to appropriate groups.',
  },
  {
    id: 'KH-1.22',
    framework: 'KHALIFA_BASELINE',
    section: '1. Identity and Access Management',
    title: 'Ensure IAM instance roles are used for AWS resource access from instances',
    description: 'Ensure EC2 instances use IAM roles instead of access keys.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'EC2 using instance roles rather than embedded credentials. Not evaluable from the graph: an access key inside an instance is not observable through the AWS APIs collected. RULE-001 and RULE-004 are mapped here but detect internet-exposed workloads, not credential placement.',
    ],
    remediationGuidance: 'Attach IAM roles to EC2 instances. Remove hardcoded credentials.',
  },
  // CloudWatch alarms for MFA deletion, Security Hub findings and GuardDuty
  // findings, and the two AWS Config detail controls. None are v3.0.0
  // requirements: section 4 covers metric filters for specific event types,
  // and section 3 ends at 3.9.
  {
    id: 'KH-4.4',
    framework: 'KHALIFA_BASELINE',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for MFA deletion',
    description: 'Ensure CloudWatch alarms exist for MFA device deletion.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for DeleteVirtualMFADevice, DeactivateMFADevice'],
    remediationGuidance: 'Create CloudWatch alarm for MFA deletion events.',
  },
  {
    id: 'KH-4.11',
    framework: 'KHALIFA_BASELINE',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for Security Hub findings',
    description: 'Ensure CloudWatch alarms exist for Security Hub finding creation.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for Security Hub finding events'],
    remediationGuidance: 'Create CloudWatch alarm for new Security Hub findings.',
  },
  {
    id: 'KH-4.12',
    framework: 'KHALIFA_BASELINE',
    section: '4. Monitoring',
    title: 'Ensure CloudWatch alarms for GuardDuty findings',
    description: 'Ensure CloudWatch alarms exist for GuardDuty finding creation.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudWatch alarm for GuardDuty finding events'],
    remediationGuidance: 'Create CloudWatch alarm for new GuardDuty findings.',
  },
  {
    id: 'KH-3.10',
    framework: 'KHALIFA_BASELINE',
    section: '3. Logging',
    title: 'Ensure Config records all resource types',
    description: 'Ensure AWS Config records configuration changes for all resource types.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['ConfigRecorder vertices with recording_all_supported true.'],
    remediationGuidance: 'Configure Config recorder to record all resource types.',
  },
  {
    id: 'KH-3.11',
    framework: 'KHALIFA_BASELINE',
    section: '3. Logging',
    title: 'Ensure Config delivers to S3 bucket with encryption',
    description: 'Ensure AWS Config delivers configuration history to an encrypted S3 bucket.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Config delivery channel S3 bucket has encryption enabled'],
    remediationGuidance: 'Use encrypted S3 bucket for Config delivery.',
  },

  // GuardDuty and Security Hub enablement, VPC endpoint use, Transit Gateway
  // route restriction. None are CIS v3.0.0 requirements: the benchmark names
  // neither GuardDuty nor Security Hub at all, and its section 5 ends at 5.6.
  // 5.7 is EC2.8's number in v5.0.0, where IMDSv2 moved -- in v3.0.0 that is
  // 5.6, which this catalogue already has correctly.
  {
    id: 'KH-4.1',
    framework: 'KHALIFA_BASELINE',
    section: '4. Monitoring',
    title: 'Ensure GuardDuty is enabled in all regions',
    description: 'Ensure Amazon GuardDuty is enabled in all regions.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-017'],
    evidenceRequirements: ['GuardDuty detector exists and is enabled in all regions'],
    remediationGuidance:
      'Enable GuardDuty in all regions. Consider delegated administrator for multi-account.',
  },
  {
    id: 'KH-5.7',
    framework: 'KHALIFA_BASELINE',
    section: '5. Networking',
    title: 'Ensure VPC endpoints are used for AWS service access',
    description:
      'Ensure VPC endpoints (Gateway/Interface) are used for private AWS service access.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['VPC endpoints exist for S3, DynamoDB, and other services used'],
    remediationGuidance:
      'Create VPC endpoints for S3, DynamoDB, and other AWS services to avoid internet traversal.',
  },
  {
    id: 'KH-5.8',
    framework: 'KHALIFA_BASELINE',
    section: '5. Networking',
    title: 'Ensure Transit Gateway routes are restricted',
    description: 'Ensure Transit Gateway route tables restrict cross-VPC traffic.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['TGW route tables have specific routes, no 0.0.0.0/0 blackhole'],
    remediationGuidance: 'Configure TGW route tables with least-privilege routes between VPCs.',
  },

  // S3 versioning and server-side encryption, bucket access logging and
  // replication, RDS backup retention, EBS volume encryption. These carried
  // flat CIS ids 2.2-2.8. v3.0.0 section 2 is nested (2.1.x S3, 2.2.x EBS,
  // 2.3.x RDS, 2.4.x EFS) and has no requirement matching any of them, so the
  // flat ids collided with real ones meaning different things.
  {
    id: 'KH-2.2',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure S3 buckets have versioning enabled',
    description:
      'Ensure S3 buckets have versioning enabled to protect against accidental deletion.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['S3 bucket versioning status = Enabled'],
    remediationGuidance: 'Enable versioning on all S3 buckets.',
  },
  {
    id: 'KH-2.3',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure S3 buckets have server-side encryption enabled',
    description: 'Ensure S3 buckets have default server-side encryption (SSE-S3 or SSE-KMS).',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['S3 bucket default encryption configured'],
    remediationGuidance:
      'Enable default encryption on all S3 buckets. Use SSE-KMS for sensitive data.',
  },
  {
    id: 'KH-2.4',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure S3 bucket access logging is enabled',
    description: 'Ensure S3 buckets have access logging enabled to a target bucket.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['S3 bucket logging configuration present'],
    remediationGuidance: 'Configure access logging for all S3 buckets to a centralized log bucket.',
  },
  {
    id: 'KH-2.5',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure S3 bucket replication is enabled for critical data',
    description: 'Ensure critical S3 buckets have cross-region replication enabled.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Cross-region replication configured for critical buckets'],
    remediationGuidance: 'Enable CRR for buckets containing critical data.',
  },
  {
    id: 'KH-2.6',
    // Evaluator removed deliberately. It queried EbsVolume, a label the
    // collector has never created, so it reported PASS against no data --
    // a green tick for a check that never looked. NOT_EVALUATED is the
    // honest state until the collector stage and IAM grant exist.
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure EBS volumes are encrypted',
    description: 'Ensure all EBS volumes are encrypted at rest.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['All EBS volumes have Encrypted=true'],
    remediationGuidance:
      'Enable encryption by default for EBS. Encrypt existing unencrypted volumes.',
  },
  {
    id: 'KH-2.8',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure RDS instances have backup retention >= 7 days',
    description: 'Ensure RDS instances have automated backup retention of at least 7 days.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['RDS BackupRetentionPeriod >= 7'],
    remediationGuidance: 'Set automated backup retention to 7 days or more.',
  },
  // Redshift, ElastiCache and OpenSearch encryption, and RDS deletion
  // protection. These carried CIS ids 2.10-2.16 and are not in the benchmark:
  // v3.0.0 section 2 ends at 2.9, and mentions none of these services. Showing
  // an auditor "CIS 2.14: PASS" for a control CIS does not define is worse than
  // not having it, so they live here under KH- ids instead.
  {
    id: 'KH-2.10',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure RDS instances have deletion protection enabled',
    description: 'Ensure RDS instances have deletion protection enabled.',
    severity: 'medium',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['RDS DeletionProtection=true'],
    remediationGuidance: 'Enable deletion protection on all RDS instances.',
  },
  {
    id: 'KH-2.11',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure Redshift clusters are encrypted',
    description: 'Ensure Redshift clusters have encryption enabled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Redshift clusters have Encrypted=true'],
    remediationGuidance:
      'Enable encryption for Redshift clusters. Recreate from encrypted snapshots if needed.',
  },
  {
    id: 'KH-2.12',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure Redshift clusters are not publicly accessible',
    description: 'Ensure Redshift clusters do not have public accessibility enabled.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Redshift PubliclyAccessible=false'],
    remediationGuidance: 'Disable public accessibility on Redshift clusters.',
  },
  {
    id: 'KH-2.13',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure Elasticache clusters are encrypted in transit and at rest',
    description: 'Ensure ElastiCache clusters have encryption in transit and at rest.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'ElastiCache TransitEncryptionEnabled=true, AtRestEncryptionEnabled=true',
    ],
    remediationGuidance: 'Enable encryption in transit and at rest for ElastiCache clusters.',
  },
  {
    id: 'KH-2.14',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure OpenSearch domains are encrypted at rest',
    description: 'Ensure OpenSearch domains have encryption at rest enabled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['OpenSearch EncryptionAtRestOptions.Enabled=true'],
    remediationGuidance: 'Enable encryption at rest for OpenSearch domains.',
  },
  {
    id: 'KH-2.15',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure OpenSearch domains enforce HTTPS',
    description: 'Ensure OpenSearch domains enforce HTTPS for all traffic.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['OpenSearch DomainEndpointOptions.EnforceHTTPS=true'],
    remediationGuidance: 'Enforce HTTPS on OpenSearch domain endpoints.',
  },
  {
    id: 'KH-2.16',
    framework: 'KHALIFA_BASELINE',
    section: '2. Storage',
    title: 'Ensure OpenSearch domains have node-to-node encryption',
    description: 'Ensure OpenSearch domains have node-to-node encryption enabled.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['OpenSearch NodeToNodeEncryptionOptions.Enabled=true'],
    remediationGuidance: 'Enable node-to-node encryption for OpenSearch domains.',
  },
  {
    id: 'KH-3.4',
    framework: 'KHALIFA_BASELINE',
    section: '3. Logging',
    title: 'Ensure CloudTrail logs are sent to CloudWatch Logs',
    description: 'Ensure CloudTrail logs are delivered to CloudWatch Logs for monitoring.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail CloudWatchLogsLogGroupArn configured'],
    remediationGuidance: 'Configure CloudTrail to send logs to CloudWatch Logs.',
  },
  {
    id: 'KH-3.5',
    framework: 'KHALIFA_BASELINE',
    section: '3. Logging',
    title: 'Ensure S3 bucket used for CloudTrail logs is not public',
    description: 'Ensure the S3 bucket storing CloudTrail logs is not publicly accessible.',
    severity: 'critical',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['CloudTrail S3 bucket has Block Public Access enabled'],
    remediationGuidance: 'Enable Block Public Access on CloudTrail log bucket.',
  },
  {
    id: 'KH-5.1',
    framework: 'KHALIFA_BASELINE',
    section: '5. Networking',
    title: 'Ensure no Network ACLs allow unrestricted ingress to database ports',
    description:
      'CIS 5.1 stops at the administration ports, 22 and 3389. A network ACL that allows the whole internet inbound on 1433, 3306 or 5432 exposes every database in the subnets it is associated with, and nothing in v3.0.0 covers that. Unlike CIS 5.1 this control reads both address families, because it is ours to define and a dual-stack subnet is reachable either way.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [
      'NetworkAclEntry vertices with rule_action allow, direction ingress, cidr_block 0.0.0.0/0 or ::/0 covering port 1433, 3306 or 5432, on a NetworkAcl with at least one ASSOCIATED_WITH edge to a Subnet',
    ],
    remediationGuidance:
      'Scope the offending rule to the CIDRs that legitimately reach the database tier, or disassociate the NACL from its subnets. A default NACL cannot be deleted and always allows all ports, so moving subnets onto a custom NACL is what clears this — the default NACL itself stops being flagged once no subnet uses it.',
  },
  {
    id: 'KH-5.6',
    framework: 'KHALIFA_BASELINE',
    section: '5. Networking',
    title: 'Ensure restricted common ports on security groups',
    description: 'Ensure security groups restrict access to common sensitive ports.',
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: ['Security groups restrict ports 1433, 3306, 5432, 6379, 9200, 27017'],
    remediationGuidance: 'Restrict database and cache ports to application security groups only.',
  },
  {
    id: 'KH-IAM-1',
    framework: 'KHALIFA_BASELINE',
    section: '1. Identity and Access Management',
    title: 'Ensure internet-reachable and externally trusted roles are not broadly privileged',
    description:
      'A broadly privileged role is most dangerous where something outside the account can reach it: attached to an internet-reachable workload, or trusted by another principal.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-004', 'RULE-006'],
    evidenceRequirements: [
      'RULE-004: an admin role on an internet-reachable EC2 instance or Lambda. RULE-006: a role trusted by another principal holding an Allow on a wildcard resource.',
    ],
    remediationGuidance:
      'Scope the role to the actions and resources the workload uses; split roles that serve several purposes.',
  },
  {
    id: 'KH-IAM-2',
    framework: 'KHALIFA_BASELINE',
    section: '1. Identity and Access Management',
    title: 'Ensure no principal can assume its way to an admin or privilege-escalation role',
    description:
      'A chain of role trusts that ends at an admin role, or at a role that can grant itself more, gives every principal at its start that power.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-030'],
    evidenceRequirements: [
      'RULE-030: a principal or account that can assume, in up to three hops, an admin role or a role holding privilege-escalation actions.',
    ],
    remediationGuidance:
      'Trust specific roles instead of the account root, add trust conditions, and remove trusts no workload uses.',
  },
  {
    id: 'KH-EXP-1',
    framework: 'KHALIFA_BASELINE',
    section: 'Attack paths',
    title: 'Ensure internet-connected compute cannot reach classified data',
    description:
      'Compute the internet can reach, holding a role that grants access to classified data, is one hop from exfiltration.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-001', 'RULE-009'],
    evidenceRequirements: [
      'RULE-001: an internet-exposed EC2 instance whose role reaches a restricted S3 bucket. RULE-009: a VPC Lambda with internet access whose role reaches classified S3 or DynamoDB data.',
    ],
    remediationGuidance:
      'Remove the internet path, or narrow the role so it cannot reach the classified resource.',
  },
  {
    id: 'KH-SH-1',
    framework: 'KHALIFA_BASELINE',
    section: '4. Monitoring',
    title:
      'Ensure no critical or high Security Hub findings are active on internet-exposed resources',
    description:
      'CIS 4.16 only asks that Security Hub is enabled. This asks that what it finds on exposed resources is dealt with.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-018'],
    evidenceRequirements: [
      'Active SecurityHubFinding vertices of CRITICAL or HIGH severity on an internet-exposed resource (RULE-018).',
    ],
    remediationGuidance:
      'Remediate or suppress, with a recorded reason, each active critical or high finding on an internet-exposed resource.',
  },
  {
    id: 'KH-VULN-1',
    framework: 'KHALIFA_BASELINE',
    section: 'Vulnerability management',
    title: 'Ensure container images are free of critical CVEs',
    description:
      'Container images running on internet-reachable workloads should carry no critical severity CVEs.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-003'],
    evidenceRequirements: [
      'ContainerImage with HAS_CVE edges. Not evaluable: the collector records repository, digest and tag only, creates no Cve vertices, and RULE-003 is disabled for the same reason. Needs image scanning wired in.',
    ],
    remediationGuidance: 'Rebuild affected images from patched bases and redeploy.',
  },
  {
    id: 'KH-PATH-1',
    framework: 'KHALIFA_BASELINE',
    section: 'Attack paths',
    title: 'Ensure no reachable path exists from the internet to a crown-jewel resource',
    description:
      'Multi-hop reachability from the synthetic Internet vertex to a resource tagged crown_jewel.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-005'],
    evidenceRequirements: ['Graph traversal result for RULE-005'],
    remediationGuidance:
      'Break the path at its narrowest hop: remove the exposure, the role, or the grant.',
  },
  {
    id: 'KH-SEC-1',
    framework: 'KHALIFA_BASELINE',
    section: 'Secrets management',
    title: 'Ensure Secrets Manager access is scoped to explicit secret ARNs',
    description:
      'Identity and resource policies granting secret reads against wildcard resources or cross-account principals.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-010', 'RULE-016'],
    evidenceRequirements: ['Graph traversal result for RULE-010, RULE-016'],
    remediationGuidance:
      'Replace wildcard resources with explicit secret ARNs and remove cross-account principals.',
  },
  {
    id: 'KH-SEC-2',
    framework: 'KHALIFA_BASELINE',
    section: 'Secrets management',
    title: 'Ensure no secrets are stored in object storage or function environments',
    description:
      'Secret material detected by the DSPM scanner inside S3 objects or Lambda environment variables.',
    severity: 'high',
    automated: true,
    relatedRules: ['RULE-012'],
    evidenceRequirements: ['Graph traversal result for RULE-012'],
    remediationGuidance: 'Move the value into Secrets Manager and rotate the exposed credential.',
  },
  {
    id: 'KH-EKS-1',
    framework: 'KHALIFA_BASELINE',
    section: 'Kubernetes',
    title: 'Ensure EKS control-plane endpoints are not open to the internet',
    description: 'Clusters whose public API endpoint accepts traffic from any CIDR.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-019'],
    evidenceRequirements: ['Graph traversal result for RULE-019'],
    remediationGuidance:
      'Set public access CIDRs to known prefixes, or disable public endpoint access.',
  },
  {
    id: 'KH-DET-1',
    framework: 'KHALIFA_BASELINE',
    section: 'Detection',
    title: 'Ensure there are no unresolved credential-use anomalies',
    description:
      'Reworded from "credential-use anomalies are detected", which its rules could not measure: they fire when an anomaly occurs, so zero was the healthy state and a finding read as a control failure. Stated as an outcome, each finding is a violation.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-021', 'RULE-022'],
    evidenceRequirements: [
      'Open CloudTrailAnomaly findings of type SECRET_READ_NEW_SOURCE_IP (RULE-021) or ACCESS_DENIED_SPIKE (RULE-022).',
    ],
    remediationGuidance:
      'Investigate the principal and source IP; rotate the secret if the access was not expected.',
  },
  {
    id: 'KH-DET-2',
    framework: 'KHALIFA_BASELINE',
    section: 'Detection',
    title: 'Ensure no canary credential has been used',
    description:
      'Reworded from "decoy credentials are planted and monitored" for the same reason as KH-DET-1: RULE-023 fires when a canary is used, which is the violation, not evidence the control is missing.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-023'],
    evidenceRequirements: [
      'Open CloudTrailAnomaly findings of type CANARY_USED (RULE-023). Any use of a canary is a presumed compromise.',
    ],
    remediationGuidance:
      'Treat as an active intrusion: revoke the canary, and investigate how it was obtained.',
  },
  {
    id: 'KH-DET-3',
    framework: 'KHALIFA_BASELINE',
    section: 'Detection',
    title: 'Ensure no internet-exposed resource has an active GuardDuty attack finding',
    description:
      'Stated as the outcome RULE-029 measures, like KH-DET-1 and KH-DET-2: the finding is the violation. Findings are read from the GuardDuty delegated administrator, so every member account and region with a detector is covered.',
    severity: 'critical',
    automated: true,
    relatedRules: ['RULE-029'],
    evidenceRequirements: [
      'Open RULE-029 issues: unarchived GuardDuty findings of an attack class linked DETECTS_ON to a resource with is_internet_exposed.',
    ],
    remediationGuidance:
      'Contain the resource, rotate any credentials it holds, and resolve or archive the GuardDuty finding once investigated.',
  },
];

// Controls whose evidence comes from per-region resources. Their result only
// covers the regions the collector ran in (collection.regions), so a PASS says
// nothing about the others. Per the Security Hub source of truth
// (benchmarks/cis-aws-foundations-3.0.0): IAM.28 (1.20) and Config.1 (3.3) are
// evaluated in the current Region; EC2.6 (3.7) and EC2.2 (5.4) are per VPC;
// EC2.7 (2.2.1) is a per-Region account setting. The rest read resources that
// exist per Region. CloudTrail controls are not here: a multi-Region trail is
// visible from any one Region. IAM and S3 are global.
export const REGIONAL_CONTROL_IDS: ReadonlySet<string> = new Set([
  '1.20',
  '2.2.1',
  '2.3.1',
  '2.3.2',
  '2.3.3',
  '2.4.1',
  '3.3',
  '3.6',
  '3.7',
  '4.16',
  '5.1',
  '5.2',
  '5.3',
  '5.4',
  '5.6',
  'KH-2.6',
  'KH-2.8',
  'KH-2.10',
  'KH-2.11',
  'KH-2.12',
  'KH-2.13',
  'KH-2.14',
  'KH-2.15',
  'KH-2.16',
  'KH-3.10',
  'KH-3.11',
  'KH-4.1',
  'KH-5.1',
  'KH-5.6',
  'KH-5.7',
  'KH-EKS-1',
  'KH-PATH-1',
]);

// CIS v3.0.0 controls Khalifa evaluates although Security Hub, the source of
// truth (benchmarks/cis-aws-foundations-3.0.0), lists them as manual. Each is
// deliberate; cis-v3-source-of-truth.test.ts fails on any automated CIS
// control that is neither mapped by Security Hub nor listed here.
export const KHALIFA_AUTOMATED_BEYOND_SECURITY_HUB: Readonly<Record<string, string>> = {
  '1.7': 'Root activity is detected by RULE-020 from CloudTrail',
  '4.1': 'CloudWatch alarm and metric filter reads (CollectionPolicyV3)',
  '4.3': 'CloudWatch alarm and metric filter reads (CollectionPolicyV3)',
  '4.4': 'CloudWatch alarm and metric filter reads (CollectionPolicyV3)',
  '4.5': 'CloudWatch alarm and metric filter reads (CollectionPolicyV3)',
  '4.8': 'CloudWatch alarm and metric filter reads (CollectionPolicyV3)',
  '4.9': 'CloudWatch alarm and metric filter reads (CollectionPolicyV3)',
  '4.14': 'CloudWatch alarm and metric filter reads (CollectionPolicyV3)',
  '4.16': 'Security Hub cannot report on itself being disabled; the collector reads DescribeHub',
};

export function getAllControls(): ComplianceControl[] {
  return [...CIS_AWS_FOUNDATIONS_V3_CONTROLS, ...KHALIFA_BASELINE_CONTROLS];
}

export function getControlsByFramework(framework: ComplianceFramework): ComplianceControl[] {
  switch (framework) {
    case 'CIS_AWS_FOUNDATIONS':
      return CIS_AWS_FOUNDATIONS_V3_CONTROLS;
    case 'KHALIFA_BASELINE':
      return KHALIFA_BASELINE_CONTROLS;
    case 'SOC2':
    case 'ISO27001':
    case 'PCI_DSS':
    case 'NIST_800_53':
      // Mapped frameworks cite canonical controls instead of owning a catalog.
      return [];
  }
}

export function getControlById(
  id: string,
  framework?: ComplianceFramework
): ComplianceControl | undefined {
  const controls = framework ? getControlsByFramework(framework) : getAllControls();
  return controls.find((c) => c.id === id);
}
