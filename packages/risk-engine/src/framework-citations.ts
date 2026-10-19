import type {
  ComplianceControl,
  ComplianceControlStatus,
  ComplianceFramework,
} from './compliance-types';
import { getControlById } from './compliance-types';

/**
 * Mapped frameworks cite the canonical controls (CIS and Khalifa baseline)
 * instead of defining their own catalogs and evaluators. One evaluation pass
 * produces evidence for every framework; a requirement's status is derived
 * from the statuses of the controls that evidence it.
 *
 * Mappings are curated like REVIEWED_MAPPING in control-rule-mapping.test.ts:
 * a citation exists only when the canonical control's meaning matches the
 * requirement, and `why` records the reasoning. `framework-citations.test.ts`
 * pins both the golden requirement list and that every cited id resolves.
 */
export type MappedFramework = 'SOC2' | 'ISO27001' | 'PCI_DSS' | 'NIST_800_53';

export const MAPPED_FRAMEWORKS: MappedFramework[] = ['SOC2', 'ISO27001', 'PCI_DSS', 'NIST_800_53'];

/** Canonical frameworks first, then the mapped ones. */
export const ALL_FRAMEWORKS: ComplianceFramework[] = [
  'CIS_AWS_FOUNDATIONS',
  'KHALIFA_BASELINE',
  ...MAPPED_FRAMEWORKS,
];

export interface FrameworkCitation {
  framework: MappedFramework;
  requirement: string;
  section: string;
  title: string;
  description: string;
  severity?: ComplianceControl['severity'];
  /** Canonical control ids that evidence this requirement. */
  controls: string[];
  /** Why these controls evidence the requirement. */
  why: string;
}

export const FRAMEWORK_VERSIONS: Record<ComplianceFramework, string> = {
  CIS_AWS_FOUNDATIONS: '3.0.0',
  KHALIFA_BASELINE: '2022',
  SOC2: '2017',
  ISO27001: '2022',
  PCI_DSS: '4.0',
  NIST_800_53: 'Rev. 5',
};

export function isMappedFramework(framework: ComplianceFramework): framework is MappedFramework {
  return (MAPPED_FRAMEWORKS as readonly string[]).includes(framework);
}

export function citationsByFramework(framework: MappedFramework): FrameworkCitation[] {
  return FRAMEWORK_CITATIONS.filter((citation) => citation.framework === framework);
}

/** Reverse index: which framework requirements cite this canonical control. */
export function citationsForControl(controlId: string): FrameworkCitation[] {
  return FRAMEWORK_CITATIONS.filter((citation) => citation.controls.includes(controlId));
}

/**
 * A requirement's status across its mapped controls. Conservative on purpose:
 * a requirement only passes when every mapped control passes (or does not
 * apply); anything manual or unevaluated keeps it NOT_EVALUATED so the
 * framework never looks better than the evidence behind it.
 */
export function aggregateMappedStatus(
  statuses: ComplianceControlStatus[]
): 'PASS' | 'FAIL' | 'NOT_APPLICABLE' | 'NOT_EVALUATED' {
  if (statuses.length === 0) return 'NOT_EVALUATED';
  if (statuses.some((status) => status === 'FAIL')) return 'FAIL';
  if (statuses.every((status) => status === 'PASS')) return 'PASS';
  if (statuses.every((status) => status === 'NOT_APPLICABLE')) return 'NOT_APPLICABLE';
  return 'NOT_EVALUATED';
}

export const FRAMEWORK_CITATIONS: FrameworkCitation[] = [
  // ---- SOC 2 (2017 Trust Services Criteria, Common Criteria) ----
  {
    framework: 'SOC2',
    requirement: 'CC6.1',
    section: 'Logical access',
    title: 'Logical access to systems is restricted to authorized users',
    description:
      'Root and user credentials, MFA, and group-based permissions are enforced, and internet-reachable or externally trusted roles are checked for broad privilege.',
    controls: ['1.4', '1.5', '1.7', '1.10', '1.15', 'KH-1.8', 'KH-1.19', 'KH-IAM-1'],
    why: 'Credential and least-privilege controls are the access enforcement Khalifa can observe from configuration.',
  },
  {
    framework: 'SOC2',
    requirement: 'CC6.2',
    section: 'Logical access',
    title: 'Access credentials are registered, rotated, and removed when no longer required',
    description:
      'Unused credentials are disabled, access keys rotate within 90 days, expired certificates are removed, and passwords expire.',
    controls: ['1.12', '1.14', '1.19', 'KH-1.15'],
    why: 'Credential lifecycle controls evidence registration and removal of access.',
  },
  {
    framework: 'SOC2',
    requirement: 'CC6.3',
    section: 'Logical access',
    title: 'Role-based access and least privilege are enforced',
    description:
      'Permissions are granted through groups, principals cannot escalate to admin, and privileged roles reachable from the internet are flagged.',
    controls: ['1.15', 'KH-1.19', 'KH-IAM-1', 'KH-IAM-2'],
    why: 'Group-based permission and escalation-path detection are the role model evidence.',
  },
  {
    framework: 'SOC2',
    requirement: 'CC6.6',
    section: 'Logical access',
    title: 'Boundary protection restricts access from outside the system',
    description:
      'Security groups and network ACLs do not expose administration or database ports to the internet, and default groups restrict all traffic.',
    controls: ['5.1', '5.2', '5.3', '5.4', 'KH-5.1', 'KH-5.6'],
    why: 'Network boundary controls evidence the protection of the system boundary.',
  },
  {
    framework: 'SOC2',
    requirement: 'CC6.7',
    section: 'Logical access',
    title: 'Transmission of data is restricted and encrypted',
    description:
      'Object storage denies unencrypted transport, and datastore endpoints enforce TLS in transit.',
    controls: ['2.1.1', 'KH-2.13', 'KH-2.15', 'KH-2.16'],
    why: 'In-transit encryption controls evidence restricted data transmission.',
  },
  {
    framework: 'SOC2',
    requirement: 'CC7.1',
    section: 'Monitoring and operations',
    title: 'Configuration and vulnerability detection procedures are in place',
    description:
      'AWS Config records and delivers changes, Security Hub and GuardDuty are enabled, and container images are checked for critical vulnerabilities.',
    controls: ['KH-VULN-1', '3.3', 'KH-3.10', 'KH-3.11', '4.16', 'KH-4.1'],
    why: 'Detection of misconfiguration and vulnerabilities is the CC7.1 evidence set.',
  },
  {
    framework: 'SOC2',
    requirement: 'CC7.2',
    section: 'Monitoring and operations',
    title: 'System components are monitored for anomalies',
    description:
      'CloudWatch alarms cover unauthorized API calls, root usage, and security-relevant changes; credential anomalies and canary use raise findings.',
    controls: [
      '4.1',
      '4.3',
      '4.4',
      '4.5',
      '4.8',
      '4.9',
      '4.14',
      'KH-4.4',
      'KH-4.11',
      'KH-4.12',
      'KH-DET-1',
      'KH-DET-2',
    ],
    why: 'Alarm coverage plus credential-anomaly and canary detection evidence anomaly monitoring.',
  },
  {
    framework: 'SOC2',
    requirement: 'CC7.3',
    section: 'Monitoring and operations',
    title: 'Security events are evaluated against criteria and incidents identified',
    description:
      'Detected anomalies, GuardDuty attack findings on exposed resources, and reachable attack paths are evaluated as security events.',
    controls: ['KH-DET-1', 'KH-DET-2', 'KH-DET-3', 'KH-SH-1', 'KH-EXP-1', 'KH-PATH-1'],
    why: 'Detection outcomes and attack-path reachability are how Khalifa evaluates events.',
  },
  {
    framework: 'SOC2',
    requirement: 'CC9.1',
    section: 'Availability',
    title: 'Availability is protected with backup and durability controls',
    description:
      'RDS instances keep at least seven days of backups with deletion protection, and critical data replicates.',
    controls: ['KH-2.5', 'KH-2.8', 'KH-2.10'],
    why: 'Backup retention, deletion protection, and replication evidence availability protection.',
  },

  // ---- ISO/IEC 27001:2022 Annex A ----
  {
    framework: 'ISO27001',
    requirement: 'A.5.15',
    section: 'Organizational controls',
    title: 'Access to information and systems is controlled',
    description:
      'Group-based permissions, unused-credential disablement, and least-privilege checks restrict access to information and systems.',
    controls: ['1.12', '1.15', 'KH-1.19', 'KH-IAM-1', 'KH-IAM-2'],
    why: 'Access control and least-privilege controls evidence A.5.15.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.5.16',
    section: 'Organizational controls',
    title: 'Identity lifecycle is managed',
    description:
      'Unused credentials are disabled, access keys rotate, and users are granted access through groups.',
    controls: ['1.12', '1.14', 'KH-1.19'],
    why: 'Credential lifecycle controls evidence identity management.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.5.17',
    section: 'Organizational controls',
    title: 'Authentication information is managed',
    description:
      'MFA is enforced for root and console users, hardware MFA is required, and the IAM password policy enforces length, reuse, and expiry.',
    controls: ['1.4', '1.5', '1.6', '1.8', '1.9', '1.10', 'KH-1.8', 'KH-1.15'],
    why: 'Credential hygiene and MFA controls evidence authentication information management.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.5.23',
    section: 'Organizational controls',
    title: 'Security of cloud services is assured',
    description:
      'Cloud storage blocks public access, databases are not publicly accessible, and EKS control-plane endpoints are not open to the internet.',
    controls: ['2.1.4', '2.3.3', 'KH-2.12', 'KH-EKS-1'],
    why: 'Public-exposure controls evidence the cloud-service configuration assurance.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.5.33',
    section: 'Organizational controls',
    title: 'Records are protected from loss or tampering',
    description:
      'CloudTrail log file validation is enabled, logs are KMS-encrypted, the trail bucket is not public, and object versioning is on.',
    controls: ['3.2', '3.5', 'KH-2.2', 'KH-3.5'],
    why: 'Log integrity and versioning controls evidence record protection.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.2',
    section: 'Technological controls',
    title: 'Privileged access rights are restricted',
    description:
      'Daily root use is eliminated, admin-effective-permission principals are detected, and root usage raises an alarm.',
    controls: ['1.7', '4.3', 'KH-IAM-1', 'KH-IAM-2'],
    why: 'Root-use and escalation controls evidence restricted privileged access.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.3',
    section: 'Technological controls',
    title: 'Information access is restricted to authorized scopes',
    description:
      'Secrets Manager access is scoped to explicit secret ARNs, secrets are kept out of object storage and function environments, and CloudShell full access is restricted.',
    controls: ['1.22', 'KH-SEC-1', 'KH-SEC-2'],
    why: 'Secret-scope and credentials-in-code controls evidence scope restriction.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.5',
    section: 'Technological controls',
    title: 'Secure authentication is enforced',
    description:
      'MFA protects root and console users, password reuse is blocked, and EC2 instances require IMDSv2.',
    controls: ['1.5', '1.9', '1.10', '5.6', 'KH-1.8'],
    why: 'MFA, password, and instance-identity controls evidence secure authentication.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.8',
    section: 'Technological controls',
    title: 'Technical vulnerabilities are managed',
    description:
      'Container images are checked for critical CVEs and RDS instances receive automatic minor version upgrades.',
    controls: ['2.3.2', 'KH-VULN-1'],
    why: 'Vulnerability detection and patch-level controls evidence vulnerability management.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.9',
    section: 'Technological controls',
    title: 'Configuration management is applied',
    description:
      'AWS Config records all resource types and delivers to an encrypted bucket, and EKS endpoints are configured closed to the internet.',
    controls: ['3.3', 'KH-3.10', 'KH-3.11', 'KH-EKS-1'],
    why: 'Configuration recording and hardening controls evidence configuration management.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.12',
    section: 'Technological controls',
    title: 'Data leakage is prevented',
    description:
      'Object storage blocks public access, and secrets are not exposed through storage or function environments.',
    controls: ['2.1.4', 'KH-SEC-1', 'KH-SEC-2'],
    why: 'Public-access and secret-exposure controls evidence leakage prevention.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.13',
    section: 'Technological controls',
    title: 'Information backup is maintained',
    description:
      'RDS instances keep at least seven days of backups with deletion protection, and critical data replicates.',
    controls: ['KH-2.5', 'KH-2.8', 'KH-2.10'],
    why: 'Backup and deletion-protection controls evidence information backup.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.15',
    section: 'Technological controls',
    title: 'Logging captures relevant events',
    description:
      'Organization CloudTrail records in all regions, VPC flow logs are enabled, S3 object-level logging is on, and trail logs reach CloudWatch Logs.',
    controls: ['3.1', '3.4', '3.7', '3.8', '3.9', 'KH-3.4'],
    why: 'Trail, flow-log, and object-log controls evidence event logging.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.16',
    section: 'Technological controls',
    title: 'Monitoring activities detect anomalies',
    description:
      'CloudWatch alarms, Security Hub, GuardDuty, and credential or canary anomaly detection watch for deviations, including attack findings on exposed resources.',
    controls: [
      '4.1',
      '4.3',
      '4.4',
      '4.5',
      '4.8',
      '4.9',
      '4.14',
      '4.16',
      'KH-4.1',
      'KH-4.11',
      'KH-4.12',
      'KH-DET-1',
      'KH-DET-2',
      'KH-DET-3',
    ],
    why: 'Alarm coverage and detection outcomes evidence monitoring activities.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.20',
    section: 'Technological controls',
    title: 'Networks and network devices are secured',
    description:
      'Security groups and NACLs do not expose administration or database ports, default groups restrict all traffic, and Transit Gateway routes are restricted.',
    controls: ['5.1', '5.2', '5.3', '5.4', 'KH-5.1', 'KH-5.6', 'KH-5.8'],
    why: 'Boundary and routing controls evidence network security.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.21',
    section: 'Technological controls',
    title: 'Security of network services is ensured',
    description:
      'Object storage denies unencrypted requests and OpenSearch domains enforce HTTPS with node-to-node encryption.',
    controls: ['2.1.1', 'KH-2.15', 'KH-2.16'],
    why: 'Transport-security controls evidence network service security.',
  },
  {
    framework: 'ISO27001',
    requirement: 'A.8.24',
    section: 'Technological controls',
    title: 'Cryptography is used to protect information',
    description:
      'EBS, RDS, EFS, Redshift, ElastiCache, OpenSearch, and S3 are encrypted at rest, logs are KMS-encrypted, and CMKs rotate.',
    controls: [
      '2.2.1',
      '2.3.1',
      '2.4.1',
      '3.5',
      '3.6',
      'KH-2.3',
      'KH-2.6',
      'KH-2.11',
      'KH-2.13',
      'KH-2.14',
      'KH-2.16',
    ],
    why: 'Encryption-at-rest and key-rotation controls evidence cryptographic protection.',
  },
  // ---- PCI DSS v4.0 (requirements Khalifa can evidence) ----
  {
    framework: 'PCI_DSS',
    requirement: '1.3',
    section: 'Network security',
    title: 'Network access to the cardholder data environment is restricted',
    description:
      'Security groups and network ACLs do not expose administration or database ports to the internet, and default groups restrict all traffic.',
    controls: ['5.1', '5.2', '5.3', '5.4', 'KH-5.1', 'KH-5.6'],
    why: 'Boundary controls are the network access restriction Khalifa observes.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '1.4',
    section: 'Network security',
    title: 'Connections between trusted and untrusted networks are controlled',
    description: 'Service traffic uses VPC endpoints and Transit Gateway routes are restricted.',
    controls: ['KH-5.7', 'KH-5.8'],
    why: 'Endpoint-based service access and restricted routes evidence controlled connectivity.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '2.2',
    section: 'Secure configuration',
    title: 'System components are configured and hardened securely',
    description:
      'AWS Config records all resource types and delivers to an encrypted bucket, and EKS control-plane endpoints are closed to the internet.',
    controls: ['3.3', 'KH-3.10', 'KH-3.11', 'KH-EKS-1'],
    why: 'Configuration recording and hardening controls evidence secure configuration.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '3.5',
    section: 'Data protection',
    title: 'Stored account data is protected with strong cryptography',
    description:
      'EBS, RDS, EFS, Redshift, ElastiCache, OpenSearch, and S3 storage are encrypted at rest, and CMKs rotate.',
    controls: [
      '2.2.1',
      '2.3.1',
      '2.4.1',
      '3.6',
      'KH-2.3',
      'KH-2.6',
      'KH-2.11',
      'KH-2.13',
      'KH-2.14',
    ],
    why: 'Encryption-at-rest and key-rotation controls evidence stored-data protection.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '4.2',
    section: 'Data protection',
    title: 'Account data in transit is protected with strong cryptography',
    description:
      'Object storage denies unencrypted transport, and datastore endpoints enforce TLS.',
    controls: ['2.1.1', 'KH-2.15', 'KH-2.16'],
    why: 'In-transit encryption controls evidence transmission protection.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '6.3',
    section: 'Vulnerability management',
    title: 'Security vulnerabilities are identified and addressed',
    description:
      'Container images are checked for critical CVEs and RDS instances receive automatic minor version upgrades.',
    controls: ['2.3.2', 'KH-VULN-1'],
    why: 'Vulnerability detection and patch-level controls evidence this requirement.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '7.2',
    section: 'Access control',
    title: 'Access to system components is appropriately defined and assigned',
    description:
      'Permissions are granted through groups, and principals cannot escalate to admin or remain broadly privileged behind internet exposure.',
    controls: ['1.15', 'KH-1.19', 'KH-IAM-1', 'KH-IAM-2'],
    why: 'Group-based permission and escalation detection evidence access assignment.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '8.3',
    section: 'Access control',
    title: 'User authentication is secured with strong factors',
    description:
      'MFA protects root and console users, hardware MFA is required, and password reuse is blocked.',
    controls: ['1.5', '1.6', '1.9', '1.10', 'KH-1.8'],
    why: 'MFA and password policy controls evidence strong user authentication.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '8.6',
    section: 'Access control',
    title: 'Interactive and system accounts are managed through their lifecycle',
    description:
      'Daily root use is eliminated, unused credentials are disabled, access keys rotate, and passwords expire.',
    controls: ['1.7', '1.12', '1.14', 'KH-1.15'],
    why: 'Account lifecycle controls evidence managed interactive and system accounts.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '10.2',
    section: 'Logging and monitoring',
    title: 'Audit logs capture the events relevant to the environment',
    description:
      'Organization CloudTrail records in all regions, VPC flow logs are enabled, S3 object-level logging is on, and trail logs reach CloudWatch Logs.',
    controls: ['3.1', '3.4', '3.7', '3.8', '3.9', 'KH-3.4'],
    why: 'Trail, flow-log, and object-log controls evidence audit logging coverage.',
  },
  {
    framework: 'PCI_DSS',
    requirement: '10.4',
    section: 'Logging and monitoring',
    title: 'Audit logs are reviewed and anomalies are acted on',
    description:
      'CloudWatch alarms, Security Hub, GuardDuty, and credential or canary anomaly detection watch for deviations.',
    controls: [
      '4.1',
      '4.3',
      '4.4',
      '4.5',
      '4.8',
      '4.9',
      '4.14',
      'KH-4.4',
      'KH-4.11',
      'KH-4.12',
      'KH-DET-1',
      'KH-DET-2',
    ],
    why: 'Alarm coverage and detection outcomes evidence log review and anomaly response.',
  },

  // ---- NIST SP 800-53 Rev. 5 (selected controls Khalifa can evidence) ----
  {
    framework: 'NIST_800_53',
    requirement: 'AC-2',
    section: 'Access control',
    title: 'Account management',
    description:
      'Unused credentials are disabled, access keys rotate, and users are granted access through groups.',
    controls: ['1.12', '1.14', 'KH-1.15', 'KH-1.19'],
    why: 'Credential lifecycle controls evidence account management.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'AC-6',
    section: 'Access control',
    title: 'Least privilege',
    description:
      'Permissions are granted through groups, and principals cannot escalate to admin or remain broadly privileged behind internet exposure.',
    controls: ['1.15', 'KH-IAM-1', 'KH-IAM-2'],
    why: 'Group-based permission and escalation detection evidence least privilege.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'AU-2',
    section: 'Audit and accountability',
    title: 'Event logging',
    description:
      'Organization CloudTrail records in all regions, VPC flow logs are enabled, and trail logs reach CloudWatch Logs.',
    controls: ['3.1', '3.4', '3.7', 'KH-3.4'],
    why: 'Trail and flow-log controls evidence the events logged.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'AU-6',
    section: 'Audit and accountability',
    title: 'Audit record review, analysis, and reporting',
    description:
      'CloudWatch alarms, Security Hub, GuardDuty, attack findings on exposed resources, and credential anomaly detection feed review.',
    controls: [
      '4.1',
      '4.3',
      '4.4',
      '4.5',
      '4.8',
      '4.9',
      '4.14',
      'KH-4.11',
      'KH-4.12',
      'KH-DET-1',
      'KH-DET-2',
      'KH-DET-3',
    ],
    why: 'Detection and alarm outcomes evidence audit review and analysis.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'CM-6',
    section: 'Configuration management',
    title: 'Configuration settings',
    description:
      'AWS Config records all resource types and delivers to an encrypted bucket, and EKS control-plane endpoints are closed to the internet.',
    controls: ['3.3', 'KH-3.10', 'KH-3.11', 'KH-EKS-1'],
    why: 'Configuration recording and hardening controls evidence managed settings.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'CP-9',
    section: 'Contingency planning',
    title: 'System backup',
    description:
      'RDS instances keep at least seven days of backups with deletion protection, and critical data replicates.',
    controls: ['KH-2.5', 'KH-2.8', 'KH-2.10'],
    why: 'Backup and deletion-protection controls evidence system backup.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'IA-2',
    section: 'Identification and authentication',
    title: 'Identification and authentication (organizational users)',
    description:
      'MFA protects root and console users, hardware MFA is required, and password reuse is blocked.',
    controls: ['1.5', '1.6', '1.9', '1.10', 'KH-1.8'],
    why: 'MFA and password policy controls evidence user identification and authentication.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'IA-5',
    section: 'Identification and authentication',
    title: 'Authenticator management',
    description:
      'Root access keys are absent, the password policy enforces length, reuse and expiry, and access keys rotate.',
    controls: ['1.4', '1.8', '1.9', '1.14', 'KH-1.15'],
    why: 'Credential policy and rotation controls evidence authenticator management.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'RA-5',
    section: 'Risk assessment',
    title: 'Vulnerability monitoring and scanning',
    description:
      'Container images are checked for critical CVEs, and Security Hub or GuardDuty findings on exposed resources are surfaced.',
    controls: ['KH-VULN-1', 'KH-SH-1', 'KH-DET-3'],
    why: 'Vulnerability and exposure findings evidence monitoring and scanning.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'SC-7',
    section: 'System and communications protection',
    title: 'Boundary protection',
    description:
      'Security groups and NACLs do not expose administration or database ports, default groups restrict all traffic, and Transit Gateway routes are restricted.',
    controls: ['5.1', '5.2', '5.3', '5.4', 'KH-5.1', 'KH-5.6', 'KH-5.8'],
    why: 'Boundary and routing controls evidence boundary protection.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'SC-8',
    section: 'System and communications protection',
    title: 'Transmission confidentiality and integrity',
    description:
      'Object storage denies unencrypted transport, and OpenSearch domains enforce HTTPS with node-to-node encryption.',
    controls: ['2.1.1', 'KH-2.15', 'KH-2.16'],
    why: 'Transport-security controls evidence transmission protection.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'SC-12',
    section: 'System and communications protection',
    title: 'Cryptographic key establishment and management',
    description: 'Customer-created symmetric CMKs rotate.',
    controls: ['3.6'],
    why: 'Key-rotation control evidences cryptographic key management.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'SC-13',
    section: 'System and communications protection',
    title: 'Cryptographic protection',
    description:
      'EBS, RDS, EFS, Redshift, ElastiCache, OpenSearch, and S3 storage are encrypted at rest, and CloudTrail logs are KMS-encrypted.',
    controls: [
      '2.2.1',
      '2.3.1',
      '2.4.1',
      '3.5',
      'KH-2.3',
      'KH-2.6',
      'KH-2.11',
      'KH-2.13',
      'KH-2.14',
    ],
    why: 'Encryption controls evidence cryptographic protection of data.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'SI-2',
    section: 'System and information integrity',
    title: 'Flaw remediation',
    description:
      'Container images are checked for critical CVEs and RDS instances receive automatic minor version upgrades.',
    controls: ['2.3.2', 'KH-VULN-1'],
    why: 'Vulnerability detection and patch-level controls evidence flaw remediation.',
  },
  {
    framework: 'NIST_800_53',
    requirement: 'SI-4',
    section: 'System and information integrity',
    title: 'System monitoring',
    description:
      'Security Hub and GuardDuty are enabled, and credential, canary, and attack-finding detections monitor the environment.',
    controls: ['4.16', 'KH-4.1', 'KH-DET-1', 'KH-DET-2', 'KH-DET-3', 'KH-SH-1'],
    why: 'Detection enablement and outcomes evidence system monitoring.',
  },
];

// Resolved lazily so tests can assert resolution without import cycles.
export function resolveCitationControls(citation: FrameworkCitation): ComplianceControl[] {
  return citation.controls
    .map((id) => getControlById(id))
    .filter((c): c is ComplianceControl => !!c);
}
