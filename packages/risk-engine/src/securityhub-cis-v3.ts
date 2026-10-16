/**
 * Security Hub control -> CIS AWS Foundations Benchmark v3.0.0 requirement, from
 * the stored source of truth (benchmarks/cis-aws-foundations-3.0.0).
 * securityhub-cis-v3.test.ts keeps this equal to the page. S3.22 and S3.23 are
 * listed for v3.0.0 without a table row and are mapped by title (3.8, 3.9).
 * Several controls can map to one requirement (S3.1 and S3.8 -> 2.1.4).
 */
export const SECURITY_HUB_CIS_V3_REQUIREMENT: Readonly<Record<string, string>> = {
  'Account.1': '1.2',
  'CloudTrail.1': '3.1',
  'CloudTrail.2': '3.5',
  'CloudTrail.4': '3.2',
  'CloudTrail.7': '3.4',
  'Config.1': '3.3',
  'EC2.2': '5.4',
  'EC2.6': '3.7',
  'EC2.7': '2.2.1',
  'EC2.8': '5.6',
  'EC2.21': '5.1',
  'EC2.53': '5.2',
  'EC2.54': '5.3',
  'EFS.1': '2.4.1',
  'IAM.2': '1.15',
  'IAM.3': '1.14',
  'IAM.4': '1.4',
  'IAM.5': '1.10',
  'IAM.6': '1.6',
  'IAM.9': '1.5',
  'IAM.15': '1.8',
  'IAM.16': '1.9',
  'IAM.18': '1.17',
  'IAM.22': '1.12',
  'IAM.26': '1.19',
  'IAM.27': '1.22',
  'IAM.28': '1.20',
  'KMS.4': '3.6',
  'RDS.2': '2.3.3',
  'RDS.3': '2.3.1',
  'RDS.13': '2.3.2',
  'S3.1': '2.1.4',
  'S3.5': '2.1.1',
  'S3.8': '2.1.4',
  'S3.20': '2.1.2',
  'S3.22': '3.8',
  'S3.23': '3.9',
};

export const CIS_V3_STANDARDS_ID = 'standards/cis-aws-foundations-benchmark/v/3.0.0';

/** Requirement -> the Security Hub controls that implement it. */
export function controlsByRequirement(): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const [control, requirement] of Object.entries(SECURITY_HUB_CIS_V3_REQUIREMENT)) {
    map.set(requirement, [...(map.get(requirement) ?? []), control]);
  }
  return map;
}
