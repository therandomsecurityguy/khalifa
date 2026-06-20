import type { ComplianceControlStatus, ComplianceEvidence } from './compliance-types';
import { ComplianceControl } from './compliance-types';

export interface ComplianceRuleEvaluator {
  controlId: string;
  evaluate: (graphClient: any) => Promise<{
    status: ComplianceControlStatus;
    evidence: ComplianceEvidence[];
    issues: string[];
  }>;
}

export const complianceRuleEvaluators: ComplianceRuleEvaluator[] = [
  {
    controlId: '1.4',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'IamUser')
          .has('arn', textContains('root'))
          .out('HAS_ACCESS_KEY')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.4',
            resourceId: 'root',
            resourceType: 'IamUser',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { rootAccessKeyCount: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`Root account has ${count} access key(s)`] : [],
      };
    },
  },
  {
    controlId: '1.5',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'IamUser')
          .has('arn', textContains('root'))
          .has('mfa_enabled', true)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const hasMfa = (result[0] || 0) > 0;
      return {
        status: hasMfa ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.5',
            resourceId: 'root',
            resourceType: 'IamUser',
            status: hasMfa ? 'PASS' : 'FAIL',
            details: { mfaEnabled: hasMfa },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: hasMfa ? [] : ['Root account does not have MFA enabled'],
      };
    },
  },
  {
    controlId: '1.7',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'IamUser')
          .has('password_enabled', true)
          .has('mfa_enabled', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.7',
            resourceId: 'iam-users',
            resourceType: 'IamUser',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { usersWithoutMfa: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} IAM users with console access lack MFA`] : [],
      };
    },
  },
  {
    controlId: '1.10',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'IamUser')
          .out('HAS_ACCESS_KEY')
          .has('last_used_date', lte(new Date(Date.now() - 90*24*60*60*1000).toISOString()))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.10',
            resourceId: 'iam-access-keys',
            resourceType: 'AccessKey',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { keysOlderThan90Days: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} access keys not rotated in 90+ days`] : [],
      };
    },
  },
  {
    controlId: '1.11',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'AccessKey')
          .has('last_used_date', lte(new Date(Date.now() - 90*24*60*60*1000).toISOString()))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.11',
            resourceId: 'iam-access-keys',
            resourceType: 'AccessKey',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { unusedKeys: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} access keys unused for 90+ days`] : [],
      };
    },
  },
  {
    controlId: '1.12',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'IamUser')
          .out('HAS_INLINE_POLICY')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.12',
            resourceId: 'iam-users',
            resourceType: 'IamUser',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { usersWithInlinePolicies: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} IAM users have inline policies`] : [],
      };
    },
  },
  {
    controlId: '1.13',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'AccountPasswordPolicy')
          .has('min_password_length', lt(14))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.13',
            resourceId: 'account-password-policy',
            resourceType: 'AccountPasswordPolicy',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { policyCompliant: count === 0 },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? ['Password policy minimum length < 14'] : [],
      };
    },
  },
  {
    controlId: '1.14',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'AccountPasswordPolicy')
          .has('password_reuse_prevention', lt(24))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.14',
            resourceId: 'account-password-policy',
            resourceType: 'AccountPasswordPolicy',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { policyCompliant: count === 0 },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? ['Password policy reuse prevention < 24'] : [],
      };
    },
  },
  {
    controlId: '1.15',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'AccountPasswordPolicy')
          .has('max_password_age', gt(90))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '1.15',
            resourceId: 'account-password-policy',
            resourceType: 'AccountPasswordPolicy',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { policyCompliant: count === 0 },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? ['Password policy max age > 90 days'] : [],
      };
    },
  },
  {
    controlId: '2.1',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'S3Bucket')
          .has('is_publicly_accessible', true)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.1',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { publicBuckets: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} S3 buckets are publicly accessible`] : [],
      };
    },
  },
  {
    controlId: '2.2',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'S3Bucket')
          .has('versioning_enabled', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.2',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { bucketsWithoutVersioning: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} S3 buckets lack versioning`] : [],
      };
    },
  },
  {
    controlId: '2.3',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'S3Bucket')
          .has('default_encryption', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.3',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { bucketsWithoutEncryption: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} S3 buckets lack default encryption`] : [],
      };
    },
  },
  {
    controlId: '2.4',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'S3Bucket')
          .has('logging_enabled', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.4',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { bucketsWithoutLogging: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} S3 buckets lack access logging`] : [],
      };
    },
  },
  {
    controlId: '2.6',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'EbsVolume')
          .has('encrypted', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.6',
            resourceId: 'ebs-volumes',
            resourceType: 'EbsVolume',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { unencryptedVolumes: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} EBS volumes are not encrypted`] : [],
      };
    },
  },
  {
    controlId: '2.7',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'RdsInstance')
          .has('storage_encrypted', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.7',
            resourceId: 'rds-instances',
            resourceType: 'RdsInstance',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { unencryptedInstances: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} RDS instances are not encrypted`] : [],
      };
    },
  },
  {
    controlId: '2.8',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'RdsInstance')
          .has('backup_retention_period', lt(7))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.8',
            resourceId: 'rds-instances',
            resourceType: 'RdsInstance',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { instancesWithShortRetention: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} RDS instances have backup retention < 7 days`] : [],
      };
    },
  },
  {
    controlId: '2.9',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'RdsInstance')
          .has('publicly_accessible', true)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.9',
            resourceId: 'rds-instances',
            resourceType: 'RdsInstance',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { publicInstances: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} RDS instances are publicly accessible`] : [],
      };
    },
  },
  {
    controlId: '2.10',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'RdsInstance')
          .has('deletion_protection', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '2.10',
            resourceId: 'rds-instances',
            resourceType: 'RdsInstance',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { instancesWithoutDeletionProtection: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} RDS instances lack deletion protection`] : [],
      };
    },
  },
  {
    controlId: '3.1',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'CloudTrail')
          .has('is_multi_region_trail', true)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count > 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '3.1',
            resourceId: 'cloudtrail',
            resourceType: 'CloudTrail',
            status: count > 0 ? 'PASS' : 'FAIL',
            details: { multiRegionTrails: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count === 0 ? ['No multi-region CloudTrail trail found'] : [],
      };
    },
  },
  {
    controlId: '3.2',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'CloudTrail')
          .has('log_file_validation_enabled', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '3.2',
            resourceId: 'cloudtrail',
            resourceType: 'CloudTrail',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { trailsWithoutValidation: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} CloudTrail trails lack log file validation`] : [],
      };
    },
  },
  {
    controlId: '3.3',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'CloudTrail')
          .has('kms_key_id', '')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '3.3',
            resourceId: 'cloudtrail',
            resourceType: 'CloudTrail',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { trailsWithoutKms: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} CloudTrail trails lack KMS encryption`] : [],
      };
    },
  },
  {
    controlId: '3.4',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'CloudTrail')
          .has('cloudwatch_logs_log_group_arn', '')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '3.4',
            resourceId: 'cloudtrail',
            resourceType: 'CloudTrail',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { trailsWithoutCloudWatchLogs: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} CloudTrail trails not sending to CloudWatch Logs`] : [],
      };
    },
  },
  {
    controlId: '3.7',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'Vpc')
          .has('flow_logs_enabled', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '3.7',
            resourceId: 'vpcs',
            resourceType: 'Vpc',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { vpcsWithoutFlowLogs: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} VPCs lack flow logs`] : [],
      };
    },
  },
  {
    controlId: '3.9',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'ConfigRecorder')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count > 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '3.9',
            resourceId: 'aws-config',
            resourceType: 'ConfigRecorder',
            status: count > 0 ? 'PASS' : 'FAIL',
            details: { configRecorders: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count === 0 ? ['AWS Config not enabled'] : [],
      };
    },
  },
  {
    controlId: '4.1',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'GuardDutyDetector')
          .has('status', 'ENABLED')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count > 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '4.1',
            resourceId: 'guardduty',
            resourceType: 'GuardDutyDetector',
            status: count > 0 ? 'PASS' : 'FAIL',
            details: { enabledDetectors: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count === 0 ? ['GuardDuty not enabled in any region'] : [],
      };
    },
  },
  {
    controlId: '4.2',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'SecurityHub')
          .has('enabled', true)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count > 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '4.2',
            resourceId: 'security-hub',
            resourceType: 'SecurityHub',
            status: count > 0 ? 'PASS' : 'FAIL',
            details: { enabledRegions: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count === 0 ? ['Security Hub not enabled'] : [],
      };
    },
  },
  {
    controlId: '5.1',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'SecurityGroup')
          .out('ALLOWS_INGRESS')
          .has('cidr_block', '0.0.0.0/0')
          .has('port_range', within(22, 22))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '5.1',
            resourceId: 'security-groups',
            resourceType: 'SecurityGroup',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { groupsWithOpenSsh: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} security groups allow 0.0.0.0/0 on port 22`] : [],
      };
    },
  },
  {
    controlId: '5.2',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'SecurityGroup')
          .out('ALLOWS_INGRESS')
          .has('cidr_block', '0.0.0.0/0')
          .has('port_range', within(3389, 3389))
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '5.2',
            resourceId: 'security-groups',
            resourceType: 'SecurityGroup',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { groupsWithOpenRdp: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} security groups allow 0.0.0.0/0 on port 3389`] : [],
      };
    },
  },
  {
    controlId: '5.3',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'SecurityGroup')
          .has('is_default', true)
          .out('ALLOWS_INGRESS')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '5.3',
            resourceId: 'default-security-groups',
            resourceType: 'SecurityGroup',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { defaultGroupsWithRules: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} default security groups have inbound rules`] : [],
      };
    },
  },
  {
    controlId: '5.4',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'Vpc')
          .has('flow_logs_enabled', false)
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: '5.4',
            resourceId: 'vpcs',
            resourceType: 'Vpc',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { vpcsWithoutFlowLogs: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} VPCs lack flow logs`] : [],
      };
    },
  },
  {
    controlId: 'CC6.1',
    evaluate: async (graphClient) => {
      const queries = [
        `g.V().has('label', 'IamUser').has('mfa_enabled', false).has('password_enabled', true).count()`,
        `g.V().has('label', 'SecurityGroup').out('ALLOWS_INGRESS').has('cidr_block', '0.0.0.0/0').has('port_range', within(22, 3389)).count()`,
        `g.V().has('label', 'S3Bucket').has('is_publicly_accessible', true).count()`,
      ];
      const results = await Promise.all(queries.map((q) => graphClient.executeQuery(q)));
      const totalIssues = results.reduce((sum, r) => sum + (r[0] || 0), 0);
      return {
        status: totalIssues === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'CC6.1',
            resourceId: 'logical-access',
            resourceType: 'Composite',
            status: totalIssues === 0 ? 'PASS' : 'FAIL',
            details: {
              usersWithoutMfa: results[0][0] || 0,
              openSecurityGroups: results[1][0] || 0,
              publicBuckets: results[2][0] || 0,
            },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: totalIssues > 0 ? ['Logical access controls have gaps'] : [],
      };
    },
  },
  {
    controlId: 'CC6.6',
    evaluate: async (graphClient) => {
      const queries = [
        `g.V().has('label', 'S3Bucket').has('default_encryption', false).count()`,
        `g.V().has('label', 'EbsVolume').has('encrypted', false).count()`,
        `g.V().has('label', 'RdsInstance').has('storage_encrypted', false).count()`,
      ];
      const results = await Promise.all(queries.map((q) => graphClient.executeQuery(q)));
      const totalIssues = results.reduce((sum, r) => sum + (r[0] || 0), 0);
      return {
        status: totalIssues === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'CC6.6',
            resourceId: 'encryption',
            resourceType: 'Composite',
            status: totalIssues === 0 ? 'PASS' : 'FAIL',
            details: {
              unencryptedS3: results[0][0] || 0,
              unencryptedEbs: results[1][0] || 0,
              unencryptedRds: results[2][0] || 0,
            },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: totalIssues > 0 ? ['Encryption gaps detected'] : [],
      };
    },
  },
  {
    controlId: 'A.8.2',
    evaluate: async (graphClient) => {
      const query = `
        g.V().has('label', 'S3Bucket')
          .has('data_classification', '')
          .count()
      `;
      const result = await graphClient.executeQuery(query);
      const count = result[0] || 0;
      return {
        status: count === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'A.8.2',
            resourceId: 's3-buckets',
            resourceType: 'S3Bucket',
            status: count === 0 ? 'PASS' : 'FAIL',
            details: { bucketsWithoutClassification: count },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: count > 0 ? [`${count} S3 buckets lack data classification tags`] : [],
      };
    },
  },
  {
    controlId: 'A.9.2',
    evaluate: async (graphClient) => {
      const queries = [
        `g.V().has('label', 'IamUser').has('mfa_enabled', false).has('password_enabled', true).count()`,
        `g.V().has('label', 'IamUser').out('HAS_ACCESS_KEY').has('last_used_date', lte(new Date(Date.now() - 90*24*60*60*1000).toISOString())).count()`,
      ];
      const results = await Promise.all(queries.map((q) => graphClient.executeQuery(q)));
      const totalIssues = results.reduce((sum, r) => sum + (r[0] || 0), 0);
      return {
        status: totalIssues === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'A.9.2',
            resourceId: 'user-access',
            resourceType: 'Composite',
            status: totalIssues === 0 ? 'PASS' : 'FAIL',
            details: { usersWithoutMfa: results[0][0] || 0, staleAccessKeys: results[1][0] || 0 },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: totalIssues > 0 ? ['User access management gaps'] : [],
      };
    },
  },
  {
    controlId: 'A.10.1',
    evaluate: async (graphClient) => {
      const queries = [
        `g.V().has('label', 'S3Bucket').has('default_encryption', false).count()`,
        `g.V().has('label', 'EbsVolume').has('encrypted', false).count()`,
        `g.V().has('label', 'RdsInstance').has('storage_encrypted', false).count()`,
      ];
      const results = await Promise.all(queries.map((q) => graphClient.executeQuery(q)));
      const totalIssues = results.reduce((sum, r) => sum + (r[0] || 0), 0);
      return {
        status: totalIssues === 0 ? 'PASS' : 'FAIL',
        evidence: [
          {
            controlId: 'A.10.1',
            resourceId: 'cryptographic-controls',
            resourceType: 'Composite',
            status: totalIssues === 0 ? 'PASS' : 'FAIL',
            details: {
              unencryptedS3: results[0][0] || 0,
              unencryptedEbs: results[1][0] || 0,
              unencryptedRds: results[2][0] || 0,
            },
            collectedAt: new Date().toISOString(),
            collectedBy: 'compliance-engine',
          },
        ],
        issues: totalIssues > 0 ? ['Cryptographic control gaps'] : [],
      };
    },
  },
];

export function getEvaluatorForControl(controlId: string): ComplianceRuleEvaluator | undefined {
  return complianceRuleEvaluators.find((e) => e.controlId === controlId);
}

export function getAllEvaluators(): ComplianceRuleEvaluator[] {
  return complianceRuleEvaluators;
}
