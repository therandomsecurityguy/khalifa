import { readFileSync } from 'fs';
import { resolve } from 'path';

const roleTemplate = readFileSync(
  resolve(__dirname, '../../../templates/SecurityGraphCollectorRole.yaml'),
  'utf8'
);

describe('organization collection infrastructure', () => {
  it('requires exact hub principals and controlled ExternalId without ReadOnlyAccess', () => {
    expect(roleTemplate).toContain('!Ref TrustedPrincipalArn');
    expect(roleTemplate).toContain('!Ref AdditionalTrustedPrincipalArn');
    expect(roleTemplate).toContain('StringEquals:');
    expect(roleTemplate).toContain('sts:ExternalId: !Ref ExternalId');
    expect(roleTemplate).not.toContain('role/*');
    expect(roleTemplate).not.toContain('ReadOnlyAccess');
    expect(roleTemplate).not.toMatch(/^\s+- [a-z0-9-]+:\*$/m);
    expect(roleTemplate).toContain('iam:ListGroupsForUser');
    // GetBucketEncryption is authorized by s3:GetEncryptionConfiguration; the API-shaped
    // name is not an IAM action and grants nothing.
    expect(roleTemplate).toContain('s3:GetEncryptionConfiguration');
    expect(roleTemplate).not.toContain('s3:GetBucketEncryption');
    expect(roleTemplate).toContain('CollectionPolicyV3');
    expect(roleTemplate).not.toContain('CollectionPolicyV2');
    expect(roleTemplate).toContain('iam:ListAccessKeys');
    expect(roleTemplate).toContain('iam:GenerateCredentialReport');
    expect(roleTemplate).toContain('kms:GetKeyRotationStatus');
    expect(roleTemplate).toContain('secretsmanager:GetResourcePolicy');
    expect(roleTemplate).toContain('ec2:DescribeFlowLogs');
    expect(roleTemplate).toContain('config:DescribeConfigurationRecorders');
    expect(roleTemplate).toContain('config:DescribeConfigurationRecorderStatus');
    expect(roleTemplate).toContain('config:DescribeDeliveryChannels');
    expect(roleTemplate).toContain('guardduty:ListDetectors');
    expect(roleTemplate).toContain('guardduty:GetAdministratorAccount');
    // Findings are read from the GuardDuty delegated administrator's detectors.
    expect(roleTemplate).toContain('guardduty:ListFindings');
    expect(roleTemplate).toContain('guardduty:GetFindings');
    expect(roleTemplate).toContain('securityhub:GetFindings');
    expect(roleTemplate).toContain('securityhub:GetEnabledStandards');
    expect(roleTemplate).toContain('cloudtrail:GetEventSelectors');
    expect(roleTemplate).toContain('logs:DescribeLogGroups');
    // V3: the read permissions CIS 1.6, 1.19, 2.1.1, 2.2.1, 2.4.1, section 4 and
    // KH-2.6 need. Each is also granted to the hub in khalifa-data/iam.tf.
    for (const action of [
      'cloudwatch:DescribeAlarms',
      'logs:DescribeMetricFilters',
      'iam:ListVirtualMFADevices',
      'iam:ListServerCertificates',
      's3:GetBucketPolicy',
      // CIS 2.1.4 passes on the account-level Block Public Access setting too.
      's3:GetAccountPublicAccessBlock',
      'ec2:GetEbsEncryptionByDefault',
      'ec2:DescribeVolumes',
      'elasticfilesystem:DescribeFileSystems',
    ]) {
      expect(roleTemplate).toContain(action);
    }
    // Resolves an EC2 instance profile to its role. Also granted to the hub
    // in khalifa-data/iam.tf.
    expect(roleTemplate).toContain('iam:ListInstanceProfiles');
    // Finds Lambda function URLs and invoke policies open to the internet.
    // Also granted to the hub in khalifa-data/iam.tf.
    expect(roleTemplate).toContain('lambda:ListFunctionUrlConfigs');
    expect(roleTemplate).toContain('lambda:GetPolicy');
    expect(roleTemplate).toContain('CreateCollectorRole');
    expect(roleTemplate).toMatch(/ExternalId:[\s\S]*?MinLength: 16/);
  });
});
