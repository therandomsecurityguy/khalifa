import { GuardDutyClient } from '@aws-sdk/client-guardduty';
import { SecurityHubClient } from '@aws-sdk/client-securityhub';
import { collectGuardDuty, collectSecurityHub } from './security-services';

const ACCOUNT = '111122223333';

function createMockClient(responses: {
  [commandName: string]: (input: Record<string, unknown>) => unknown;
}): unknown {
  const send = jest.fn(async (command: { constructor: { name: string } }) => {
    const handler = responses[command.constructor.name];
    if (!handler) {
      throw new Error(`Unexpected command in test: ${command.constructor.name}`);
    }
    return handler((command as unknown as { input: Record<string, unknown> }).input || {});
  });
  return { send };
}

describe('collectGuardDuty', () => {
  it('emits detector nodes with status and feature flags', async () => {
    const client = createMockClient({
      ListDetectorsCommand: () => ({ DetectorIds: ['abc123'] }),
      GetAdministratorAccountCommand: () => ({ Administrator: { AccountId: '999988887777' } }),
      GetDetectorCommand: () => ({
        Status: 'ENABLED',
        FindingPublishingFrequency: 'FIFTEEN_MINUTES',
        CreatedAt: '2025-01-01T00:00:00Z',
        Features: [
          { Name: 'EKS_AUDIT_LOGS', Status: 'ENABLED' },
          { Name: 'S3_DATA_EVENTS', Status: 'DISABLED' },
          { Name: 'UNKNOWN_FEATURE', Status: 'ENABLED' },
        ],
      }),
    }) as GuardDutyClient;

    const { nodes, edges } = await collectGuardDuty(
      client as GuardDutyClient,
      ACCOUNT,
      'us-east-1'
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0].label).toBe('GuardDutyDetector');
    expect(nodes[0].id).toBe(`arn:aws:guardduty:us-east-1:${ACCOUNT}:detector/abc123`);
    expect(nodes[0].properties).toMatchObject({
      status: 'ENABLED',
      finding_publishing_frequency: 'FIFTEEN_MINUTES',
      administrator_account_id: '999988887777',
      eks_audit_logs_enabled: true,
      s3_data_events_enabled: false,
    });
    expect(nodes[0].properties.unknown_feature_enabled).toBeUndefined();
    expect(edges).toHaveLength(0);
  });

  it('emits a synthetic MISSING detector vertex when no detector exists', async () => {
    const client = createMockClient({
      ListDetectorsCommand: () => ({ DetectorIds: [] }),
    });

    const { nodes } = await collectGuardDuty(client as GuardDutyClient, ACCOUNT, 'us-east-1');

    expect(nodes).toHaveLength(1);
    expect(nodes[0].id).toBe(`arn:aws:guardduty:us-east-1:${ACCOUNT}:detector/missing`);
    expect(nodes[0].properties).toMatchObject({ status: 'MISSING', region: 'us-east-1' });
  });

  it('collects every detector when several exist', async () => {
    const client = createMockClient({
      ListDetectorsCommand: () => ({ DetectorIds: ['a', 'b'] }),
      GetAdministratorAccountCommand: () => {
        const error = new Error('not org');
        error.name = 'BadRequestException';
        throw error;
      },
      GetDetectorCommand: () => ({ Status: 'DISABLED' }),
    });

    const { nodes } = await collectGuardDuty(client as GuardDutyClient, ACCOUNT, 'us-east-1');
    expect(nodes).toHaveLength(2);
    for (const node of nodes) {
      expect(node.properties.status).toBe('DISABLED');
    }
  });
});

describe('collectSecurityHub', () => {
  it('caps each severity window at its own page bound and flags each as truncated', async () => {
    const window = (input: any) => input.Filters.SeverityLabel[0].Value as string;
    const getFindings = jest.fn((input: any) => ({
      Findings: [{ Id: `${window(input)}-${input.NextToken ?? 'first'}`, RecordState: 'ACTIVE' }],
      NextToken: `after-${input.NextToken ?? 'first'}`,
    }));
    const client = createMockClient({
      DescribeHubCommand: () => ({ SubscribedAt: '2025-01-01T00:00:00Z' }),
      GetEnabledStandardsCommand: () => ({ StandardsSubscriptions: [] }),
      GetFindingsCommand: getFindings,
    });

    const { nodes } = await collectSecurityHub(
      client as SecurityHubClient,
      ACCOUNT,
      'us-east-1',
      new Set()
    );

    // Medium and low fill their own window; critical and high keep all five pages.
    expect(getFindings).toHaveBeenCalledTimes(10);
    const findings = nodes.filter((n) => n.label === 'SecurityHubFinding');
    expect(findings.filter((n) => String(n.properties.id).startsWith('CRITICAL'))).toHaveLength(5);
    expect(findings.filter((n) => String(n.properties.id).startsWith('MEDIUM'))).toHaveLength(5);
    const hub = nodes.find((n) => n.label === 'SecurityHub');
    expect(hub?.properties.findings_truncated).toBe(true);
    expect(hub?.properties.other_findings_truncated).toBe(true);
  });

  it('emits the hub, active findings, HAS_FINDING edges, and DETECTS_ON for known resources', async () => {
    const resourceArn = `arn:aws:ec2:us-east-1:${ACCOUNT}:instance/i-1234567890abcdef0`;
    const client = createMockClient({
      DescribeHubCommand: () => ({ SubscribedAt: '2025-01-01T00:00:00Z' }),
      GetEnabledStandardsCommand: () => ({
        StandardsSubscriptions: [
          { StandardsArn: 'arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0' },
        ],
      }),
      GetFindingsCommand: (input: any) => ({
        Findings:
          input.Filters.SeverityLabel[0].Value !== 'CRITICAL'
            ? []
            : [
                {
                  Id: '11111111-2222-3333-4444-555555555555',
                  Title: 'Instance exposed to internet',
                  Severity: { Label: 'CRITICAL' },
                  RecordState: 'ACTIVE',
                  Workflow: { Status: 'NEW' },
                  Types: ['Software and Configuration Checks/Exposure'],
                  Resources: [{ Id: resourceArn, Type: 'AwsEc2Instance' }],
                  ProductArn: 'arn:aws:securityhub:::product/aws/securityhub',
                },
                {
                  Id: '99999999-8888-7777-6666-555555555555',
                  Title: 'Finding on an uncollected resource',
                  Severity: { Label: 'HIGH' },
                  RecordState: 'ACTIVE',
                  Resources: [
                    {
                      Id: 'arn:aws:ec2:us-east-1:123456789012:volume/vol-unknown',
                      Type: 'AwsEc2Volume',
                    },
                  ],
                },
              ],
      }),
    });

    const { nodes, edges } = await collectSecurityHub(
      client as SecurityHubClient,
      ACCOUNT,
      'us-east-1',
      new Set([resourceArn])
    );

    const hub = nodes.find((n) => n.label === 'SecurityHub');
    expect(hub?.properties).toMatchObject({
      enabled: true,
      subscribed_at: '2025-01-01T00:00:00Z',
      enabled_standards: ['arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0'],
      findings_truncated: false,
    });

    const finding = nodes.find((n) => n.label === 'SecurityHubFinding');
    expect(finding?.properties).toMatchObject({
      severity: 'CRITICAL',
      record_state: 'ACTIVE',
      workflow_state: 'NEW',
      resource_arn: resourceArn,
      resource_type: 'AwsEc2Instance',
    });

    expect(edges).toHaveLength(3);
    expect(edges).toContainEqual({
      from: `arn:aws:securityhub:us-east-1:${ACCOUNT}:hub/default`,
      to: `arn:aws:securityhub:us-east-1:${ACCOUNT}:finding/11111111-2222-3333-4444-555555555555`,
      label: 'HAS_FINDING',
    });
    expect(edges).toContainEqual({
      from: `arn:aws:securityhub:us-east-1:${ACCOUNT}:finding/11111111-2222-3333-4444-555555555555`,
      to: resourceArn,
      label: 'DETECTS_ON',
    });
    expect(edges).toContainEqual({
      from: `arn:aws:securityhub:us-east-1:${ACCOUNT}:hub/default`,
      to: `arn:aws:securityhub:us-east-1:${ACCOUNT}:finding/99999999-8888-7777-6666-555555555555`,
      label: 'HAS_FINDING',
    });
    expect(
      edges.filter((e) => e.to === 'arn:aws:ec2:us-east-1:123456789012:volume/vol-unknown')
    ).toHaveLength(0);
  });

  it('returns empty when Security Hub is not enabled', async () => {
    const client = createMockClient({
      DescribeHubCommand: () => {
        const error = new Error('not enabled');
        error.name = 'ResourceNotFoundException';
        throw error;
      },
    });

    const { nodes, edges } = await collectSecurityHub(
      client as SecurityHubClient,
      ACCOUNT,
      'us-east-1',
      new Set()
    );

    expect(nodes).toHaveLength(0);
    expect(edges).toHaveLength(0);
  });

  it('rethrows unexpected hub errors', async () => {
    const client = createMockClient({
      DescribeHubCommand: () => {
        throw new Error('ThrottlingException');
      },
    });

    await expect(
      collectSecurityHub(client as SecurityHubClient, ACCOUNT, 'us-east-1', new Set())
    ).rejects.toThrow('ThrottlingException');
  });
});

// GuardDuty findings move to the delegated administrator's detectors. Security
// Hub drops them only once that path is on, so there is never a window with
// neither.
describe('collectSecurityHub GuardDuty exclusion', () => {
  async function filtersFor(options?: { excludeGuardDuty?: boolean }) {
    const getFindings = jest.fn(() => ({ Findings: [] }));
    const client = createMockClient({
      DescribeHubCommand: () => ({ SubscribedAt: '2025-01-01T00:00:00Z' }),
      GetEnabledStandardsCommand: () => ({ StandardsSubscriptions: [] }),
      GetFindingsCommand: getFindings,
    });
    await collectSecurityHub(client as SecurityHubClient, ACCOUNT, 'us-west-2', new Set(), options);
    return (getFindings.mock.calls[0] as unknown as [{ Filters: Record<string, unknown> }])[0]
      .Filters;
  }

  it('keeps GuardDuty findings by default', async () => {
    expect((await filtersFor()).ProductName).toBeUndefined();
  });

  it('excludes GuardDuty findings when they come from the administrator', async () => {
    expect((await filtersFor({ excludeGuardDuty: true })).ProductName).toEqual([
      { Value: 'GuardDuty', Comparison: 'NOT_EQUALS' },
    ]);
  });

  it('asks only for active, untriaged critical or high findings, worst first', async () => {
    const filters = await filtersFor();
    expect(filters.SeverityLabel).toEqual([
      { Value: 'CRITICAL', Comparison: 'EQUALS' },
      { Value: 'HIGH', Comparison: 'EQUALS' },
    ]);
    expect(filters.WorkflowStatus).toEqual([
      { Value: 'NEW', Comparison: 'EQUALS' },
      { Value: 'NOTIFIED', Comparison: 'EQUALS' },
    ]);
    expect(filters.RecordState).toEqual([{ Value: 'ACTIVE', Comparison: 'EQUALS' }]);
  });

  it('asks for medium and low findings in a second request of their own', async () => {
    const getFindings = jest.fn(() => ({ Findings: [] }));
    const client = createMockClient({
      DescribeHubCommand: () => ({ SubscribedAt: '2025-01-01T00:00:00Z' }),
      GetEnabledStandardsCommand: () => ({ StandardsSubscriptions: [] }),
      GetFindingsCommand: getFindings,
    });
    await collectSecurityHub(client as SecurityHubClient, ACCOUNT, 'us-west-2', new Set());
    const second = (
      getFindings.mock.calls[1] as unknown as [{ Filters: Record<string, unknown> }]
    )[0].Filters;
    expect(second.SeverityLabel).toEqual([
      { Value: 'MEDIUM', Comparison: 'EQUALS' },
      { Value: 'LOW', Comparison: 'EQUALS' },
    ]);
    expect(second.WorkflowStatus).toEqual([
      { Value: 'NEW', Comparison: 'EQUALS' },
      { Value: 'NOTIFIED', Comparison: 'EQUALS' },
    ]);
  });
});
