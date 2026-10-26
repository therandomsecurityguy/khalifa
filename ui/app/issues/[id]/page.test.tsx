import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { getAccounts, getIssue, getPathSimulation, getRule, getSession } from '@/lib/api';
import type { IssueDetail } from '@/types';
import IssuePage from './page';

jest.mock('next/navigation', () => ({ useParams: () => ({ id: 'RULE-013-v2-abc' }) }));
jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getAccounts: jest.fn(),
  getIssue: jest.fn(),
  getPathSimulation: jest.fn(),
  getRule: jest.fn(),
  getSession: jest.fn(),
}));

const mockedIssue = getIssue as jest.MockedFunction<typeof getIssue>;

const user = 'arn:aws:iam::111122223333:user/ci-deployer';
const key = 'arn:aws:iam::111122223333:user/ci-deployer/access-key/AKIAX3L7Q';

function detail(overrides: Partial<IssueDetail> = {}): IssueDetail {
  return {
    id: 'RULE-013-v2-abc',
    ruleId: 'RULE-013',
    resourcesInvolved: [
      {
        resourceId: user,
        resourceType: 'IamUser',
        resourceName: 'ci-deployer',
        accountId: '111122223333',
      },
      {
        resourceId: key,
        resourceType: 'AccessKey',
        resourceName: 'AKIAX3L7Q',
        accountId: '111122223333',
        region: 'us-east-1',
      },
    ],
    pathSummary: [{ from: user, to: key, edgeType: 'HAS_ACCESS_KEY' }],
    riskScore: 62.4,
    severity: 'high',
    status: 'open',
    createdAt: '2026-10-03T01:30:00.000Z',
    updatedAt: '2026-10-06T04:10:00.000Z',
    owningTeam: 'iam-security',
    remediationHint: 'Rotate the key.',
    metadata: { ruleName: 'Old key', lastRefreshedAt: '2026-10-06T04:10:00.000Z' },
    attackPath: {
      nodes: [
        { id: user, label: 'IamUser', properties: { name: 'ci-deployer', mfa_enabled: false } },
        {
          id: key,
          label: 'AccessKey',
          properties: {
            status: 'Active',
            key_age_days: 131,
            created_date: '2026-05-28T12:00:00.000Z',
          },
        },
      ],
      edges: [{ id: 'e', label: 'HAS_ACCESS_KEY', from: user, to: key }],
    },
    ...overrides,
  };
}

describe('IssuePage involved resources', () => {
  beforeEach(() => {
    (getAccounts as jest.Mock).mockResolvedValue({
      accounts: [{ id: '111122223333', name: 'analytics - test' }],
    });
    (getRule as jest.Mock).mockResolvedValue({
      id: 'RULE-013',
      name: 'IAM User with Active Access Key Older Than 90 Days',
      description: 'Old keys.',
      severityHint: 'high',
      ownerTeam: 'iam-security',
      enabled: true,
    });
    (getSession as jest.Mock).mockResolvedValue({
      email: 'viewer@example.com',
      role: 'Viewer',
      canManageIssues: false,
    });
    mockedIssue.mockReset().mockResolvedValue(detail());
  });

  it('shows each resource with the facts that made it match, by account name', async () => {
    render(<IssuePage />);
    const card = (await screen.findByText('Involved resources')).closest('section')!;

    expect(within(card).getByText(/Values are from the latest collection, /)).toBeInTheDocument();
    expect(within(card).getAllByText(/analytics - test/)).toHaveLength(2);
    expect(within(card).getByText('analytics - test · us-east-1')).toBeInTheDocument();
    expect(within(card).getByText('Age')).toBeInTheDocument();
    const age = within(card).getByText('131 days');
    expect(age.className).toContain('text-red-800');
    expect(within(card).queryByText(/^rule:/)).not.toBeInTheDocument();
    expect(within(card).getByText('May 28, 2026')).toBeInTheDocument();
    expect(within(card).getByText('MFA')).toBeInTheDocument();
    expect(within(card).getByText('no').className).not.toContain('text-red-800');
  });

  it('says when a matched resource is no longer in the graph', async () => {
    const base = detail();
    mockedIssue.mockResolvedValue(
      detail({
        attackPath: {
          ...base.attackPath,
          nodes: [
            base.attackPath.nodes[0],
            { id: key, label: 'Missing', properties: { name: 'AKIAX3L7Q', missing: true } },
          ],
        },
      })
    );
    render(<IssuePage />);
    const card = (await screen.findByText('Involved resources')).closest('section')!;

    expect(within(card).getByText(/No longer in the graph/)).toBeInTheDocument();
    expect(within(card).queryByText('Age')).not.toBeInTheDocument();
  });

  it('shows the facts for involved resources off the drawn path', async () => {
    const other = 'arn:aws:iam::111122223333:user/ci-deployer/access-key/AKIAOTHER';
    const base = detail();
    mockedIssue.mockResolvedValue(
      detail({
        resourcesInvolved: [
          ...base.resourcesInvolved,
          { resourceId: other, resourceType: 'AccessKey', resourceName: 'AKIAOTHER' },
        ],
        involvedResources: [
          {
            id: other,
            label: 'AccessKey',
            properties: { status: 'Active', key_age_days: 412 },
          },
        ],
      })
    );
    render(<IssuePage />);
    const card = (await screen.findByText('Involved resources')).closest('section')!;

    expect(within(card).getByText('412 days')).toBeInTheDocument();
    expect(within(card).getByText('131 days')).toBeInTheDocument();
  });

  it('lists several findings on one resource under it, grouped by package', async () => {
    const instance = 'arn:aws:ec2:us-west-2:111122223333:instance/i-1';
    const inspector = 'arn:aws:securityhub:us-west-2::product/aws/inspector';
    const findingIds = ['f1', 'f2', 'f3'].map(
      (id) => `arn:aws:securityhub:us-west-2:111122223333:finding/${id}`
    );
    const titles = [
      'CVE-2026-1 - linux-image-aws',
      'CVE-2026-2 - linux-image-aws',
      'CVE-2026-3 - openssl',
    ];
    mockedIssue.mockResolvedValue(
      detail({
        ruleId: 'RULE-018',
        resourcesInvolved: [
          { resourceId: instance, resourceType: 'Ec2Instance', accountId: '111122223333' },
          ...findingIds.map((resourceId) => ({ resourceId, resourceType: 'SecurityHubFinding' })),
        ],
        pathSummary: [{ from: findingIds[0], to: instance, edgeType: 'DETECTS_ON' }],
        attackPath: {
          nodes: [
            {
              id: findingIds[0],
              label: 'SecurityHubFinding',
              properties: { title: titles[0], severity: 'CRITICAL', product_arn: inspector },
            },
            { id: instance, label: 'Ec2Instance', properties: { state: 'running' } },
          ],
          edges: [],
        },
        involvedResources: findingIds.slice(1).map((id, i) => ({
          id,
          label: 'SecurityHubFinding',
          properties: { title: titles[i + 1], severity: 'HIGH', product_arn: inspector },
        })),
      })
    );
    render(<IssuePage />);
    const card = (await screen.findByText('Involved resources')).closest('section')!;

    expect(within(card).getByText('3 Security Hub findings on this resource')).toBeInTheDocument();
    expect(within(card).getByText('linux-image-aws')).toBeInTheDocument();
    expect(within(card).getByText('openssl')).toBeInTheDocument();
    expect(within(card).getByText('CVE-2026-1')).toBeInTheDocument();
    expect(within(card).queryByText(findingIds[1])).not.toBeInTheDocument();
    expect(within(card).getAllByRole('listitem')[0]).toHaveTextContent('openssl');
  });
});

describe('IssuePage fix simulation', () => {
  beforeEach(() => {
    (getAccounts as jest.Mock).mockResolvedValue({ accounts: [] });
    (getRule as jest.Mock).mockResolvedValue({
      id: 'RULE-013',
      name: 'IAM User with Active Access Key Older Than 90 Days',
      description: 'Old keys.',
      severityHint: 'high',
      ownerTeam: 'iam-security',
    });
    (getSession as jest.Mock).mockResolvedValue({
      email: 'viewer@example.com',
      role: 'viewer',
    });
    mockedIssue.mockReset().mockResolvedValue(detail());
    (getPathSimulation as jest.Mock).mockReset();
  });

  it('ranks the fixes by how many matched paths each one clears', async () => {
    (getPathSimulation as jest.Mock).mockResolvedValue({
      ruleId: 'RULE-013',
      ruleName: 'IAM User with Active Access Key Older Than 90 Days',
      totalPaths: 3,
      truncated: false,
      edges: [
        {
          id: 'e1',
          label: 'HAS_ACCESS_KEY',
          from: user,
          to: key,
          pathsUsing: 3,
          remainingPaths: 0,
          worstLikelihood: 0.42,
        },
        {
          id: 'e2',
          label: 'ATTACHED_TO',
          from: user,
          to: 'arn:aws:iam::111122223333:policy/reader',
          pathsUsing: 1,
          remainingPaths: 2,
          worstLikelihood: 0.2,
        },
      ],
    });

    render(<IssuePage />);
    const card = (await screen.findByText('What removes these paths')).closest('section')!;
    await userEvent.click(within(card).getByRole('button', { name: 'Simulate fixes' }));

    expect(getPathSimulation).toHaveBeenCalledWith('RULE-013');
    expect(
      await within(card).findByText(/clears 3 of 3 matched paths · worst likelihood 42%/)
    ).toBeInTheDocument();
    expect(
      within(card).getByText(/clears 1 of 3 matched paths · worst likelihood 20%/)
    ).toBeInTheDocument();
    expect(within(card).getAllByRole('listitem')[0]).toHaveTextContent('HAS_ACCESS_KEY');
  });

  it('says when no single edge clears a matched path', async () => {
    (getPathSimulation as jest.Mock).mockResolvedValue({
      ruleId: 'RULE-013',
      ruleName: 'IAM User with Active Access Key Older Than 90 Days',
      totalPaths: 0,
      truncated: false,
      edges: [],
    });

    render(<IssuePage />);
    const card = (await screen.findByText('What removes these paths')).closest('section')!;
    await userEvent.click(within(card).getByRole('button', { name: 'Simulate fixes' }));

    expect(
      await within(card).findByText('No single edge clears a matched path.')
    ).toBeInTheDocument();
  });

  it('lists the threat-intel matches recorded on the issue', async () => {
    mockedIssue.mockResolvedValue(
      detail({
        metadata: {
          ...detail().metadata,
          threatIntelMatches: [{ type: 'ip', value: '203.0.113.7', source: 's3://lists/ips.txt' }],
        },
      })
    );

    render(<IssuePage />);

    const card = (await screen.findByText('Threat intelligence')).closest('section')!;
    expect(within(card).getByText('203.0.113.7')).toBeInTheDocument();
    expect(within(card).getByText(/ip · s3:\/\/lists\/ips.txt/)).toBeInTheDocument();
  });

  it('shows no threat-intel card without a match', async () => {
    render(<IssuePage />);
    expect(await screen.findByText('Involved resources')).toBeInTheDocument();
    expect(screen.queryByText('Threat intelligence')).not.toBeInTheDocument();
  });
});
