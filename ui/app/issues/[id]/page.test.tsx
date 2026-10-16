import { render, screen, within } from '@testing-library/react';
import { getAccounts, getIssue, getRule, getSession } from '@/lib/api';
import type { IssueDetail } from '@/types';
import IssuePage from './page';

jest.mock('next/navigation', () => ({ useParams: () => ({ id: 'RULE-013-v2-abc' }) }));
jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getAccounts: jest.fn(),
  getIssue: jest.fn(),
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
});
