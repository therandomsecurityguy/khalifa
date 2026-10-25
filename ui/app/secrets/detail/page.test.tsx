import { fireEvent, render, screen, within } from '@testing-library/react';
import { getAccounts, getSecret } from '@/lib/api';
import type { SecretInventoryItem } from '@/types';
import SecretDetailPage from './page';

let search = '';
jest.mock('next/navigation', () => ({ useSearchParams: () => new URLSearchParams(search) }));
jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getAccounts: jest.fn(),
  getSecret: jest.fn(),
}));

const ARN = 'arn:aws:secretsmanager:us-west-2:111122223333:secret:prod/payments/key-Ab12';

const secret: SecretInventoryItem = {
  id: ARN,
  kind: 'secrets-manager',
  name: 'prod/payments/key',
  accountId: '111122223333',
  region: 'us-west-2',
  encryption: 'customer-managed',
  rotationEnabled: null,
  lastRotated: null,
  createdAt: '2025-09-06T00:00:00.000Z',
  lastAccessed: null,
  lastModified: null,
  collectionRestricted: false,
  env: 'prod',
  owner: 'payments',
  sharing: { scope: 'outside', accounts: 0 },
  issues: [
    {
      id: 'RULE-033-v2-b',
      ruleId: 'RULE-033',
      severity: 'low',
      title: 'Secret Shared with Another Collected Account',
      openedAt: '2026-10-10T00:00:00.000Z',
    },
    {
      id: 'RULE-010-v2-a',
      ruleId: 'RULE-010',
      severity: 'critical',
      title: 'Secret Shared Outside Collected Accounts by Its Resource Policy',
      openedAt: '2026-10-01T00:00:00.000Z',
    },
  ],
};

describe('SecretDetailPage', () => {
  beforeEach(() => {
    search = `arn=${encodeURIComponent(ARN)}`;
    (getAccounts as jest.Mock).mockResolvedValue({
      accounts: [{ id: '111122223333', name: 'payments-prod' }],
    });
    (getSecret as jest.Mock)
      .mockReset()
      .mockResolvedValue({ item: secret, issuesUnavailable: false, readers: null });
  });

  it('shows the secret, its facts, issues worst first and what to fix', async () => {
    render(<SecretDetailPage />);
    expect(await screen.findByRole('heading', { name: 'prod/payments/key' })).toBeInTheDocument();
    expect(getSecret).toHaveBeenCalledWith(ARN, expect.anything());
    expect(screen.getByText('payments-prod')).toBeInTheDocument();
    expect(screen.getByText('Off · never configured')).toBeInTheDocument();
    expect(screen.getByText('Customer managed key')).toBeInTheDocument();
    const links = screen.getAllByRole('link', { name: 'View issue →' });
    expect(links[0]).toHaveAttribute('href', '/issues/RULE-010-v2-a');
    expect(screen.queryByText(/RULE-0/)).toBeNull();
    expect(screen.getByText(/Remove the outside account/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Attack paths to this secret →' })).toHaveAttribute(
      'href',
      `/attack-paths?from=any&to=resource&toResource=${encodeURIComponent(ARN)}&hops=4`
    );
  });

  it('refuses a link that is not a secret ARN without calling the API', async () => {
    search = `arn=${encodeURIComponent('arn:aws:iam::111122223333:role/admin')}`;
    render(<SecretDetailPage />);
    expect(await screen.findByText(/does not name a Secrets Manager secret/)).toBeInTheDocument();
    expect(getSecret).not.toHaveBeenCalled();
  });

  it('marks a plain-text parameter as stored unencrypted and says how to fix it', async () => {
    (getSecret as jest.Mock).mockResolvedValue({
      item: {
        ...secret,
        id: 'arn:aws:ssm:us-west-2:111122223333:parameter/app/db-password',
        kind: 'ssm-plaintext',
        name: '/app/db-password',
        encryption: 'none',
        sharing: null,
        issues: [],
      },
      issuesUnavailable: false,
      readers: null,
    });
    search = `arn=${encodeURIComponent('arn:aws:ssm:us-west-2:111122223333:parameter/app/db-password')}`;
    render(<SecretDetailPage />);
    expect(await screen.findByText('Stored unencrypted')).toBeInTheDocument();
    expect(screen.getByText('None: plain-text String parameter')).toBeInTheDocument();
    expect(screen.getByText(/Move this value to a SecureString parameter/)).toBeInTheDocument();
  });

  it('lists who can read it, broadest first, and filters to broad grants', async () => {
    (getSecret as jest.Mock).mockResolvedValue({
      item: secret,
      issuesUnavailable: false,
      readers: {
        truncated: false,
        unavailable: false,
        items: [
          {
            id: 'arn:aws:iam::111122223333:role/AWSReservedSSO_PowerUser',
            name: 'AWSReservedSSO_PowerUser',
            type: 'role',
            admin: false,
            mayBeDenied: false,
            grants: [
              {
                policyName: 'PowerUserAccess',
                policyKind: 'aws-managed',
                scope: 'all',
                notAction: true,
                conditional: false,
              },
            ],
          },
          {
            id: 'arn:aws:iam::111122223333:role/payments-api',
            name: 'payments-api',
            type: 'role',
            admin: false,
            mayBeDenied: true,
            grants: [
              {
                policyName: 'payments-read',
                policyKind: 'inline',
                scope: 'secret',
                notAction: false,
                conditional: true,
              },
            ],
          },
        ],
      },
    });
    render(<SecretDetailPage />);
    const table = await screen.findByRole('table', { name: 'Who can read it' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('AWSReservedSSO_PowerUser');
    expect(within(rows[0]).getByText('All resources')).toBeInTheDocument();
    expect(within(rows[0]).getByText('All actions but listed')).toBeInTheDocument();
    expect(within(rows[1]).getByText('May be denied')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Conditional')).toBeInTheDocument();
    expect(within(rows[0]).getByRole('link', { name: 'AWSReservedSSO_PowerUser' })).toHaveAttribute(
      'href',
      '/resources?arn=' +
        encodeURIComponent('arn:aws:iam::111122223333:role/AWSReservedSSO_PowerUser')
    );

    fireEvent.click(screen.getByRole('button', { name: 'Broad only (1)' }));
    expect(within(table).getAllByRole('row')).toHaveLength(2);
  });

  it('says when readers could not be worked out', async () => {
    (getSecret as jest.Mock).mockResolvedValue({
      item: secret,
      issuesUnavailable: false,
      readers: { items: [], truncated: false, unavailable: true },
    });
    render(<SecretDetailPage />);
    expect(await screen.findByText(/Readers could not be worked out/)).toBeInTheDocument();
  });

  it('scrolls to the readers card when the link asked for it', async () => {
    const scrollIntoView = jest.fn();
    Element.prototype.scrollIntoView = scrollIntoView;
    window.history.replaceState(null, '', '/secrets/detail#readers');
    (getSecret as jest.Mock).mockResolvedValue({
      item: secret,
      issuesUnavailable: false,
      readers: { items: [], truncated: false, unavailable: false },
    });
    render(<SecretDetailPage />);
    expect(await screen.findByText(/No role, user or group in this account/)).toBeInTheDocument();
    expect(scrollIntoView).toHaveBeenCalled();
    window.history.replaceState(null, '', '/');
  });
});
