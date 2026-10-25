import { fireEvent, render, screen, within } from '@testing-library/react';
import { getAccounts, getSecretReaderCounts, getSecrets } from '@/lib/api';
import type { SecretInventoryItem } from '@/types';
import SecretsPage from './page';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getAccounts: jest.fn(),
  getSecrets: jest.fn(),
  getSecretReaderCounts: jest.fn(),
}));

function item(overrides: Partial<SecretInventoryItem>): SecretInventoryItem {
  return {
    id: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:x',
    kind: 'secrets-manager',
    name: 'x',
    accountId: '111122223333',
    region: 'us-west-2',
    encryption: 'aws-managed',
    rotationEnabled: true,
    lastRotated: new Date().toISOString(),
    createdAt: null,
    lastAccessed: null,
    lastModified: null,
    collectionRestricted: false,
    env: null,
    owner: null,
    sharing: { scope: 'account', accounts: 0 },
    issues: [],
    ...overrides,
  };
}

const issue = (id: string, severity: 'critical' | 'high' | 'low') => ({
  id,
  ruleId: 'RULE-010',
  severity,
  title: 'Shared outside',
  openedAt: '2026-10-01T00:00:00.000Z',
});

const shared = item({
  id: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:prod/prism/falco/kafka',
  name: 'prod/prism/falco/kafka',
  rotationEnabled: null,
  lastRotated: null,
  encryption: 'customer-managed',
  sharing: { scope: 'outside', accounts: 0 },
  issues: [issue('a', 'critical'), issue('b', 'high'), issue('c', 'high')],
});
const rotated = item({
  id: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:prod/db',
  name: 'prod/db',
});
const parameter = item({
  id: 'arn:aws:ssm:us-west-2:111122223333:parameter/db/password',
  kind: 'ssm-parameter',
  name: '/db/password',
  rotationEnabled: null,
  lastRotated: null,
  sharing: null,
});

const plaintext = item({
  id: 'arn:aws:ssm:us-west-2:111122223333:parameter/app/db-password',
  kind: 'ssm-plaintext',
  name: '/app/db-password',
  encryption: 'none',
  rotationEnabled: null,
  lastRotated: null,
  sharing: null,
  env: 'prod',
  owner: 'data-platform',
});

function load(items: SecretInventoryItem[], issuesUnavailable = false) {
  (getSecrets as jest.Mock).mockResolvedValue({ items, truncated: false, issuesUnavailable });
}

describe('SecretsPage', () => {
  beforeEach(() => {
    (getAccounts as jest.Mock).mockResolvedValue({
      accounts: [{ id: '111122223333', name: 'payments-prod' }],
    });
    load([rotated, parameter, shared]);
    (getSecretReaderCounts as jest.Mock).mockResolvedValue({
      counts: {},
      unavailableAccounts: 0,
      partialAccounts: 0,
      truncated: false,
    });
  });

  it('links each secret to its page and shows issues as severity counts', async () => {
    render(<SecretsPage />);
    const table = await screen.findByRole('table', { name: 'Secrets' });
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows[0]).toHaveTextContent('prod/prism/falco/kafka');
    expect(
      within(rows[0]).getByRole('link', { name: /prod\/prism\/falco\/kafka/ })
    ).toHaveAttribute('href', `/secrets/detail?arn=${encodeURIComponent(shared.id)}`);
    expect(
      within(rows[0]).getByRole('img', { name: '1 critical, 2 high open issues' })
    ).toBeInTheDocument();
    expect(within(rows[0]).queryByText(/RULE-010/)).toBeNull();
    expect(within(rows[0]).getByText('Off')).toBeInTheDocument();
    expect(within(rows[0]).queryByText('Never configured')).toBeNull();
    expect(within(table).queryByRole('columnheader', { name: /Encryption/ })).toBeNull();
  });

  it('summarises by type and filters from a risk row, clearing on a second click', async () => {
    render(<SecretsPage />);
    const summary = await screen.findByRole('group', { name: 'Filter secrets' });
    expect(within(summary).getByRole('button', { name: /All secrets/ })).toHaveTextContent('3');
    const off = within(summary).getByRole('button', { name: /Rotation off/ });
    expect(off).toHaveTextContent('1');
    fireEvent.click(off);
    expect(off).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getByText('Showing 1 of 1 secret')).toBeInTheDocument();
    fireEvent.click(off);
    expect(screen.getByText('Showing 3 of 3 secrets')).toBeInTheDocument();
  });

  it('shows a dash for the date-based counts until the collector records dates', async () => {
    render(<SecretsPage />);
    expect(await screen.findByText(/fill in after the next collection run/)).toBeInTheDocument();
    const stale = screen.getByRole('button', { name: /Not rotated in 90\+ days/ });
    expect(stale).toBeDisabled();
    expect(stale).toHaveTextContent('—');
  });

  it('filters by a column funnel and shows the filter as a removable chip', async () => {
    render(<SecretsPage />);
    fireEvent.click(await screen.findByRole('button', { name: 'Filter Shared with' }));
    fireEvent.click(screen.getByRole('checkbox', { name: /Outside the org/ }));
    expect(screen.getByText('Showing 1 of 1 secret')).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole('button', { name: 'Remove filter: Shared with: Outside the org' })
    );
    expect(screen.getByText('Showing 3 of 3 secrets')).toBeInTheDocument();
  });

  it('searches by name', async () => {
    render(<SecretsPage />);
    fireEvent.change(await screen.findByLabelText('Search'), { target: { value: 'DB' } });
    expect(screen.getByText('Showing 2 of 2 secrets')).toBeInTheDocument();
  });

  it('warns when issues could not be loaded', async () => {
    load([rotated], true);
    render(<SecretsPage />);
    expect(await screen.findByText(/Open issues could not be loaded/)).toBeInTheDocument();
  });

  it('shows plain-text parameters with their own summary row, and finds secrets by owner', async () => {
    load([rotated, plaintext]);
    render(<SecretsPage />);
    const table = await screen.findByRole('table', { name: 'Secrets' });
    const row = within(table).getByRole('link', { name: '/app/db-password' }).closest('tr')!;
    expect(within(row).getByText('Plain text')).toBeInTheDocument();
    expect(within(row).getByText('SSM String')).toBeInTheDocument();
    expect(within(row).queryByText('SSM String (plain text)')).toBeNull();
    expect(within(table).queryByRole('columnheader', { name: /Env|Owner/ })).toBeNull();

    const unencrypted = screen.getByRole('button', { name: /Possibly unencrypted secrets/ });
    expect(unencrypted).toHaveTextContent('1');
    fireEvent.click(unencrypted);
    expect(screen.getByText('Showing 1 of 1 secret')).toBeInTheDocument();
    fireEvent.click(unencrypted);

    fireEvent.change(screen.getByLabelText('Search'), { target: { value: 'data-platform' } });
    expect(screen.getByText('Showing 1 of 1 secret')).toBeInTheDocument();
    expect(within(table).getByRole('link', { name: '/app/db-password' })).toBeInTheDocument();
  });

  it('filters by account and region next to search, and searches owners', async () => {
    const east = item({
      id: 'arn:aws:secretsmanager:us-east-1:444455556666:secret:east',
      name: 'east',
      accountId: '444455556666',
      region: 'us-east-1',
      owner: 'growth',
    });
    load([rotated, east]);
    render(<SecretsPage />);
    const table = await screen.findByRole('table', { name: 'Secrets' });
    expect(within(table).queryByRole('button', { name: 'Filter Account' })).toBeNull();

    fireEvent.change(screen.getByLabelText('Region'), { target: { value: 'us-east-1' } });
    expect(screen.getByText('Showing 1 of 1 secret')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Region'), { target: { value: '' } });

    fireEvent.change(screen.getByLabelText('Account'), { target: { value: '111122223333' } });
    expect(within(table).queryByRole('link', { name: 'east' })).toBeNull();
    fireEvent.change(screen.getByLabelText('Account'), { target: { value: '' } });

    fireEvent.change(screen.getByLabelText('Search'), { target: { value: 'growth' } });
    expect(screen.getByText('Showing 1 of 1 secret')).toBeInTheDocument();
  });

  it('shows how many can read each secret, linked to its readers, with a funnel', async () => {
    (getSecretReaderCounts as jest.Mock).mockResolvedValue({
      counts: {
        [shared.id]: { total: 24, broad: 6, partial: false },
        [rotated.id]: { total: 2, broad: 0, partial: false },
      },
      unavailableAccounts: 1,
      partialAccounts: 0,
      truncated: false,
    });
    render(<SecretsPage />);
    const link = await screen.findByRole('link', {
      name: '24 principals can read prod/prism/falco/kafka, 6 broadly',
    });
    expect(link).toHaveAttribute(
      'href',
      `/secrets/detail?arn=${encodeURIComponent(shared.id)}#readers`
    );
    expect(link).toHaveTextContent('6 broad');
    expect(screen.getByText(/Readers could not be counted for 1 account/)).toBeInTheDocument();

    expect(screen.queryByRole('button', { name: /Readable by 20\+ principals/ })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Filter Readable by' }));
    fireEvent.click(screen.getByRole('checkbox', { name: /1–5/ }));
    expect(screen.getByText('Showing 1 of 1 secret')).toBeInTheDocument();
  });

  it('shows the table before reader counts arrive, with the count pending', async () => {
    (getSecretReaderCounts as jest.Mock).mockReturnValue(new Promise(() => {}));
    render(<SecretsPage />);
    const table = await screen.findByRole('table', { name: 'Secrets' });
    expect(within(table).getAllByText('…').length).toBeGreaterThan(0);
  });

  it('marks counts from a partly read account as a minimum on the row', async () => {
    (getSecretReaderCounts as jest.Mock).mockResolvedValue({
      counts: { [shared.id]: { total: 24, broad: 6, partial: true } },
      unavailableAccounts: 0,
      partialAccounts: 1,
      truncated: false,
    });
    render(<SecretsPage />);
    const link = await screen.findByRole('link', {
      name: 'At least 24 principals can read prod/prism/falco/kafka, 6 broadly',
    });
    expect(link).toHaveTextContent('≥24');
    expect(link).toHaveAttribute('title', 'At least this many: not every policy was read');
    expect(screen.queryByText(/more policies than one count reads/)).toBeNull();
  });

  it('shows 30 secrets a page, steps through pages, and starts over on a new filter', async () => {
    const many = Array.from({ length: 65 }, (_, i) =>
      item({
        id: `arn:aws:secretsmanager:us-west-2:111122223333:secret:s${String(i).padStart(2, '0')}`,
        name: `s${String(i).padStart(2, '0')}`,
      })
    );
    load(many);
    render(<SecretsPage />);
    expect(await screen.findByText('Showing 1–30 of 65 secrets')).toBeInTheDocument();
    expect(screen.getByText('Page 1 of 3')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();

    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('Showing 31–60 of 65 secrets')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 's30' })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByText('Showing 61–65 of 65 secrets')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Search'), { target: { value: 's0' } });
    expect(screen.getByText('Showing 10 of 10 secrets')).toBeInTheDocument();
    expect(screen.queryByText(/Page \d of/)).toBeNull();
  });

  it('shows when each secret was created, before its rotation, and a dash when unknown', async () => {
    const created = new Date(Date.now() - 412 * 86_400_000).toISOString();
    load([
      item({ name: 'aged', createdAt: created, rotationEnabled: null, lastRotated: null }),
      parameter,
    ]);
    render(<SecretsPage />);
    const table = await screen.findByRole('table', { name: 'Secrets' });
    const headers = within(table)
      .getAllByRole('columnheader')
      .map((th) => th.textContent ?? '');
    expect(headers.findIndex((h) => h.startsWith('Created'))).toBe(
      headers.findIndex((h) => h.startsWith('Rotation')) - 1
    );
    const aged = within(table).getByRole('link', { name: 'aged' }).closest('tr')!;
    expect(within(aged).getByText('412 days ago')).toBeInTheDocument();
    expect(within(aged).getByText('Off')).toBeInTheDocument();
    expect(within(aged).queryByText('Never configured')).toBeNull();
    const param = within(table).getByRole('link', { name: '/db/password' }).closest('tr')!;
    expect(within(param).getAllByText('—').length).toBeGreaterThan(0);
  });

  it('notes a secret whose rotation is on but has never run', async () => {
    load([item({ name: 'failing', rotationEnabled: true, lastRotated: null })]);
    render(<SecretsPage />);
    const table = await screen.findByRole('table', { name: 'Secrets' });
    const row = within(table).getByRole('link', { name: 'failing' }).closest('tr')!;
    expect(within(row).getByText('On')).toBeInTheDocument();
    expect(within(row).getByText('Never rotated')).toBeInTheDocument();
  });
});
