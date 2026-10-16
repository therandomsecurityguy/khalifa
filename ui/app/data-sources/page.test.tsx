import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { getDataSources } from '@/lib/api';
import type { AccountCoverage, JobOutput } from '@/types';
import DataSourcesPage from './page';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getDataSources: jest.fn(),
}));

const mocked = getDataSources as jest.MockedFunction<typeof getDataSources>;
const recent = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();

const service = (name: string, extra: Partial<AccountCoverage['services'][number]> = {}) => ({
  service: name,
  region: 'us-west-2',
  status: 'SUCCEEDED',
  lastAttemptAt: recent,
  lastSuccessAt: recent,
  error: null,
  failureType: null,
  nodes: 10,
  ...extra,
});

const accounts: AccountCoverage[] = [
  {
    id: '111111111111',
    name: 'platform',
    resources: 500,
    prod: 120,
    collectedAt: recent,
    status: 'ok',
    services: [service('iam'), service('tags')],
    detection: { securityHub: 'truncated', guardDuty: 'on', config: 'on', accessAnalyzer: 'on' },
  },
  {
    id: '222222222222',
    name: 'research-dev',
    resources: 80,
    prod: 0,
    collectedAt: recent,
    status: 'failing',
    services: [
      service('iam'),
      service('tags', { status: 'FAILED', error: 'AccessDenied: tag:GetResources' }),
    ],
    detection: { securityHub: 'on', guardDuty: 'missing', config: 'on', accessAnalyzer: 'on' },
  },
];

const hoursAgo = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
const jobs: JobOutput[] = [
  {
    id: 'rule-runner',
    name: 'Rule runner',
    everyHours: 4,
    lastOutputAt: hoursAgo(1),
    produced: '767 open issues',
    quietWhenClean: false,
  },
  {
    id: 'policy-evaluator',
    name: 'Policy evaluator',
    everyHours: 24,
    lastOutputAt: hoursAgo(60),
    produced: '2,744 principals',
    quietWhenClean: false,
  },
  {
    id: 'dspm-scanner',
    name: 'DSPM scanner',
    everyHours: 24,
    lastOutputAt: null,
    produced: '0 classified resources',
    quietWhenClean: true,
  },
];

describe('DataSourcesPage', () => {
  beforeEach(() => mocked.mockReset().mockResolvedValue({ accounts, jobs }));

  it('summarises accounts and opens an account to its services', async () => {
    render(<DataSourcesPage />);

    expect(await screen.findByText('1 fully collected')).toBeInTheDocument();
    expect(screen.getByText('580', { selector: 'dd' })).toBeInTheDocument();
    expect(screen.getByText('120', { selector: 'dd' })).toBeInTheDocument();
    expect(screen.getByText('2h ago', { selector: 'dd' })).toBeInTheDocument();

    const table = screen.getByRole('table', { name: 'Accounts' });
    const rows = within(table).getAllByRole('row');
    // Failing accounts first.
    expect(rows[1]).toHaveTextContent('research-dev');
    expect(rows[1]).toHaveTextContent('tags failing');
    expect(rows[2]).toHaveTextContent('All 2 services');

    await userEvent.click(within(rows[1]).getByRole('button', { name: /research-dev/ }));
    expect(screen.getByText('AccessDenied: tag:GetResources')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Browse this account/ })).toHaveAttribute(
      'href',
      '/resources?label=*&property=account_id&value=222222222222'
    );
  });

  it('lists failures under Needs attention and jumps to the account', async () => {
    render(<DataSourcesPage />);
    const menu = await screen.findByRole('navigation', { name: 'Data source sections' });

    await userEvent.click(within(menu).getByRole('button', { name: /Needs attention/ }));
    expect(screen.getByText('Collection failing · 1')).toBeInTheDocument();
    expect(
      screen.getByText('Security Hub findings truncated in 1 of 2 accounts')
    ).toBeInTheDocument();
    expect(screen.getByText(/Policy evaluator has no recent output/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Open →' }));

    expect(screen.getByRole('table', { name: 'Accounts' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /research-dev/ })).toHaveAttribute(
      'aria-expanded',
      'true'
    );
  });

  it('shows each service with the accounts where it fails', async () => {
    render(<DataSourcesPage />);
    const menu = await screen.findByRole('navigation', { name: 'Data source sections' });
    await userEvent.click(within(menu).getByRole('button', { name: /Services/ }));

    const table = screen.getByRole('table', { name: 'Services' });
    expect(within(table).getByText('2 of 2 accounts')).toBeInTheDocument();
    expect(within(table).getByText('1 of 2 accounts')).toBeInTheDocument();
    await userEvent.click(within(table).getByRole('button', { name: 'tags' }));
    expect(within(table).getByText('research-dev')).toBeInTheDocument();
  });

  it('shows detection sources with the accounts where each is not on', async () => {
    render(<DataSourcesPage />);
    const menu = await screen.findByRole('navigation', { name: 'Data source sections' });
    await userEvent.click(within(menu).getByRole('button', { name: /Detection sources/ }));

    const table = screen.getByRole('table', { name: 'Detection sources' });
    expect(within(table).getByText('1 truncated')).toBeInTheDocument();
    expect(within(table).getByText('1 missing')).toBeInTheDocument();
    expect(within(table).getAllByText('On everywhere')).toHaveLength(2);
    await userEvent.click(within(table).getByRole('button', { name: 'GuardDuty' }));
    expect(within(table).getByText('research-dev')).toBeInTheDocument();
  });

  it('marks jobs on time, overdue, or quiet when they only write on findings', async () => {
    render(<DataSourcesPage />);
    const menu = await screen.findByRole('navigation', { name: 'Data source sections' });
    await userEvent.click(within(menu).getByRole('button', { name: /Analysis jobs/ }));

    const rows = within(screen.getByRole('table', { name: 'Analysis jobs' })).getAllByRole('row');
    expect(rows[1]).toHaveTextContent('Every 4h');
    expect(rows[1]).toHaveTextContent('On time');
    expect(rows[2]).toHaveTextContent('Overdue');
    expect(rows[3]).toHaveTextContent('No recent findings');
  });
});
