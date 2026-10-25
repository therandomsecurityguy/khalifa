import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ApiError, getIssueSummary, getIssues, listRules } from '@/lib/api';
import type { Issue, SeverityStatusCounts } from '@/types';
import IssuesPage from './page';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getAccounts: jest.fn().mockResolvedValue({ accounts: [] }),
  getIssues: jest.fn(),
  getIssueSummary: jest.fn(),
  listRules: jest.fn(),
}));

const mockedIssues = getIssues as jest.MockedFunction<typeof getIssues>;
const mockedSummary = getIssueSummary as jest.MockedFunction<typeof getIssueSummary>;

function summary(
  cells: Partial<Record<string, [number, number, number]>> = {}
): SeverityStatusCounts {
  const row = (key: string) => {
    const [open, suppressed, resolved] = cells[key] ?? [0, 0, 0];
    return { open, suppressed, resolved };
  };
  return { critical: row('critical'), high: row('high'), medium: row('medium'), low: row('low') };
}
const mockedRules = listRules as jest.MockedFunction<typeof listRules>;

function rule(id: string, ownerTeam: string) {
  return { id, name: id, description: '', severityHint: 'high' as const, ownerTeam, enabled: true };
}

function issue(id: string, severity: Issue['severity']): Issue {
  return {
    id,
    ruleId: `RULE-${id}`,
    resourcesInvolved: [{ resourceId: `arn:aws:s3:::${id}`, resourceType: 'S3Bucket' }],
    pathSummary: [],
    riskScore: 42,
    severity,
    status: 'open',
    createdAt: '2026-09-18T00:00:00Z',
    updatedAt: '2026-09-18T00:00:00Z',
    owningTeam: 'cloud-security',
    remediationHint: 'Fix it',
    metadata: { ruleName: `Title ${id}` },
  };
}

function list(items: Issue[]) {
  return { items, totalCount: items.length };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe('IssuesPage', () => {
  beforeEach(() => {
    mockedIssues.mockReset();
    mockedSummary.mockReset().mockResolvedValue(summary());
    mockedRules.mockReset().mockResolvedValue({
      rules: [
        rule('RULE-001', 'cloud-security'),
        rule('RULE-013', 'iam-security'),
        rule('RULE-014', 'iam-security'),
      ],
    });
  });

  it('shows the list even when the summary fails', async () => {
    mockedIssues.mockResolvedValue(list([issue('a', 'high')]));
    mockedSummary.mockRejectedValue(new ApiError(500, 'summary exploded'));
    render(<IssuesPage />);

    expect(await screen.findByRole('cell', { name: /RULE-a/ })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong');
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
  });

  it('distinguishes filtered-out results from an empty backlog', async () => {
    mockedIssues.mockResolvedValue(list([]));
    render(<IssuesPage />);

    expect(await screen.findByText('No issues match the current filters')).toBeInTheDocument();
    expect(screen.getByText('Active filters: Status open')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(await screen.findByText('No issues recorded')).toBeInTheDocument();
    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: [], team: [] }),
      expect.anything()
    );
  });

  it('drops a stale response when the filter changed before it arrived', async () => {
    const slow = deferred<ReturnType<typeof list>>();
    mockedIssues
      .mockReturnValueOnce(slow.promise)
      .mockResolvedValueOnce(list([issue('crit', 'critical')]));
    render(<IssuesPage />);

    const statuses = await screen.findByRole('group', { name: 'Status' });
    await userEvent.click(within(statuses).getByRole('button', { name: /^Resolved/ }));
    expect(await screen.findByRole('cell', { name: /RULE-crit/ })).toBeInTheDocument();

    await act(async () => slow.resolve(list([issue('stale', 'low')])));
    const table = screen.getByRole('table');
    expect(within(table).queryByRole('cell', { name: /RULE-stale/ })).not.toBeInTheDocument();
    expect(within(table).getByRole('cell', { name: /RULE-crit/ })).toBeInTheDocument();
  });

  it('filters by several teams from the column funnel, listing each team once', async () => {
    mockedIssues.mockResolvedValue(list([issue('a', 'high')]));
    render(<IssuesPage />);
    await screen.findByRole('cell', { name: /RULE-a/ });

    await userEvent.click(screen.getByRole('button', { name: 'Filter Team' }));
    const panel = screen.getByRole('group', { name: 'Team filter' });
    expect(
      within(panel)
        .getAllByRole('checkbox')
        .map((box) => box.parentElement?.textContent)
    ).toEqual(['cloud-security', 'iam-security']);
    await userEvent.click(within(panel).getByRole('checkbox', { name: 'cloud-security' }));
    await userEvent.click(within(panel).getByRole('checkbox', { name: 'iam-security' }));

    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ team: ['cloud-security', 'iam-security'], status: ['open'] }),
      expect.anything()
    );
    expect(screen.getByRole('button', { name: 'Filter Team' })).toHaveTextContent('2');
  });

  it('puts the resource name, then its type, then its account on separate lines', async () => {
    const key = issue('k', 'high');
    key.resourcesInvolved = [
      {
        resourceId: 'arn:aws:iam::111122223333:user/ci/AKIAEXAMPLE',
        resourceType: 'AccessKey',
        resourceName: 'AKIAEXAMPLE',
      },
    ];
    mockedIssues.mockResolvedValue(list([key]));
    render(<IssuesPage />);

    const name = await screen.findByText('AKIAEXAMPLE', { selector: 'div' });
    const type = name.nextElementSibling as HTMLElement;
    expect(type).toHaveTextContent(/^Access key$/);
    expect(type.nextElementSibling).toHaveTextContent(/^111122223333$/);
  });

  it('keeps the column funnels reachable when a filter matches nothing', async () => {
    mockedIssues.mockResolvedValue(list([]));
    render(<IssuesPage />);

    expect(await screen.findByText('No issues match the current filters')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Filter Team' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Filter Status' })).not.toBeInTheDocument();
  });

  it('shows the rule with its name, the resource apart, and filters by several rules', async () => {
    mockedIssues.mockResolvedValue(list([issue('a', 'high')]));
    render(<IssuesPage />);

    const rule = await screen.findByRole('cell', { name: 'RULE-a Title a' });
    const row = rule.closest('tr') as HTMLElement;
    const resource = within(row).getByText('a', { selector: 'div' });
    expect(resource.nextElementSibling).toHaveTextContent(/^S3 bucket$/);
    expect(screen.getByRole('columnheader', { name: 'Resources' })).toBeInTheDocument();
    expect(screen.queryByRole('columnheader', { name: 'Issue' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Filter Rule' }));
    const panel = screen.getByRole('group', { name: 'Rule filter' });
    await userEvent.click(within(panel).getByRole('checkbox', { name: 'RULE-001' }));
    await userEvent.click(within(panel).getByRole('checkbox', { name: 'RULE-013' }));

    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ ruleId: ['RULE-001', 'RULE-013'] }),
      expect.anything()
    );
  });

  it('shows totals by status and recounts severities for the selected status', async () => {
    mockedSummary.mockResolvedValue(
      summary({ critical: [2, 0, 1], high: [4, 1, 1], medium: [4, 2, 2], low: [2, 0, 2] })
    );
    mockedIssues.mockResolvedValue(list([issue('a', 'high')]));
    render(<IssuesPage />);

    const heading = await screen.findByText('Actionable issues');
    expect(heading.nextElementSibling).toHaveTextContent('12 / 21');
    const statuses = screen.getByRole('group', { name: 'Status' });
    expect(within(statuses).getByRole('button', { name: /^Open/ })).toHaveTextContent('Open12');
    expect(within(statuses).getByRole('button', { name: /^Suppressed/ })).toHaveTextContent('3');
    expect(within(statuses).getByRole('button', { name: /^Resolved/ })).toHaveTextContent('6');

    const severities = screen.getByRole('group', { name: 'Severity' });
    expect(within(severities).getByRole('button', { name: /^High/ })).toHaveTextContent('High4');

    await userEvent.click(within(statuses).getByRole('button', { name: /^Resolved/ }));
    expect(within(severities).getByRole('button', { name: /^High/ })).toHaveTextContent('High1');
    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: ['resolved'] }),
      expect.anything()
    );
  });

  it('filters by severity from the summary and removes it from its chip', async () => {
    mockedSummary.mockResolvedValue(summary({ critical: [2, 0, 1], high: [4, 1, 1] }));
    mockedIssues.mockResolvedValue(list([issue('a', 'high')]));
    render(<IssuesPage />);

    const severities = await screen.findByRole('group', { name: 'Severity' });
    await userEvent.click(within(severities).getByRole('button', { name: /^Critical/ }));
    await userEvent.click(within(severities).getByRole('button', { name: /^High/ }));
    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ severity: ['critical', 'high'], status: ['open'] }),
      expect.anything()
    );
    const statuses = screen.getByRole('group', { name: 'Status' });
    expect(within(statuses).getByRole('button', { name: /^Open/ })).toHaveTextContent('Open6');

    await userEvent.click(screen.getByRole('button', { name: 'Remove severity filter: critical' }));
    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ severity: ['high'] }),
      expect.anything()
    );
  });

  it('shows how many of the total are loaded and appends the next page on request', async () => {
    mockedSummary.mockResolvedValue(summary({ high: [3, 0, 0] }));
    mockedIssues
      .mockResolvedValueOnce({
        items: [issue('a', 'high'), issue('b', 'high')],
        nextToken: 't1',
        totalCount: 2,
      })
      .mockResolvedValueOnce({ items: [issue('c', 'high')], totalCount: 1 });
    render(<IssuesPage />);

    expect(await screen.findByText('Showing 2 of 3 issues')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'Load more' }));
    expect(await screen.findByText('Showing 3 of 3 issues')).toBeInTheDocument();
    expect(screen.getByRole('cell', { name: /Title c/ })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Load more' })).not.toBeInTheDocument();
    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ status: ['open'], nextToken: 't1' })
    );
  });

  it('lists newest first and flips to oldest first from the Created header, keeping filters', async () => {
    mockedIssues.mockResolvedValue(list([issue('a', 'high')]));
    render(<IssuesPage />);
    await screen.findByRole('cell', { name: /Title a/ });
    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ order: 'desc', status: ['open'] }),
      expect.anything()
    );

    await userEvent.click(screen.getByRole('button', { name: 'Created, newest first' }));

    expect(mockedIssues).toHaveBeenLastCalledWith(
      expect.objectContaining({ order: 'asc', status: ['open'] }),
      expect.anything()
    );
    expect(screen.getByRole('button', { name: 'Created, oldest first' })).toBeInTheDocument();
  });
});
