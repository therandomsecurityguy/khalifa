import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ApiError, getAccounts, getSession, searchAttackPaths, searchResources } from '@/lib/api';
import type { AttackPathSearchResponse } from '@/types';
import AttackPathsPage from './page';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  searchAttackPaths: jest.fn(),
  getAccounts: jest.fn(),
  getSession: jest.fn(),
  searchResources: jest.fn(),
}));

const mockedSearch = searchAttackPaths as jest.MockedFunction<typeof searchAttackPaths>;
const mockedAccounts = getAccounts as jest.MockedFunction<typeof getAccounts>;
const mockedSession = getSession as jest.MockedFunction<typeof getSession>;
const mockedResources = searchResources as jest.MockedFunction<typeof searchResources>;

function result(overrides: Partial<AttackPathSearchResponse> = {}): AttackPathSearchResponse {
  return {
    from: 'any',
    to: 'restricted',
    maxPathLength: 4,
    paths: [],
    entries: {},
    truncated: false,
    ...overrides,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => (resolve = res));
  return { promise, resolve };
}

const filters = () => screen.getByRole('search', { name: 'Filters' });
const pick = (name: string, value: string) =>
  userEvent.selectOptions(within(filters()).getByRole('combobox', { name }), value);

describe('AttackPathsPage', () => {
  beforeEach(() => {
    window.history.replaceState(null, '', '/attack-paths');
    mockedSearch.mockReset().mockResolvedValue(result());
    mockedAccounts.mockReset().mockResolvedValue({
      accounts: [{ id: '111122223333', name: 'prod' }],
    });
    mockedResources.mockReset().mockResolvedValue({
      label: 'S3Bucket',
      resources: [
        {
          id: 'arn:aws:s3:::payments-exports',
          label: 'S3Bucket',
          properties: { name: 'payments-exports', account_id: '111122223333' },
        },
      ],
    });
    mockedSession.mockReset().mockResolvedValue({
      email: 'analyst@example.com',
      role: 'Analyst',
      canManageIssues: true,
    });
  });

  it('does not search until a start and a target are chosen', async () => {
    render(<AttackPathsPage />);

    expect(
      await screen.findByText(/Pick a starting point and a target in the filters/)
    ).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Attack paths', level: 2 })).toBeInTheDocument();

    await pick('Starting from', 'any');
    expect(mockedSearch).not.toHaveBeenCalled();

    await pick('Reaching', 'restricted');
    await waitFor(() =>
      expect(mockedSearch).toHaveBeenCalledWith({
        from: 'any',
        to: 'restricted',
        fromResource: undefined,
        toResource: undefined,
        account: undefined,
        maxPathLength: 4,
      })
    );
    expect(
      screen.getByRole('heading', { name: 'Any entry point → Restricted data' })
    ).toBeInTheDocument();
    expect(await screen.findByText(/No path within 4 hops matches/)).toBeInTheDocument();
    expect(window.location.search).toBe('?from=any&to=restricted&hops=4');
  });

  it('re-searches when a filter changes, and only the newest result is shown', async () => {
    window.history.replaceState(null, '', '/attack-paths?from=any&to=restricted');
    const slow = deferred<AttackPathSearchResponse>();
    mockedSearch
      .mockReturnValueOnce(slow.promise)
      .mockResolvedValueOnce(result({ from: 'outside', to: 'secrets', paths: [] }));
    render(<AttackPathsPage />);
    await waitFor(() => expect(mockedSearch).toHaveBeenCalledTimes(1));

    await pick('Starting from', 'outside');
    await pick('Reaching', 'secrets');
    await waitFor(() =>
      expect(mockedSearch).toHaveBeenLastCalledWith(
        expect.objectContaining({ from: 'outside', to: 'secrets' })
      )
    );
    expect(await screen.findByText(/No path within/)).toBeInTheDocument();

    await act(async () =>
      slow.resolve(
        result({
          truncated: true,
          paths: [
            {
              nodes: [],
              edges: [],
              score: 1,
              severity: 'low',
              likelihood: 0.1,
              likelihoodFactors: {
                exposure: 1,
                privilege: 0.5,
                exploitability: 0.5,
                reachability: 1,
              },
            },
          ],
        })
      )
    );
    expect(screen.queryByText(/more exist/)).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Outside accounts → Secrets' })).toBeInTheDocument();
  });

  it('caps the hop slider at the caller role limit', async () => {
    render(<AttackPathsPage />);
    expect(await screen.findByRole('slider', { name: 'Max hops' })).toHaveAttribute('max', '10');
  });

  it('caps Viewers at 4 hops', async () => {
    mockedSession.mockResolvedValue({
      email: 'viewer@example.com',
      role: 'Viewer',
      canManageIssues: false,
    });
    window.history.replaceState(null, '', '/attack-paths?from=any&to=crown&hops=9');
    render(<AttackPathsPage />);
    expect(await screen.findByRole('slider', { name: 'Max hops' })).toHaveAttribute('max', '4');
    await waitFor(() =>
      expect(mockedSearch).toHaveBeenCalledWith(expect.objectContaining({ maxPathLength: 4 }))
    );
  });

  it('waits for a picked resource before searching to it', async () => {
    window.history.replaceState(null, '', '/attack-paths?from=any&to=restricted');
    render(<AttackPathsPage />);
    await waitFor(() => expect(mockedSearch).toHaveBeenCalledTimes(1));

    await pick('Reaching', 'resource');
    expect(screen.getByText(/Choose a resource in the filters/)).toBeInTheDocument();
    expect(within(filters()).getByRole('group', { name: 'End at' })).toBeInTheDocument();
    expect(within(filters()).queryByRole('group', { name: 'Start at' })).not.toBeInTheDocument();

    await userEvent.type(within(filters()).getByLabelText('Name'), 'payments');
    await userEvent.click(
      await within(filters()).findByRole('button', { name: /payments-exports/ })
    );

    await waitFor(() =>
      expect(mockedSearch).toHaveBeenLastCalledWith(
        expect.objectContaining({ to: 'resource', toResource: 'arn:aws:s3:::payments-exports' })
      )
    );
    expect(
      screen.getByRole('heading', { name: 'Any entry point → payments-exports' })
    ).toBeInTheDocument();
    expect(mockedSearch).toHaveBeenCalledTimes(2);
  });

  it('restores a shared link, including a resource and account', async () => {
    window.history.replaceState(
      null,
      '',
      '/attack-paths?from=resource&fromResource=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fapp&to=crown&hops=3&account=111122223333'
    );
    render(<AttackPathsPage />);

    await waitFor(() =>
      expect(mockedSearch).toHaveBeenCalledWith({
        from: 'resource',
        to: 'crown',
        fromResource: 'arn:aws:iam::111122223333:role/app',
        toResource: undefined,
        account: '111122223333',
        maxPathLength: 3,
      })
    );
    expect(screen.getByRole('heading', { name: 'app → Crown jewels' })).toBeInTheDocument();
    expect(
      await within(filters()).findByRole('option', { name: 'prod · 111122223333' })
    ).toBeInTheDocument();
    expect(within(filters()).getByRole('combobox', { name: 'Account' })).toHaveValue(
      '111122223333'
    );
  });

  it('narrows to an account picked from the list', async () => {
    window.history.replaceState(null, '', '/attack-paths?from=any&to=restricted');
    render(<AttackPathsPage />);
    await waitFor(() => expect(mockedSearch).toHaveBeenCalledTimes(1));

    await within(filters()).findByRole('option', { name: 'prod · 111122223333' });
    await pick('Account', '111122223333');
    await waitFor(() =>
      expect(mockedSearch).toHaveBeenLastCalledWith(
        expect.objectContaining({ account: '111122223333' })
      )
    );

    await pick('Account', '');
    await waitFor(() =>
      expect(mockedSearch).toHaveBeenLastCalledWith(expect.objectContaining({ account: undefined }))
    );
  });

  it('says so when results were cut off', async () => {
    window.history.replaceState(null, '', '/attack-paths?from=any&to=restricted');
    mockedSearch.mockResolvedValue(result({ truncated: true }));
    render(<AttackPathsPage />);
    expect(await screen.findByText(/more exist/)).toBeInTheDocument();
  });

  it('asks to narrow a search that timed out', async () => {
    window.history.replaceState(null, '', '/attack-paths?from=any&to=restricted');
    mockedSearch.mockRejectedValue(new ApiError(504, 'Attack path search timed out'));
    render(<AttackPathsPage />);
    expect(
      await screen.findByText(/took too long. Pick an account or fewer hops/)
    ).toBeInTheDocument();
  });

  it('clears a stale graph when a search fails', async () => {
    window.history.replaceState(null, '', '/attack-paths?from=any&to=restricted');
    mockedSearch
      .mockResolvedValueOnce(result({ truncated: true }))
      .mockRejectedValueOnce(new ApiError(500, 'boom'));
    render(<AttackPathsPage />);
    expect(await screen.findByText(/more exist/)).toBeInTheDocument();

    await pick('Reaching', 'crown');
    expect(await screen.findByRole('alert')).toBeInTheDocument();
    expect(screen.queryByText(/more exist/)).not.toBeInTheDocument();
  });
});
