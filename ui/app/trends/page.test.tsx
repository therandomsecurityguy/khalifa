import { render, screen, within } from '@testing-library/react';
import { getTrend, listTrendMetrics } from '@/lib/api';
import TrendsPage from './page';

let mockSearch = 'metric=issuesResolved&days=90';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn(), replace: jest.fn() }),
  useSearchParams: () => new URLSearchParams(mockSearch),
}));

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getTrend: jest.fn(),
  listTrendMetrics: jest.fn(),
}));

const mockedTrend = getTrend as jest.MockedFunction<typeof getTrend>;
const mockedMetrics = listTrendMetrics as jest.MockedFunction<typeof listTrendMetrics>;

describe('TrendsPage', () => {
  beforeEach(() => {
    mockSearch = 'metric=issuesResolved&days=90';
    mockedMetrics.mockResolvedValue({ metrics: ['openIssuesBySeverity', 'issuesResolved'] });
    mockedTrend.mockResolvedValue({
      metric: 'issuesResolved',
      points: [
        { date: '2026-09-26', value: 0 },
        { date: '2026-09-27', value: 4 },
        { date: '2026-09-28', value: 9 },
      ],
    });
  });

  it('colors a rise in resolved issues as good and names the baseline date', async () => {
    render(<TrendsPage />);

    expect(await screen.findByText('vs Sep 26')).toBeInTheDocument();
    expect(screen.getByText('+9')).toHaveClass('text-green-700');
    expect(screen.getByText('+5')).toHaveClass('text-green-700');
    expect(screen.getByText('improving')).toBeInTheDocument();
  });

  it('lists the newest day first and draws no bar for a zero day', async () => {
    render(<TrendsPage />);

    expect(await screen.findByText('3 of 90 days have data')).toBeInTheDocument();
    const rows = screen.getAllByTestId('trend-row');
    expect(rows.map((row) => within(row).getByText(/^Sep \d+$/).textContent)).toEqual([
      'Sep 28',
      'Sep 27',
      'Sep 26',
    ]);
    expect(within(rows[0]).getByText('+5')).toBeInTheDocument();
    expect(within(rows[2]).getByText('—')).toBeInTheDocument();
    expect(screen.getAllByTestId('trend-bar')).toHaveLength(2);
    expect(screen.queryAllByTestId('severity-chip')).toHaveLength(0);
  });

  it('puts severity chips on the same row as the day’s change', async () => {
    mockSearch = 'metric=openIssuesBySeverity&days=90';
    mockedTrend.mockResolvedValue({
      metric: 'openIssuesBySeverity',
      points: [
        { date: '2026-09-26', value: 1275 },
        {
          date: '2026-09-27',
          value: 1281,
          bySeverity: { critical: 39, high: 298, medium: 661, low: 283 },
        },
        {
          date: '2026-09-28',
          value: 1361,
          bySeverity: { critical: 42, high: 318, medium: 701, low: 300 },
        },
      ],
    });
    render(<TrendsPage />);

    const rows = await screen.findAllByTestId('trend-row');
    const chipText = (row: HTMLElement) =>
      within(row)
        .queryAllByTestId('severity-chip')
        .map((chip) => chip.textContent);

    expect(chipText(rows[0])).toEqual(['Ccritical +3', 'Hhigh +20', 'Mmedium +40', 'Llow +17']);
    expect(within(rows[0]).getByText('+80')).toBeInTheDocument();
    expect(chipText(rows[1])).toEqual(['Ccritical 39', 'Hhigh 298', 'Mmedium 661', 'Llow 283']);
    expect(chipText(rows[2])).toEqual([]);
  });

  it('no longer claims lower is better on every series', async () => {
    render(<TrendsPage />);

    expect(await screen.findByText('Daily snapshots from the risk runner.')).toBeInTheDocument();
    expect(screen.queryByText(/Lower is better on every series/)).not.toBeInTheDocument();
  });

  it('lists only the metrics the page describes', async () => {
    mockedMetrics.mockResolvedValue({
      metrics: ['openIssuesBySeverity', 'issuesResolved', 'publicBuckets', 'usersWithoutMfa'],
    });
    render(<TrendsPage />);

    expect(await screen.findByRole('option', { name: 'Open issues' })).toBeInTheDocument();
    expect(
      screen.queryByRole('option', { name: /publicBuckets|Public buckets/ })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('option', { name: /usersWithoutMfa|without MFA/ })
    ).not.toBeInTheDocument();
  });
});
