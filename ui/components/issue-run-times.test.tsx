import { render, screen } from '@testing-library/react';
import { getIssueSchedule } from '@/lib/api';
import { IssueRunTimes } from './issue-run-times';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getIssueSchedule: jest.fn(),
}));

const mocked = getIssueSchedule as jest.MockedFunction<typeof getIssueSchedule>;
const minutesFromNow = (m: number) => new Date(Date.now() + m * 60_000).toISOString();

describe('IssueRunTimes', () => {
  it('shows when issues were last updated and when they update next', async () => {
    mocked.mockResolvedValue({
      lastRunAt: minutesFromNow(-72),
      nextRunAt: minutesFromNow(168),
      intervalMinutes: 240,
    });
    render(<IssueRunTimes />);

    expect(await screen.findByText('Issues last updated 1h 12m ago')).toBeInTheDocument();
    expect(screen.getByText('Next update in about 2h 48m')).toBeInTheDocument();
  });

  it('flags an overdue update', async () => {
    mocked.mockResolvedValue({
      lastRunAt: minutesFromNow(-9 * 60),
      nextRunAt: minutesFromNow(30),
      intervalMinutes: 240,
    });
    render(<IssueRunTimes />);

    const line = await screen.findByText(/Issues last updated 9h ago · overdue/);
    expect(line.parentElement).toHaveClass('text-amber-800');
  });
});
