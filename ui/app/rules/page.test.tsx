import { render, screen, within } from '@testing-library/react';
import { getRuleQuality } from '@/lib/api';
import RulesPage from './page';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getRuleQuality: jest.fn(),
}));

const mockedQuality = getRuleQuality as jest.MockedFunction<typeof getRuleQuality>;

const thresholds = { minHandled: 10, reliableDismissalRate: 0.2, noisyDismissalRate: 0.5 };

describe('RulesPage', () => {
  beforeEach(() => {
    mockedQuality.mockReset().mockResolvedValue({
      rules: [
        {
          ruleId: 'RULE-006',
          name: 'Cross-Account IAM Trust with Wildcard Resource Access',
          ownerTeam: 'iam-security',
          severityHint: 'critical',
          enabled: true,
          autoTicket: false,
          inCatalogue: true,
          open: 40,
          suppressed: 12,
          resolved: 8,
          handled: 20,
          dismissalRate: 0.6,
          corroborated: 7,
          labeled: 10,
          corroborationRate: 0.7,
          verdict: 'noisy',
        },
        {
          ruleId: 'RULE-002',
          name: 'Security Groups Open to the Internet on SSH/RDP',
          ownerTeam: 'cloud-security',
          severityHint: 'high',
          enabled: true,
          autoTicket: true,
          inCatalogue: true,
          open: 3,
          suppressed: 1,
          resolved: 19,
          handled: 20,
          dismissalRate: 0.05,
          corroborated: 2,
          labeled: 2,
          corroborationRate: null,
          verdict: 'reliable',
        },
      ],
      thresholds,
      generatedAt: '2026-10-26T00:00:00.000Z',
    });
  });

  it('shows each rule with its lifecycle counts, dismissal rate and verdict', async () => {
    render(<RulesPage />);

    expect(await screen.findByText('Rule quality')).toBeInTheDocument();
    const rows = screen.getAllByTestId('rule-quality-row');
    expect(rows).toHaveLength(2);

    const noisy = rows[0];
    expect(
      within(noisy).getByText('Cross-Account IAM Trust with Wildcard Resource Access')
    ).toBeInTheDocument();
    expect(within(noisy).getByText('RULE-006')).toBeInTheDocument();
    expect(within(noisy).getByText('60%')).toBeInTheDocument();
    expect(within(noisy).getByText('70% of 10')).toBeInTheDocument();
    expect(within(noisy).getByText('Noisy')).toBeInTheDocument();
    expect(within(noisy).getByText('off')).toBeInTheDocument();

    const reliable = rows[1];
    expect(within(reliable).getByText('5%')).toBeInTheDocument();
    expect(within(reliable).getAllByText('—').length).toBeGreaterThan(0);
    expect(within(reliable).getByText('Reliable')).toBeInTheDocument();
    expect(within(reliable).getByText('on')).toBeInTheDocument();
  });

  it('explains that dismissal is a proxy and how many closed issues a verdict needs', async () => {
    render(<RulesPage />);

    const description = await screen.findByText(/noise proxy, not ground truth/);
    expect(description).toHaveTextContent('at least 10 closed issues');
    expect(description).toHaveTextContent('independent detector');
  });

  it('shows the empty state before anything has closed', async () => {
    mockedQuality.mockResolvedValue({
      rules: [],
      thresholds,
      generatedAt: '2026-10-26T00:00:00.000Z',
    });

    render(<RulesPage />);

    expect(await screen.findByText('No issues recorded yet')).toBeInTheDocument();
  });
});
