import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { listAttackScenarios, runAttackScenario } from '@/lib/api';
import AttackScenariosPage from './page';

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  listAttackScenarios: jest.fn(),
  runAttackScenario: jest.fn(),
}));

const mockedList = listAttackScenarios as jest.MockedFunction<typeof listAttackScenarios>;
const mockedRun = runAttackScenario as jest.MockedFunction<typeof runAttackScenario>;

describe('AttackScenariosPage', () => {
  beforeEach(() => {
    mockedList.mockReset().mockResolvedValue({
      scenarios: [
        {
          id: 'internet-to-admin',
          name: 'Internet exposure to admin',
          description: 'An open entry point and an admin role behind it.',
          techniques: [{ id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access' }],
          steps: [
            {
              ruleId: 'RULE-002',
              ruleName: 'Security Groups Open to the Internet on SSH/RDP',
              description: 'Security group open to the internet on SSH/RDP',
            },
            {
              ruleId: 'RULE-004',
              ruleName: 'Admin IAM Role on an Internet-Reachable Workload',
              description: 'Admin role on an internet-reachable workload',
            },
          ],
        },
      ],
    });
    mockedRun.mockReset().mockResolvedValue({
      scenarioId: 'internet-to-admin',
      name: 'Internet exposure to admin',
      matchedSteps: 1,
      totalSteps: 2,
      coverage: { level: 'fresh', note: 'Newest complete collection 1.2h ago.' },
      steps: [
        {
          ruleId: 'RULE-002',
          description: 'Security group open to the internet on SSH/RDP',
          matchedPaths: 3,
          resources: ['arn:aws:ec2:us-west-2:111122223333:security-group/sg-123'],
          truncated: false,
        },
        {
          ruleId: 'RULE-004',
          description: 'Admin role on an internet-reachable workload',
          matchedPaths: 0,
          resources: [],
          truncated: false,
        },
      ],
    });
  });

  it('lists scenarios with their techniques and steps, then shows a run result', async () => {
    render(<AttackScenariosPage />);

    const card = (await screen.findByText('Internet exposure to admin')).closest('section')!;
    expect(within(card).getByText(/T1133 · External Remote Services/)).toBeInTheDocument();
    expect(
      within(card).getByText('Security group open to the internet on SSH/RDP')
    ).toBeInTheDocument();

    await userEvent.click(within(card).getByRole('button', { name: 'Run scenario' }));

    expect(mockedRun).toHaveBeenCalledWith('internet-to-admin');
    expect(await within(card).findByText('1/2 steps matched')).toBeInTheDocument();
    expect(within(card).getByText(/3 matched paths/)).toBeInTheDocument();
    expect(within(card).getByText('no matches')).toBeInTheDocument();
    expect(within(card).getByText(/Graph-only/)).toBeInTheDocument();
    expect(within(card).getByText(/Newest complete collection 1.2h ago/)).toBeInTheDocument();
  });
});
