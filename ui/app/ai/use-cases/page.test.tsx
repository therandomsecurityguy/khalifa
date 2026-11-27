import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createAiUseCase, getAiUseCaseCoverage, getAiUseCases, getSession } from '@/lib/api';
import type { AiUseCase, AiUseCaseCoverage } from '@/types';
import AiUseCasesPage from './page';

const push = jest.fn();

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: jest.fn() }),
}));

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  createAiUseCase: jest.fn(),
  getAiUseCaseCoverage: jest.fn(),
  getAiUseCases: jest.fn(),
  getSession: jest.fn(),
}));

const useCase: AiUseCase = {
  id: 'support-assistant',
  name: 'Support assistant',
  description: 'Answers customer questions with a Bedrock agent.',
  owner: 'team-ai',
  status: 'approved',
  assets: ['arn:aws:bedrock:us-west-2:111122223333:agent/agent-1'],
  dataClasses: ['internal'],
  assessment: {
    status: 'approved',
    riskTier: 'medium',
    owner: 'risk@example.com',
    humanOversight: 'Weekly review.',
    impacts: '',
    notes: '',
    reviewedAt: '2026-11-01T00:00:00Z',
    updatedAt: '2026-11-01T00:00:00Z',
    updatedBy: 'risk@example.com',
  },
  createdAt: '2026-10-01T00:00:00Z',
  createdBy: 'team-ai',
  updatedAt: '2026-11-01T00:00:00Z',
  updatedBy: 'team-ai',
};

const coverage: AiUseCaseCoverage = {
  useCaseCount: 1,
  registeredAssets: 1,
  unregistered: [
    {
      arn: 'arn:aws:sagemaker:us-west-2:111122223333:endpoint/ep-1',
      type: 'endpoints',
      label: 'AiEndpoint',
      name: 'ep-1',
      account_id: '111122223333',
      region: 'us-west-2',
    },
  ],
  missing: [
    { arn: 'arn:aws:bedrock:us-west-2:111122223333:agent/gone', useCaseId: 'support-assistant' },
  ],
  truncated: false,
};

describe('AiUseCasesPage', () => {
  beforeEach(() => {
    push.mockReset();
    (getSession as jest.Mock).mockResolvedValue({
      email: 'analyst@example.com',
      role: 'Analyst',
      canManageIssues: true,
    });
    (getAiUseCases as jest.Mock).mockResolvedValue({ items: [useCase], truncated: false });
    (getAiUseCaseCoverage as jest.Mock).mockResolvedValue(coverage);
    (createAiUseCase as jest.Mock).mockReset();
  });

  it('renders the registry and the coverage gaps it creates', async () => {
    render(<AiUseCasesPage />);

    expect(await screen.findByRole('heading', { name: 'Use cases (1)' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Support assistant' })).toHaveAttribute(
      'href',
      '/ai/use-cases/detail?id=support-assistant'
    );
    expect(screen.getByText('medium')).toBeInTheDocument();
    expect(screen.getByText(/Collected assets no use case covers \(1\)/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'ep-1' })).toHaveAttribute(
      'href',
      expect.stringContaining('/resources?arn=')
    );
    expect(screen.getByText(/Registered assets not in the graph \(1\)/)).toBeInTheDocument();
  });

  it('creates a use case and navigates to its detail page', async () => {
    (createAiUseCase as jest.Mock).mockResolvedValue({ ...useCase, id: 'new-case' });
    render(<AiUseCasesPage />);

    await userEvent.type(await screen.findByLabelText('Name'), 'New case');
    await userEvent.type(screen.getByLabelText('Owner'), 'team-ai');
    await userEvent.click(screen.getByRole('button', { name: /Create use case/ }));

    await waitFor(() =>
      expect(createAiUseCase).toHaveBeenCalledWith({ name: 'New case', owner: 'team-ai' })
    );
    await waitFor(() => expect(push).toHaveBeenCalledWith('/ai/use-cases/detail?id=new-case'));
  });

  it('hides the create form from a Viewer', async () => {
    (getSession as jest.Mock).mockResolvedValue({
      email: 'viewer@example.com',
      role: 'Viewer',
      canManageIssues: false,
    });
    render(<AiUseCasesPage />);

    await screen.findByRole('heading', { name: 'Use cases (1)' });
    expect(screen.queryByRole('button', { name: /Create use case/ })).not.toBeInTheDocument();
  });
});
