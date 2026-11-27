import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { deleteAiUseCase, getAiUseCase, getSession, updateAiUseCase } from '@/lib/api';
import type { AiUseCase } from '@/types';
import AiUseCaseDetailPage from './page';

const push = jest.fn();
let mockSearch = 'id=support-assistant';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: jest.fn() }),
  useSearchParams: () => new URLSearchParams(mockSearch),
}));

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  deleteAiUseCase: jest.fn(),
  getAiUseCase: jest.fn(),
  getSession: jest.fn(),
  updateAiUseCase: jest.fn(),
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

describe('AiUseCaseDetailPage', () => {
  beforeEach(() => {
    mockSearch = 'id=support-assistant';
    push.mockReset();
    (getAiUseCase as jest.Mock).mockReset().mockResolvedValue(useCase);
    (getSession as jest.Mock).mockResolvedValue({
      email: 'analyst@example.com',
      role: 'Analyst',
      canManageIssues: true,
    });
    (updateAiUseCase as jest.Mock).mockReset();
    (deleteAiUseCase as jest.Mock).mockReset();
  });

  it('renders the use case, its assets, and the assessment', async () => {
    render(<AiUseCaseDetailPage />);

    expect(await screen.findByRole('heading', { name: 'Support assistant' })).toBeInTheDocument();
    expect(screen.getByText('Weekly review.')).toBeInTheDocument();
    expect(screen.getByText('risk@example.com')).toBeInTheDocument();
    expect(
      screen.getByRole('link', {
        name: 'arn:aws:bedrock:us-west-2:111122223333:agent/agent-1',
      })
    ).toHaveAttribute('href', expect.stringContaining('/resources?arn='));
  });

  it('saves edits through the API with parsed assets and the assessment', async () => {
    (updateAiUseCase as jest.Mock).mockResolvedValue(useCase);
    render(<AiUseCaseDetailPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const name = screen.getByLabelText('Name');
    await userEvent.clear(name);
    await userEvent.type(name, 'Support assistant v2');
    const assets = screen.getByLabelText(/Covered asset ARNs/);
    await userEvent.clear(assets);
    await userEvent.type(
      assets,
      'arn:aws:bedrock:us-west-2:111122223333:agent/agent-1\narn:aws:bedrock:us-west-2:111122223333:knowledge-base/kb-1'
    );
    await userEvent.click(screen.getByRole('button', { name: /Save changes/ }));

    await waitFor(() => expect(updateAiUseCase).toHaveBeenCalled());
    expect(updateAiUseCase).toHaveBeenCalledWith(
      'support-assistant',
      expect.objectContaining({
        name: 'Support assistant v2',
        assets: [
          'arn:aws:bedrock:us-west-2:111122223333:agent/agent-1',
          'arn:aws:bedrock:us-west-2:111122223333:knowledge-base/kb-1',
        ],
        assessment: expect.objectContaining({ status: 'approved', riskTier: 'medium' }),
      })
    );
    // Back to view mode after the save.
    expect(await screen.findByRole('button', { name: 'Edit' })).toBeInTheDocument();
  });

  it('deletes through a two-step confirmation and returns to the list', async () => {
    (deleteAiUseCase as jest.Mock).mockResolvedValue({ id: 'support-assistant', deleted: true });
    render(<AiUseCaseDetailPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    expect(deleteAiUseCase).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: /Really delete/ }));

    await waitFor(() => expect(deleteAiUseCase).toHaveBeenCalledWith('support-assistant'));
    expect(push).toHaveBeenCalledWith('/ai/use-cases');
  });

  it('hides write controls from a Viewer', async () => {
    (getSession as jest.Mock).mockResolvedValue({
      email: 'viewer@example.com',
      role: 'Viewer',
      canManageIssues: false,
    });
    render(<AiUseCaseDetailPage />);

    await screen.findByRole('heading', { name: 'Support assistant' });
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });
});
