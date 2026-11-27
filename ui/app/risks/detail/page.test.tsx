import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { deleteRisk, getRisk, getSession, updateRisk } from '@/lib/api';
import type { RiskRegisterEntry } from '@/types';
import RiskDetailPage from './page';

const push = jest.fn();
let mockSearch = 'id=shared-admin-role';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: jest.fn() }),
  useSearchParams: () => new URLSearchParams(mockSearch),
}));

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  deleteRisk: jest.fn(),
  getRisk: jest.fn(),
  getSession: jest.fn(),
  updateRisk: jest.fn(),
}));

const overdue = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString();

const entry: RiskRegisterEntry = {
  id: 'shared-admin-role',
  title: 'Shared admin role',
  description: 'One role holds admin across prod accounts.',
  category: 'security',
  owner: 'team-iam',
  status: 'monitoring',
  inherent: { likelihood: 4, impact: 5 },
  residual: null,
  treatment: 'mitigate',
  acceptanceExpiry: null,
  reviewCadenceDays: 90,
  lastReviewedAt: null,
  linkedIssueIds: ['RULE-032-abc'],
  linkedControls: ['KH-IAM-1'],
  createdAt: '2026-10-01T00:00:00.000Z',
  createdBy: 'team-iam',
  updatedAt: '2026-11-01T00:00:00.000Z',
  updatedBy: 'team-iam',
  inherentScore: 20,
  inherentLevel: 'critical',
  residualScore: null,
  residualLevel: null,
  nextReviewAt: overdue,
};

describe('RiskDetailPage', () => {
  beforeEach(() => {
    mockSearch = 'id=shared-admin-role';
    push.mockReset();
    (getRisk as jest.Mock).mockReset().mockResolvedValue(entry);
    (getSession as jest.Mock).mockResolvedValue({
      email: 'analyst@example.com',
      role: 'Analyst',
      canManageIssues: true,
    });
    (updateRisk as jest.Mock).mockReset();
    (deleteRisk as jest.Mock).mockReset();
  });

  it('renders the derived score, overdue review, and links', async () => {
    render(<RiskDetailPage />);

    expect(await screen.findByRole('heading', { name: 'Shared admin role' })).toBeInTheDocument();
    expect(screen.getByText(/L4 × I5 = 20/)).toBeInTheDocument();
    expect(screen.getByText('Not assessed')).toBeInTheDocument();
    expect(screen.getByText(/overdue/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'RULE-032-abc' })).toHaveAttribute(
      'href',
      '/issues/RULE-032-abc'
    );
    expect(screen.getByText('KH-IAM-1')).toBeInTheDocument();
  });

  it('saves edits with parsed ratings, residual, and links', async () => {
    (updateRisk as jest.Mock).mockResolvedValue(entry);
    render(<RiskDetailPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const title = screen.getByLabelText('Title');
    await userEvent.clear(title);
    await userEvent.type(title, 'Shared admin role (prod)');
    await userEvent.click(screen.getByLabelText('Residual risk assessed'));
    await userEvent.selectOptions(screen.getByLabelText('Residual likelihood (1-5)'), '2');
    await userEvent.click(screen.getByRole('button', { name: /Save changes/ }));

    await waitFor(() => expect(updateRisk).toHaveBeenCalled());
    expect(updateRisk).toHaveBeenCalledWith(
      'shared-admin-role',
      expect.objectContaining({
        title: 'Shared admin role (prod)',
        residual: { likelihood: 2, impact: 3 },
        acceptanceExpiry: null,
        linkedIssueIds: ['RULE-032-abc'],
        linkedControls: ['KH-IAM-1'],
      })
    );
    expect(await screen.findByRole('button', { name: 'Edit' })).toBeInTheDocument();
  });

  it('requires an acceptance date before saving an accepted treatment', async () => {
    (updateRisk as jest.Mock).mockResolvedValue(entry);
    render(<RiskDetailPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    await userEvent.selectOptions(screen.getByLabelText('Treatment'), 'accept');

    const save = screen.getByRole('button', { name: /Save changes/ });
    expect(save).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Acceptance expiry'), {
      target: { value: '2027-01-01' },
    });
    expect(save).toBeEnabled();
    await userEvent.click(save);

    await waitFor(() => expect(updateRisk).toHaveBeenCalled());
    expect(updateRisk).toHaveBeenCalledWith(
      'shared-admin-role',
      expect.objectContaining({
        treatment: 'accept',
        acceptanceExpiry: '2027-01-01T00:00:00.000Z',
      })
    );
  });

  it('deletes through a two-step confirmation and returns to the register', async () => {
    (deleteRisk as jest.Mock).mockResolvedValue({ id: 'shared-admin-role', deleted: true });
    render(<RiskDetailPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    expect(deleteRisk).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: /Really delete/ }));

    await waitFor(() => expect(deleteRisk).toHaveBeenCalledWith('shared-admin-role'));
    expect(push).toHaveBeenCalledWith('/risks');
  });

  it('hides write controls from a Viewer', async () => {
    (getSession as jest.Mock).mockResolvedValue({
      email: 'viewer@example.com',
      role: 'Viewer',
      canManageIssues: false,
    });
    render(<RiskDetailPage />);

    await screen.findByRole('heading', { name: 'Shared admin role' });
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });
});
