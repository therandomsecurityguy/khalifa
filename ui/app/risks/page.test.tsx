import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createRisk, getRisks, getSession } from '@/lib/api';
import type { RiskRegisterEntry } from '@/types';
import RiskRegisterPage from './page';

const push = jest.fn();

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: jest.fn() }),
}));

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  createRisk: jest.fn(),
  getRisks: jest.fn(),
  getSession: jest.fn(),
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
  residual: { likelihood: 2, impact: 3 },
  treatment: 'mitigate',
  acceptanceExpiry: null,
  reviewCadenceDays: 90,
  lastReviewedAt: null,
  linkedIssueIds: [],
  linkedControls: ['KH-IAM-1'],
  createdAt: '2026-10-01T00:00:00.000Z',
  createdBy: 'team-iam',
  updatedAt: '2026-11-01T00:00:00.000Z',
  updatedBy: 'team-iam',
  inherentScore: 20,
  inherentLevel: 'critical',
  residualScore: 6,
  residualLevel: 'medium',
  nextReviewAt: overdue,
};

describe('RiskRegisterPage', () => {
  beforeEach(() => {
    push.mockReset();
    (getSession as jest.Mock).mockResolvedValue({
      email: 'analyst@example.com',
      role: 'Analyst',
      canManageIssues: true,
    });
    (getRisks as jest.Mock).mockResolvedValue({ items: [entry], truncated: false });
    (createRisk as jest.Mock).mockReset();
  });

  it('renders rows with derived levels and flags an overdue review', async () => {
    render(<RiskRegisterPage />);

    expect(await screen.findByRole('heading', { name: 'Risks (1)' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Shared admin role' })).toHaveAttribute(
      'href',
      '/risks/detail?id=shared-admin-role'
    );
    expect(screen.getByText('critical')).toBeInTheDocument();
    expect(screen.getByText('medium')).toBeInTheDocument();
    expect(screen.getByText(/overdue/)).toBeInTheDocument();
  });

  it('creates with the default 3x3 inherent rating and navigates', async () => {
    (createRisk as jest.Mock).mockResolvedValue({ ...entry, id: 'new-risk' });
    render(<RiskRegisterPage />);

    await userEvent.type(await screen.findByLabelText('Title'), 'New risk');
    await userEvent.click(screen.getByRole('button', { name: /Create risk/ }));

    await waitFor(() =>
      expect(createRisk).toHaveBeenCalledWith({
        title: 'New risk',
        inherent: { likelihood: 3, impact: 3 },
      })
    );
    await waitFor(() => expect(push).toHaveBeenCalledWith('/risks/detail?id=new-risk'));
  });

  it('hides the create form from a Viewer', async () => {
    (getSession as jest.Mock).mockResolvedValue({
      email: 'viewer@example.com',
      role: 'Viewer',
      canManageIssues: false,
    });
    render(<RiskRegisterPage />);

    await screen.findByRole('heading', { name: 'Risks (1)' });
    expect(screen.queryByRole('button', { name: /Create risk/ })).not.toBeInTheDocument();
  });
});
