import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createVendor, getSession, getVendors } from '@/lib/api';
import type { VendorRegisterEntry } from '@/types';
import VendorRegisterPage from './page';

const push = jest.fn();

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: jest.fn() }),
}));

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  createVendor: jest.fn(),
  getSession: jest.fn(),
  getVendors: jest.fn(),
}));

const past = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000).toISOString();

const entry: VendorRegisterEntry = {
  id: 'example-cloud',
  name: 'Example Cloud',
  category: 'cloud',
  purpose: 'Hosting',
  location: 'us-east-1',
  dpaUrl: 'https://example.com/dpa',
  dataClasses: ['internal'],
  owner: 'procurement@example.com',
  status: 'active',
  subprocessor: true,
  renewalAt: past,
  reviewCadenceDays: 365,
  lastReviewedAt: null,
  createdAt: '2026-10-01T00:00:00.000Z',
  createdBy: 'procurement@example.com',
  updatedAt: '2026-11-01T00:00:00.000Z',
  updatedBy: 'procurement@example.com',
  nextReviewAt: past,
};

describe('VendorRegisterPage', () => {
  beforeEach(() => {
    push.mockReset();
    (getSession as jest.Mock).mockResolvedValue({
      email: 'analyst@example.com',
      role: 'Analyst',
      canManageIssues: true,
    });
    (getVendors as jest.Mock).mockResolvedValue({ items: [entry], truncated: false });
    (createVendor as jest.Mock).mockReset();
  });

  it('renders rows with the subprocessor flag and overdue review', async () => {
    render(<VendorRegisterPage />);

    expect(await screen.findByRole('heading', { name: 'Vendors (1)' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Example Cloud' })).toHaveAttribute(
      'href',
      '/vendors/detail?id=example-cloud'
    );
    expect(screen.getByText('yes')).toBeInTheDocument();
    expect(screen.getByText(/overdue/)).toBeInTheDocument();
  });

  it('creates with the default other category and navigates', async () => {
    (createVendor as jest.Mock).mockResolvedValue({ ...entry, id: 'new-vendor' });
    render(<VendorRegisterPage />);

    await userEvent.type(await screen.findByLabelText('Name'), 'New vendor');
    await userEvent.click(screen.getByRole('button', { name: /Create vendor/ }));

    await waitFor(() =>
      expect(createVendor).toHaveBeenCalledWith({ name: 'New vendor', category: 'other' })
    );
    await waitFor(() => expect(push).toHaveBeenCalledWith('/vendors/detail?id=new-vendor'));
  });

  it('hides the create form from a Viewer', async () => {
    (getSession as jest.Mock).mockResolvedValue({
      email: 'viewer@example.com',
      role: 'Viewer',
      canManageIssues: false,
    });
    render(<VendorRegisterPage />);

    await screen.findByRole('heading', { name: 'Vendors (1)' });
    expect(screen.queryByRole('button', { name: /Create vendor/ })).not.toBeInTheDocument();
  });
});
