import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { deleteVendor, getSession, getVendor, updateVendor } from '@/lib/api';
import type { VendorRegisterEntry } from '@/types';
import VendorDetailPage from './page';

const push = jest.fn();
let mockSearch = 'id=example-cloud';

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: jest.fn() }),
  useSearchParams: () => new URLSearchParams(mockSearch),
}));

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  deleteVendor: jest.fn(),
  getSession: jest.fn(),
  getVendor: jest.fn(),
  updateVendor: jest.fn(),
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

describe('VendorDetailPage', () => {
  beforeEach(() => {
    mockSearch = 'id=example-cloud';
    push.mockReset();
    (getVendor as jest.Mock).mockReset().mockResolvedValue(entry);
    (getSession as jest.Mock).mockResolvedValue({
      email: 'analyst@example.com',
      role: 'Analyst',
      canManageIssues: true,
    });
    (updateVendor as jest.Mock).mockReset();
    (deleteVendor as jest.Mock).mockReset();
  });

  it('renders the disclosure fields, DPA link, and overdue review', async () => {
    render(<VendorDetailPage />);

    expect(await screen.findByRole('heading', { name: 'Example Cloud' })).toBeInTheDocument();
    expect(screen.getByText('Hosting')).toBeInTheDocument();
    expect(screen.getByText('us-east-1')).toBeInTheDocument();
    const dpa = screen.getByRole('link', { name: 'https://example.com/dpa' });
    expect(dpa).toHaveAttribute('href', 'https://example.com/dpa');
    expect(dpa).toHaveAttribute('rel', 'noopener noreferrer');
    expect(screen.getByText(/overdue/)).toBeInTheDocument();
    expect(screen.getByText(/passed/)).toBeInTheDocument();
  });

  it('saves edits with parsed data classes and the subprocessor fields', async () => {
    (updateVendor as jest.Mock).mockResolvedValue(entry);
    render(<VendorDetailPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const name = screen.getByLabelText('Name');
    await userEvent.clear(name);
    await userEvent.type(name, 'Example Cloud EU');
    const dataClasses = screen.getByLabelText('Data classes');
    await userEvent.clear(dataClasses);
    await userEvent.type(dataClasses, 'internal, customer-pii');
    await userEvent.click(screen.getByRole('button', { name: /Save changes/ }));

    await waitFor(() => expect(updateVendor).toHaveBeenCalled());
    expect(updateVendor).toHaveBeenCalledWith(
      'example-cloud',
      expect.objectContaining({
        name: 'Example Cloud EU',
        dataClasses: ['internal', 'customer-pii'],
        subprocessor: true,
        purpose: 'Hosting',
        location: 'us-east-1',
        dpaUrl: 'https://example.com/dpa',
      })
    );
    expect(await screen.findByRole('button', { name: 'Edit' })).toBeInTheDocument();
  });

  it('blocks saving a subprocessor listing without purpose and location', async () => {
    render(<VendorDetailPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Edit' }));
    const purpose = screen.getByLabelText('Purpose');
    await userEvent.clear(purpose);

    expect(screen.getByRole('button', { name: /Save changes/ })).toBeDisabled();
    expect(
      screen.getByText('A subprocessor listing requires its purpose and location.')
    ).toBeInTheDocument();

    await userEvent.type(purpose, 'Hosting');
    expect(screen.getByRole('button', { name: /Save changes/ })).toBeEnabled();
  });

  it('deletes through a two-step confirmation and returns to the register', async () => {
    (deleteVendor as jest.Mock).mockResolvedValue({ id: 'example-cloud', deleted: true });
    render(<VendorDetailPage />);

    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    expect(deleteVendor).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: /Really delete/ }));

    await waitFor(() => expect(deleteVendor).toHaveBeenCalledWith('example-cloud'));
    expect(push).toHaveBeenCalledWith('/vendors');
  });

  it('hides write controls from a Viewer', async () => {
    (getSession as jest.Mock).mockResolvedValue({
      email: 'viewer@example.com',
      role: 'Viewer',
      canManageIssues: false,
    });
    render(<VendorDetailPage />);

    await screen.findByRole('heading', { name: 'Example Cloud' });
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument();
  });
});
