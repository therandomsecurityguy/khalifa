import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { APP_SECTIONS } from '@/lib/routes';
import { getSession } from '@/lib/api';
import { AppNav } from './app-nav';

const usePathname = jest.fn();
jest.mock('next/navigation', () => ({ usePathname: () => usePathname() }));
jest.mock('@/lib/api', () => ({ ...jest.requireActual('@/lib/api'), getSession: jest.fn() }));

const mockedSession = getSession as jest.MockedFunction<typeof getSession>;

describe('AppNav', () => {
  beforeEach(() => {
    usePathname.mockReturnValue('/compliance/SOC2');
    mockedSession.mockResolvedValue({
      email: 'analyst@example.com',
      role: 'Analyst',
      canManageIssues: true,
    });
  });

  it("shows the sections, and the current section's pages beneath them", async () => {
    render(<AppNav />);
    const sections = screen.getByRole('navigation', { name: 'Primary' });
    expect(
      within(sections)
        .getAllByRole('link')
        .map((link) => [link.textContent, link.getAttribute('href')])
    ).toEqual(APP_SECTIONS.map((section) => [section.label, section.routes[0].href]));
    expect(within(sections).getByRole('link', { name: 'Risks' })).toHaveAttribute(
      'aria-current',
      'true'
    );

    const pages = screen.getByRole('navigation', { name: 'Risks' });
    expect(
      within(pages)
        .getAllByRole('link')
        .map((link) => link.textContent)
    ).toEqual(['Issues', 'Compliance', 'Rules']);
    expect(within(pages).getByRole('link', { name: 'Compliance' })).toHaveAttribute(
      'aria-current',
      'page'
    );
    expect(await screen.findByText('analyst@example.com')).toHaveAttribute('title', 'Analyst');
  });

  it('files Identity tools under Inventory and shows no page row off the map', async () => {
    usePathname.mockReturnValue('/least-privilege');
    const { rerender } = render(<AppNav />);
    expect(
      within(screen.getByRole('navigation', { name: 'Inventory' })).getByRole('link', {
        name: 'Identity',
      })
    ).toHaveAttribute('aria-current', 'page');

    usePathname.mockReturnValue('/nowhere');
    rerender(<AppNav />);
    expect(
      within(screen.getByRole('navigation', { name: 'Primary' })).queryByRole('link', {
        current: 'true',
      })
    ).toBeNull();
    expect(screen.getAllByRole('navigation')).toHaveLength(1);
    expect(await screen.findByText('analyst@example.com')).toBeInTheDocument();
  });

  it('shows no identity when the session cannot be verified', async () => {
    mockedSession.mockRejectedValue(new Error('401'));
    render(<AppNav />);
    await screen.findByRole('navigation', { name: 'Primary' });
    expect(screen.queryByText(/@example\.com/)).not.toBeInTheDocument();
  });

  it('hides the desktop links on small screens and exposes a toggle instead', () => {
    render(<AppNav />);
    expect(screen.getByRole('navigation', { name: 'Primary' })).toHaveClass('hidden', 'md:flex');
    expect(screen.getByRole('navigation', { name: 'Risks' })).toHaveClass('hidden', 'md:block');
    expect(screen.getByRole('button', { name: 'Open menu' })).toHaveClass('md:hidden');
  });

  it('opens the mobile menu and closes it again after navigating', async () => {
    const { rerender } = render(<AppNav />);
    const toggle = screen.getByRole('button', { name: 'Open menu' });
    expect(toggle).toHaveAttribute('aria-expanded', 'false');

    await userEvent.click(toggle);
    expect(screen.getByRole('button', { name: 'Close menu' })).toHaveAttribute(
      'aria-expanded',
      'true'
    );
    const panel = document.getElementById('mobile-navigation');
    expect(panel).not.toBeNull();
    expect(within(panel as HTMLElement).getByText('Connectors')).toBeInTheDocument();
    expect(within(panel as HTMLElement).getByRole('link', { name: 'Compliance' })).toHaveAttribute(
      'aria-current',
      'page'
    );

    usePathname.mockReturnValue('/issues');
    rerender(<AppNav />);
    expect(screen.getByRole('button', { name: 'Open menu' })).toHaveAttribute(
      'aria-expanded',
      'false'
    );
    expect(document.getElementById('mobile-navigation')).toBeNull();
  });
});
