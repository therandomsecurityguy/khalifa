import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ShellFrame } from './shell-frame';

jest.mock('next/navigation', () => ({ usePathname: () => '/issues' }));
jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  getSession: jest.fn().mockResolvedValue({ email: null, role: null, canManageIssues: false }),
}));

describe('ShellFrame', () => {
  it('exposes banner, navigation and main landmarks around the page', () => {
    render(
      <ShellFrame>
        <h1>Security issues</h1>
      </ShellFrame>
    );
    expect(screen.getByRole('banner')).toBeInTheDocument();
    expect(screen.getByRole('navigation', { name: 'Primary' })).toBeInTheDocument();
    expect(screen.getByRole('main')).toContainElement(screen.getByRole('heading', { level: 1 }));
  });

  it('puts the skip link first and moves focus to the content', async () => {
    render(
      <ShellFrame>
        <p>Body</p>
      </ShellFrame>
    );
    await userEvent.tab();
    const skip = screen.getByRole('link', { name: 'Skip to content' });
    expect(skip).toHaveFocus();
    await userEvent.click(skip);
    expect(screen.getByRole('main')).toHaveFocus();
  });
});
