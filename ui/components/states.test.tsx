import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { ApiError } from '@/lib/api';
import { EmptyState, ErrorState, LoadingState, NoMatchesState } from './states';

describe('LoadingState', () => {
  it('is announced as a live status', () => {
    render(<LoadingState label="Loading issues…" />);
    expect(screen.getByRole('status')).toHaveTextContent('Loading issues…');
  });
});

describe('ErrorState', () => {
  it('offers a retry for transient failures', async () => {
    const onRetry = jest.fn();
    render(<ErrorState error={new ApiError(503, 'down')} onRetry={onRetry} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Khalifa is unavailable');
    await userEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('asks for sign-in when the Access session has ended', () => {
    render(
      <ErrorState
        error={new ApiError(401, 'A verified account email is required')}
        onRetry={jest.fn()}
      />
    );
    expect(screen.getByRole('alert')).toHaveTextContent('Sign-in required');
    expect(screen.getByRole('button', { name: 'Sign in again' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
  });

  it('explains missing access without a retry', () => {
    render(
      <ErrorState
        error={new ApiError(403, 'A verified account email is required')}
        onRetry={jest.fn()}
      />
    );
    expect(screen.getByRole('alert')).toHaveTextContent('No access');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('surfaces validation messages from the API', () => {
    render(<ErrorState error={new ApiError(400, 'fromSelector is not a valid label')} />);
    expect(screen.getByRole('alert')).toHaveTextContent('fromSelector is not a valid label');
  });
});

describe('empty states', () => {
  it('renders the reason nothing was collected', () => {
    render(<EmptyState title="No issues recorded" description="Nothing has run yet." />);
    expect(screen.getByText('No issues recorded')).toBeInTheDocument();
    expect(screen.getByText('Nothing has run yet.')).toBeInTheDocument();
  });

  it('keeps the filter context visible and lets the reader clear it', async () => {
    const onClear = jest.fn();
    render(
      <NoMatchesState
        noun="issues"
        activeFilters={['Severity high', 'Status open']}
        onClear={onClear}
      />
    );
    expect(screen.getByText('No issues match the current filters')).toBeInTheDocument();
    expect(screen.getByText('Active filters: Severity high · Status open')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(onClear).toHaveBeenCalledTimes(1);
  });
});
