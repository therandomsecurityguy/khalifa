'use client';

import type { ReactNode } from 'react';
import Link from 'next/link';
import { describeError } from '@/lib/api';
import {
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  SECONDARY_BUTTON,
  Spinner,
  StatusMessage,
} from '@/components/ui';

export function LoadingState({ label = 'Loading…' }: { label?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex items-center justify-center gap-3 p-8 text-sm text-gray-500"
    >
      <Spinner />
      {label}
    </div>
  );
}

// One failure surface for every request. Retry is offered only when trying
// again can help; an expired Access session gets a sign-in action instead.
export function ErrorState({
  error,
  onRetry,
  className = '',
}: {
  error: unknown;
  onRetry?: () => void;
  className?: string;
}) {
  const described = describeError(error);
  return (
    <StatusMessage tone="error" className={className}>
      <p className="font-medium">{described.title}</p>
      <p className="mt-1">{described.message}</p>
      {described.kind === 'unauthenticated' ? (
        <button
          type="button"
          className={`${PRIMARY_BUTTON} mt-3`}
          onClick={() => window.location.reload()}
        >
          Sign in again
        </button>
      ) : (
        described.retryable &&
        onRetry && (
          <button type="button" className={`${SECONDARY_BUTTON} mt-3`} onClick={onRetry}>
            Try again
          </button>
        )
      )}
    </StatusMessage>
  );
}

export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="p-8 text-center">
      <p className="text-sm font-medium text-gray-900">{title}</p>
      {description && <p className="mt-1 text-sm text-gray-500">{description}</p>}
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  );
}

// Empty because of the reader's filters, not because nothing was collected.
// Names the active filters so the context is visible before it is cleared.
export function NoMatchesState({
  noun,
  activeFilters,
  onClear,
}: {
  noun: string;
  activeFilters: string[];
  onClear: () => void;
}) {
  return (
    <EmptyState
      title={`No ${noun} match the current filters`}
      description={`Active filters: ${activeFilters.join(' · ')}`}
      action={
        <button type="button" className={SECONDARY_BUTTON} onClick={onClear}>
          Clear filters
        </button>
      }
    />
  );
}

export function NotFoundState({
  title,
  message,
  backHref,
  backLabel,
}: {
  title: string;
  message: string;
  backHref: string;
  backLabel: string;
}) {
  return (
    <>
      <PageHeader title={title} backHref={backHref} backLabel={backLabel} />
      <PageBody>
        <StatusMessage tone="warning">
          <p className="font-medium">Not found</p>
          <p className="mt-1">{message}</p>
          <Link href={backHref} className={`mt-3 inline-block ${LINK}`}>
            {backLabel}
          </Link>
        </StatusMessage>
      </PageBody>
    </>
  );
}
