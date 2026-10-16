'use client';

import { useEffect } from 'react';
import { ErrorState } from '@/components/states';
import { PageBody, PageHeader } from '@/components/ui';

export default function ErrorPage({
  error,
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  useEffect(() => {
    console.error('Route render failed:', error);
  }, [error]);

  return (
    <>
      <PageHeader title="Something went wrong" backHref="/issues" backLabel="← Back to Issues" />
      <PageBody>
        <ErrorState error={error} onRetry={retry} />
      </PageBody>
    </>
  );
}
