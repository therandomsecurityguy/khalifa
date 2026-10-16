'use client';

import { Suspense, type ReactNode } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useState } from 'react';
import { isNotFound, type RequestOptions } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { principalHref } from '@/lib/routes';
import { PrincipalForm } from '@/components/principal-form';
import { EmptyState, ErrorState, LoadingState, NotFoundState } from '@/components/states';
import { PageBody, PageHeader } from '@/components/ui';

const BACK = { backHref: '/identity', backLabel: '← Back to Identity' };

// Shared frame for the identity pages that look up one principal from the
// `principal` query parameter: form, request lifecycle, and not-found copy.
export function PrincipalLookup<T>({
  title,
  path,
  load,
  prompt,
  children,
}: {
  title: string;
  path: string;
  load: (principal: string, options: RequestOptions) => Promise<T>;
  prompt: string;
  children: (data: T) => ReactNode;
}) {
  return (
    <Suspense fallback={<LoadingState label="Loading…" />}>
      <PrincipalLookupView title={title} path={path} load={load} prompt={prompt}>
        {children}
      </PrincipalLookupView>
    </Suspense>
  );
}

function PrincipalLookupView<T>({
  title,
  path,
  load,
  prompt,
  children,
}: {
  title: string;
  path: string;
  load: (principal: string, options: RequestOptions) => Promise<T>;
  prompt: string;
  children: (data: T) => ReactNode;
}) {
  const router = useRouter();
  const params = useSearchParams();
  const selected = params.get('principal') ?? '';
  const [principal, setPrincipal] = useState(selected);
  const result = useRequest((signal) => load(selected, { signal }), [selected], {
    enabled: Boolean(selected),
  });

  if (result.status === 'error' && isNotFound(result.error)) {
    return <NotFoundState title={title} message="That principal is not in the graph." {...BACK} />;
  }

  return (
    <>
      <PageHeader title={title} {...BACK} />
      <PageBody>
        <PrincipalForm
          principal={principal}
          onPrincipalChange={setPrincipal}
          onSubmit={() => router.push(principalHref(path, principal))}
        />
        <div aria-busy={result.status === 'loading'}>
          {result.status === 'error' ? (
            <ErrorState error={result.error} onRetry={result.reload} />
          ) : result.status === 'loading' ? (
            <LoadingState label={`Loading ${title.toLowerCase()}…`} />
          ) : result.status === 'idle' ? (
            <EmptyState title={prompt} />
          ) : (
            children(result.data)
          )}
        </div>
      </PageBody>
    </>
  );
}
