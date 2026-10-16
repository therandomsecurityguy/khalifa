'use client';

import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { getTrustGraph } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { GraphTable } from '@/components/graph-table';
import { EmptyState, ErrorState, LoadingState, NoMatchesState } from '@/components/states';
import { PageBody, PageHeader, PRIMARY_BUTTON, TextField } from '@/components/ui';

function TrustGraphView() {
  const router = useRouter();
  const params = useSearchParams();
  const accountFilter = params.get('account') ?? '';
  const limitFilter = params.get('limit') ?? '100';
  const [account, setAccount] = useState(accountFilter);
  const [limit, setLimit] = useState(limitFilter);
  const graph = useRequest(
    (signal) =>
      getTrustGraph({ account: accountFilter, limit: Number(limitFilter) || 100 }, { signal }),
    [accountFilter, limitFilter]
  );

  function navigate(nextAccount: string, nextLimit: string): void {
    const next = new URLSearchParams();
    if (nextAccount) next.set('account', nextAccount);
    next.set('limit', nextLimit);
    router.push(`/identity/trust-graph?${next.toString()}`);
  }

  return (
    <>
      <PageHeader
        title="Trust graph"
        backHref="/identity"
        backLabel="← Back to Identity"
        description="IAM TRUSTS edges, capped at 200 nodes per page."
      />
      <PageBody>
        <form
          className="mb-6 flex flex-wrap items-end gap-4 rounded-lg bg-white p-4 shadow"
          onSubmit={(event) => {
            event.preventDefault();
            navigate(account, limit);
          }}
        >
          <TextField
            label="Account"
            value={account}
            onChange={(event) => setAccount(event.target.value)}
          />
          <TextField
            label="Limit"
            type="number"
            min={1}
            max={200}
            value={limit}
            onChange={(event) => setLimit(event.target.value)}
          />
          <button type="submit" className={PRIMARY_BUTTON}>
            Load
          </button>
        </form>
        <div aria-busy={graph.status === 'loading'}>
          {graph.status === 'error' ? (
            <ErrorState error={graph.error} onRetry={graph.reload} />
          ) : graph.status !== 'success' ? (
            <LoadingState label="Loading trust graph…" />
          ) : graph.data.nodes.length === 0 && graph.data.edges.length === 0 ? (
            accountFilter ? (
              <NoMatchesState
                noun="trust relationships"
                activeFilters={[`Account ${accountFilter}`]}
                onClear={() => {
                  setAccount('');
                  navigate('', limit);
                }}
              />
            ) : (
              <EmptyState
                title="No trust relationships collected"
                description="No IAM TRUSTS edges are in the graph yet."
              />
            )
          ) : (
            <>
              <GraphTable nodes={graph.data.nodes} edges={graph.data.edges} empty="" />
              {graph.data.nextToken && (
                <p className="mt-4 text-sm text-gray-500">More results available.</p>
              )}
            </>
          )}
        </div>
      </PageBody>
    </>
  );
}

export default function TrustGraphPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading…" />}>
      <TrustGraphView />
    </Suspense>
  );
}
