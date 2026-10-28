'use client';

import { useEffect, useRef, useState } from 'react';
import { ApiError, getAccounts, getSession, searchAttackPaths } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import type {
  AccountSummary,
  AttackPathSearchResponse,
  AttackPathStart,
  AttackPathTarget,
} from '@/types';
import { AttackGraph } from '@/components/attack-graph';
import { ResourcePicker, type PickedResource } from '@/components/resource-picker';
import { ErrorState, LoadingState } from '@/components/states';
import { PageBody, PageHeader, SelectField, Spinner, StatusMessage } from '@/components/ui';

const STARTS: Array<{ value: AttackPathStart; label: string }> = [
  { value: 'any', label: 'Any entry point' },
  { value: 'internet', label: 'Internet-exposed resources' },
  { value: 'outside', label: 'Outside accounts' },
  { value: 'resource', label: 'A specific resource' },
];
const TARGETS: Array<{ value: AttackPathTarget; label: string }> = [
  { value: 'restricted', label: 'Restricted data' },
  { value: 'crown', label: 'Crown jewels' },
  { value: 'secrets', label: 'Secrets' },
  { value: 'admin', label: 'Admin roles' },
  { value: 'resource', label: 'A specific resource' },
];
const VERTEX_ID = /^arn:[\w-]{1,20}:[\w-]{0,40}:[\w-]{0,30}:\d{0,12}:[\x21-\x7e]{1,400}$/;
// Long enough to let a slider settle before querying Neptune.
const DEBOUNCE_MS = 400;

interface Query {
  // Nothing is preselected: the page searches once a start and a target are chosen.
  from: AttackPathStart | null;
  to: AttackPathTarget | null;
  fromResource: PickedResource | null;
  toResource: PickedResource | null;
  account: string;
  hops: number;
}

const tail = (id: string) => id.split(/[:/]/).pop() || id;
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;
const labelOf = <T extends string>(options: Array<{ value: T; label: string }>, value: T) =>
  options.find((option) => option.value === value)?.label ?? value;

function readQuery(): Query {
  const params = new URLSearchParams(window.location.search);
  const resource = (key: string) => {
    const id = params.get(key) ?? '';
    return VERTEX_ID.test(id) ? { id, name: tail(id) } : null;
  };
  const query: Query = {
    from: STARTS.find((o) => o.value === params.get('from'))?.value ?? null,
    to: TARGETS.find((o) => o.value === params.get('to'))?.value ?? null,
    fromResource: resource('fromResource'),
    toResource: resource('toResource'),
    account: /^\d{12}$/.test(params.get('account') ?? '') ? params.get('account')! : '',
    hops: /^\d{1,2}$/.test(params.get('hops') ?? '') ? Number(params.get('hops')) : 4,
  };
  // A resource start or end without its resource is no selection at all.
  if (query.from === 'resource' && !query.fromResource) query.from = null;
  if (query.to === 'resource' && !query.toResource) query.to = null;
  return query;
}

// Mirrors the search into the URL so it can be shared or bookmarked.
function writeQuery(query: Query): void {
  const params = new URLSearchParams();
  if (query.from) params.set('from', query.from);
  if (query.to) params.set('to', query.to);
  params.set('hops', String(query.hops));
  if (query.from === 'resource' && query.fromResource) {
    params.set('fromResource', query.fromResource.id);
  }
  if (query.to === 'resource' && query.toResource) params.set('toResource', query.toResource.id);
  if (query.account) params.set('account', query.account);
  window.history.replaceState(null, '', `${window.location.pathname}?${params}`);
}

const byAccount = (a: AccountSummary, b: AccountSummary) =>
  a.name && b.name
    ? a.name.localeCompare(b.name)
    : a.name
      ? -1
      : b.name
        ? 1
        : a.id.localeCompare(b.id);

export default function AttackPathsPage() {
  const session = useRequest((signal) => getSession({ signal }), []);
  const accounts = useRequest((signal) => getAccounts({ signal }), []);
  const [query, setQuery] = useState<Query | null>(null);
  const [results, setResults] = useState<AttackPathSearchResponse | null>(null);
  const [error, setError] = useState<unknown>(undefined);
  const [pending, setPending] = useState(false);
  const latest = useRef(0);

  // The API caps Viewers at 4 hops and Analysts at 10; the slider mirrors that.
  const role = session.status === 'success' ? session.data.role : null;
  const maxHops = role === 'Admin' || role === 'Analyst' ? 10 : 4;
  const accountList = accounts.status === 'success' ? accounts.data.accounts : [];
  const accountNames = Object.fromEntries(accountList.map((a) => [a.id, a.name]));

  // Restore from the URL once the caller's hop limit is known, then search.
  useEffect(() => {
    if (query || session.status === 'loading') return;
    const restored = readQuery();
    setQuery({ ...restored, hops: Math.min(Math.max(restored.hops, 1), maxHops) });
  }, [query, session.status, maxHops]);

  const ready =
    query !== null &&
    query.from !== null &&
    query.to !== null &&
    (query.from !== 'resource' || query.fromResource !== null) &&
    (query.to !== 'resource' || query.toResource !== null);

  // Results follow the filters: each change searches after a short pause, and
  // only the newest search may update the page.
  useEffect(() => {
    if (!query?.from || !query.to || !ready) return;
    const { from, to } = query;
    const id = ++latest.current;
    const timer = window.setTimeout(async () => {
      setPending(true);
      setError(undefined);
      try {
        const response = await searchAttackPaths({
          from,
          to,
          fromResource: query.from === 'resource' ? query.fromResource?.id : undefined,
          toResource: query.to === 'resource' ? query.toResource?.id : undefined,
          account: query.account || undefined,
          maxPathLength: query.hops,
        });
        if (id !== latest.current) return;
        setResults(response);
        writeQuery(query);
      } catch (failure) {
        if (id !== latest.current) return;
        // A failed search must not leave the previous graph looking current.
        setResults(null);
        setError(failure);
      } finally {
        if (id === latest.current) setPending(false);
      }
    }, DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [query, ready]);

  const update = (patch: Partial<Query>) =>
    setQuery((current) => (current ? { ...current, ...patch } : current));

  const fromLabel = (q: Query) =>
    q.from === 'resource' ? (q.fromResource?.name ?? 'a resource') : labelOf(STARTS, q.from ?? '');
  const toLabel = (q: Query) =>
    q.to === 'resource' ? (q.toResource?.name ?? 'a resource') : labelOf(TARGETS, q.to ?? '');

  return (
    <>
      <PageHeader
        title="Attack paths"
        description="How an attacker could get from an entry point to something that matters, across accounts."
      />
      <PageBody>
        <div className="overflow-hidden rounded-lg bg-white shadow">
          <div role="search" aria-label="Filters" className="border-b border-gray-200 p-4">
            {query && (
              <div className="flex flex-wrap items-end gap-3">
                <SelectField
                  label="Starting from"
                  className="w-56"
                  value={query.from ?? ''}
                  onChange={(e) => update({ from: (e.target.value || null) as Query['from'] })}
                >
                  <option value="">Choose a start</option>
                  {STARTS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </SelectField>
                <SelectField
                  label="Reaching"
                  className="w-56"
                  value={query.to ?? ''}
                  onChange={(e) => update({ to: (e.target.value || null) as Query['to'] })}
                >
                  <option value="">Choose a target</option>
                  {TARGETS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </SelectField>
                <SelectField
                  label="Account"
                  className="w-64"
                  value={query.account}
                  onChange={(e) => update({ account: e.target.value })}
                >
                  <option value="">All accounts</option>
                  {query.account && !accountList.some((a) => a.id === query.account) && (
                    <option value={query.account}>{query.account}</option>
                  )}
                  {[...accountList].sort(byAccount).map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name ? `${a.name} · ${a.id}` : a.id}
                    </option>
                  ))}
                </SelectField>
                <div className="w-40">
                  <span className="block text-sm font-medium text-gray-700">
                    Max hops · {query.hops}
                  </span>
                  <input
                    type="range"
                    min={1}
                    max={maxHops}
                    step={1}
                    value={query.hops}
                    aria-label="Max hops"
                    onChange={(e) => update({ hops: Number(e.target.value) })}
                    className="mt-2 w-full accent-indigo-600"
                  />
                </div>
                <p className="ml-auto flex items-center gap-2 self-center text-xs text-gray-500">
                  <span className="h-2 w-2 rounded-full bg-green-600" aria-hidden="true" />
                  Results update as you change filters
                </p>
              </div>
            )}
            {query && (query.from === 'resource' || query.to === 'resource') && (
              <div className="mt-4 grid gap-4 lg:grid-cols-2">
                {query.from === 'resource' && (
                  <ResourcePicker
                    label="Start at"
                    value={query.fromResource}
                    onChange={(resource) => update({ fromResource: resource })}
                  />
                )}
                {query.to === 'resource' && (
                  <ResourcePicker
                    label="End at"
                    value={query.toResource}
                    onChange={(resource) => update({ toResource: resource })}
                  />
                )}
              </div>
            )}
          </div>

          <section className="min-w-0" aria-busy={pending}>
            <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-sky-200 bg-sky-100 px-5 py-3">
              <h2 className="text-base font-semibold text-gray-900">
                {query?.from && query.to
                  ? `${fromLabel(query)} → ${toLabel(query)}`
                  : 'Attack paths'}
              </h2>
              {pending && (
                <span className="inline-flex items-center gap-1.5 text-sm text-gray-600">
                  <Spinner /> Updating…
                </span>
              )}
            </div>

            <div className={`p-4 ${pending && results ? 'opacity-50 transition-opacity' : ''}`}>
              {error instanceof ApiError && error.kind === 'timeout' ? (
                <StatusMessage tone="warning" className="mb-4">
                  This search took too long. Pick an account or fewer hops.
                </StatusMessage>
              ) : (
                error !== undefined && <ErrorState error={error} className="mb-4" />
              )}
              {query && !ready && (
                <p className="py-16 text-center text-sm text-gray-500">
                  {!query.from || !query.to
                    ? 'Pick a starting point and a target in the filters to search for paths.'
                    : 'Choose a resource in the filters to search from or to it.'}
                </p>
              )}
              {ready && !results && error === undefined && (
                <LoadingState label="Searching for paths…" />
              )}
              {ready && results?.truncated && (
                <StatusMessage tone="warning" className="mb-4">
                  Showing the first {plural(results.paths.length, 'path')}; more exist. Pick an
                  account or a narrower start or target to see the rest.
                </StatusMessage>
              )}
              {ready && results && (
                <p className="mb-3 text-xs text-gray-500" data-testid="coverage-note">
                  {results.coverage.note}
                </p>
              )}
              {ready && results && (
                <AttackGraph
                  paths={results.paths}
                  entries={results.entries}
                  accountNames={accountNames}
                  empty={`No path within ${plural(results.maxPathLength, 'hop')} matches. Try more hops or another account. Grants on Resource "*" are not traced to individual resources.`}
                />
              )}
            </div>
          </section>
        </div>
      </PageBody>
    </>
  );
}
