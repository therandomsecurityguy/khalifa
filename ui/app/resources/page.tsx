'use client';

import Link from 'next/link';
import { Suspense, useEffect, useState, type FormEvent } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  getResource,
  getResourceGraph,
  getPropertyValues,
  getResourceLabels,
  getResourceProperties,
  isNotFound,
  searchResources,
} from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { formatNodeLabel, nodeName } from '@/lib/graph-labels';
import { principalHref, resourceHref } from '@/lib/routes';
import type { GraphVertex, ResourceDetail } from '@/types';
import { GraphTable } from '@/components/graph-table';
import {
  EmptyState,
  ErrorState,
  LoadingState,
  NoMatchesState,
  NotFoundState,
} from '@/components/states';
import {
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  SECONDARY_BUTTON,
  SelectField,
  SeverityBadge,
  Spinner,
  Table,
  Td,
  TextField,
  Th,
} from '@/components/ui';

// Every label at once; the API accepts it only with a property filter.
const ALL_LABELS = '*';
const labelName = (label: string) => (label === ALL_LABELS ? 'All labels' : formatNodeLabel(label));
// A count set apart from its name in a dropdown option.
const withCount = (name: string, count: number) =>
  count > 0 ? `${name}\u00a0\u00a0(${count.toLocaleString('en-US')})` : name;
const PAGE_SIZE = 50;

function ResourceDetailView({ arn, depth }: { arn: string; depth: string }) {
  const router = useRouter();
  const params = useSearchParams();
  const detail = useRequest((signal) => getResource(arn, { signal }), [arn]);
  const graph = useRequest(
    (signal) => getResourceGraph(arn, Number(depth) || 2, { signal }),
    [arn, depth]
  );

  if (detail.status === 'error' && isNotFound(detail.error)) {
    return (
      <NotFoundState
        title="Resource"
        message="That resource is not in the graph."
        backHref="/resources"
        backLabel="← Back to explorer"
      />
    );
  }

  return (
    <>
      <PageHeader
        title="Resource"
        description="Properties, open issues, and a bounded neighbor graph."
        backHref="/resources"
        backLabel="← Back to explorer"
      />
      <PageBody>
        <div className="mb-6 flex flex-wrap items-end gap-3">
          <SelectField
            label="Graph depth"
            value={depth}
            onChange={(event) => {
              const next = new URLSearchParams(params.toString());
              next.set('depth', event.target.value);
              router.push(`/resources?${next.toString()}`);
            }}
          >
            <option value="0">0</option>
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3">3</option>
          </SelectField>
          {arn.includes(':iam:') && (
            <Link
              href={principalHref('/identity/effective-permissions', arn)}
              className={SECONDARY_BUTTON}
            >
              Identity
            </Link>
          )}
        </div>

        {detail.status === 'error' ? (
          <ErrorState error={detail.error} onRetry={detail.reload} />
        ) : detail.status !== 'success' ? (
          <LoadingState label="Loading resource…" />
        ) : (
          <div className="space-y-6">
            <ResourceProperties detail={detail.data} />
            {detail.data.issues.length > 0 && (
              <Card title="Open issues">
                <ul className="space-y-2">
                  {detail.data.issues.map((issue) => (
                    <li key={issue.id} className="flex items-center justify-between gap-3">
                      <Link href={`/issues/${issue.id}`} className={`text-sm ${LINK}`}>
                        {issue.ruleId}
                      </Link>
                      <SeverityBadge severity={issue.severity} />
                    </li>
                  ))}
                </ul>
              </Card>
            )}
            <section aria-busy={graph.status === 'loading'}>
              {graph.status === 'error' ? (
                <ErrorState error={graph.error} onRetry={graph.reload} />
              ) : graph.status !== 'success' ? (
                <LoadingState label="Loading neighbor graph…" />
              ) : (
                <GraphTable
                  nodes={graph.data.nodes}
                  edges={graph.data.edges}
                  empty="No neighbors within this depth."
                  origin={arn}
                />
              )}
            </section>
          </div>
        )}
      </PageBody>
    </>
  );
}

function ResourceProperties({ detail }: { detail: ResourceDetail }) {
  return (
    <Card title={formatNodeLabel(detail.resource.label)}>
      <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {Object.entries(detail.resource.properties ?? {}).map(([key, value]) => (
          <div key={key}>
            <dt className="text-xs font-medium uppercase tracking-wide text-gray-500">{key}</dt>
            <dd className="mt-1 break-all text-sm text-gray-900">
              {typeof value === 'object' ? JSON.stringify(value) : String(value)}
            </dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

function ResourceSearchView() {
  const router = useRouter();
  const params = useSearchParams();
  const query = {
    label: params.get('label') ?? ALL_LABELS,
    property: params.get('property') ?? '',
    value: params.get('value') ?? '',
  };
  const [form, setForm] = useState(query);
  const labels = useRequest((signal) => getResourceLabels({ signal }), []);
  // The current label always stays pickable, even before the list loads.
  const labelOptions = (() => {
    const known = [...(labels.status === 'success' ? labels.data.labels : [])].sort((a, b) =>
      labelName(a.label).localeCompare(labelName(b.label))
    );
    return form.label === ALL_LABELS || known.some((entry) => entry.label === form.label)
      ? known
      : [{ label: form.label, count: 0 }, ...known];
  })();
  const properties = useRequest(
    (signal) => getResourceProperties(form.label, { signal }),
    [form.label]
  );
  const propertyOptions = (() => {
    const known = properties.status === 'success' ? properties.data.properties : [];
    return !form.property || known.includes(form.property) ? known : [form.property, ...known];
  })();
  const values = useRequest(
    (signal) => getPropertyValues(form.label, form.property, { signal }),
    [form.label, form.property],
    { enabled: Boolean(form.property) }
  );
  // A property with a short list of values gets a dropdown; one with many
  // (names, ARNs) keeps a text box.
  const valueOptions =
    values.status === 'success' && !values.data.more && values.data.values.length > 0
      ? values.data.values.some((entry) => entry.value === form.value) || !form.value
        ? values.data.values
        : [{ value: form.value, count: 0 }, ...values.data.values]
      : null;
  const search = useRequest(
    (signal) =>
      searchResources(
        query.label,
        query.property || undefined,
        query.value || undefined,
        PAGE_SIZE,
        { signal }
      ),
    [query.label, query.property, query.value]
  );

  // Pages after the first, appended by "Load more"; a new search starts over.
  const [more, setMore] = useState<{ items: GraphVertex[]; nextToken?: string } | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState(false);
  useEffect(() => {
    setMore(null);
    setMoreError(false);
  }, [search.data]);
  const loaded =
    search.status === 'success' ? [...search.data.resources, ...(more?.items ?? [])] : [];
  const nextToken = more
    ? more.nextToken
    : search.status === 'success'
      ? search.data.nextToken
      : undefined;

  async function loadMore(): Promise<void> {
    if (!nextToken) return;
    setLoadingMore(true);
    setMoreError(false);
    try {
      const page = await searchResources(
        query.label,
        query.property || undefined,
        query.value || undefined,
        PAGE_SIZE,
        {},
        nextToken
      );
      setMore((previous) => ({
        items: [...(previous?.items ?? []), ...page.resources],
        nextToken: page.nextToken,
      }));
    } catch {
      setMoreError(true);
    } finally {
      setLoadingMore(false);
    }
  }

  const activeFilters = [
    query.property && `Property ${query.property}`,
    query.value && `Value ${query.value}`,
  ].filter((item): item is string => Boolean(item));

  function navigate(next: typeof query): void {
    const search = new URLSearchParams();
    search.set('label', next.label);
    if (next.property && next.value) {
      search.set('property', next.property);
      search.set('value', next.value);
    }
    router.push(`/resources?${search.toString()}`);
  }

  function submit(event: FormEvent): void {
    event.preventDefault();
    navigate(form);
  }

  return (
    <>
      <PageHeader
        title="Resource explorer"
        description="Search the graph by label and optional property filter."
      />
      <PageBody>
        <form
          onSubmit={submit}
          className="mb-6 grid grid-cols-1 gap-4 rounded-lg bg-white p-4 shadow md:grid-cols-4"
        >
          <div>
            <SelectField
              label="Label"
              value={form.label}
              hint={labels.status === 'loading' ? 'Counting labels…' : undefined}
              onChange={(event) => setForm({ label: event.target.value, property: '', value: '' })}
            >
              <option value={ALL_LABELS}>All labels</option>
              {labelOptions.map((entry) => (
                <option key={entry.label} value={entry.label}>
                  {withCount(labelName(entry.label), entry.count)}
                </option>
              ))}
            </SelectField>
            {labels.status === 'error' && (
              <p className="mt-1 text-xs text-red-700">
                Couldn&apos;t load the label list.{' '}
                <button type="button" className={LINK} onClick={labels.reload}>
                  Retry
                </button>
              </p>
            )}
          </div>
          <div>
            <SelectField
              label="Property"
              value={form.property}
              onChange={(event) => setForm({ ...form, property: event.target.value, value: '' })}
            >
              <option value="">Any property</option>
              {propertyOptions.map((property) => (
                <option key={property} value={property}>
                  {property}
                </option>
              ))}
            </SelectField>
            {properties.status === 'error' && (
              <p className="mt-1 text-xs text-red-700">
                Couldn&apos;t load the property list.{' '}
                <button type="button" className={LINK} onClick={properties.reload}>
                  Retry
                </button>
              </p>
            )}
          </div>
          {valueOptions ? (
            <SelectField
              label="Value"
              value={form.value}
              onChange={(event) => setForm({ ...form, value: event.target.value })}
            >
              <option value="">Choose a value</option>
              {valueOptions.map((entry) => (
                <option key={entry.value} value={entry.value}>
                  {withCount(
                    entry.name ? `${entry.name} · ${entry.value}` : entry.value,
                    entry.count
                  )}
                </option>
              ))}
            </SelectField>
          ) : (
            <TextField
              label="Value"
              value={form.value}
              disabled={!form.property}
              placeholder={form.property ? 'Type a value' : 'Pick a property first'}
              onChange={(event) => setForm({ ...form, value: event.target.value })}
            />
          )}
          <div className="flex items-end">
            <button
              type="submit"
              className={PRIMARY_BUTTON}
              disabled={Boolean(form.property) && !form.value}
            >
              Search
            </button>
          </div>
        </form>

        <div aria-busy={search.status === 'loading'}>
          {search.status === 'error' ? (
            <ErrorState error={search.error} onRetry={search.reload} />
          ) : search.status !== 'success' ? (
            <LoadingState label="Searching resources…" />
          ) : search.data.resources.length === 0 ? (
            <Card flush>
              {activeFilters.length > 0 ? (
                <NoMatchesState
                  noun={`${labelName(query.label)} resources`}
                  activeFilters={activeFilters}
                  onClear={() => {
                    const cleared = { ...query, property: '', value: '' };
                    setForm(cleared);
                    navigate(cleared);
                  }}
                />
              ) : (
                <EmptyState
                  title={`No ${labelName(query.label)} resources collected`}
                  description="Nothing with this label is in the graph yet. Check the label spelling or wait for the next collection."
                />
              )}
            </Card>
          ) : (
            <Card flush>
              <Table caption="Matching resources">
                <thead>
                  <tr>
                    <Th>Label</Th>
                    <Th>Name</Th>
                    <Th>ID</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {loaded.map((resource) => (
                    <tr key={resource.id}>
                      <Td className="whitespace-nowrap text-gray-500">
                        {formatNodeLabel(resource.label)}
                      </Td>
                      <Td className="whitespace-nowrap text-gray-900">{nodeName(resource)}</Td>
                      <Td>
                        <Link href={resourceHref(resource.id)} className={`break-all ${LINK}`}>
                          {resource.id}
                        </Link>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-gray-200 px-6 py-3 text-sm text-gray-500">
                <span className="tabular-nums">
                  Showing {loaded.length} {loaded.length === 1 ? 'resource' : 'resources'}
                </span>
                <span className="flex items-center gap-3">
                  {moreError && (
                    <span className="text-red-700">Could not load more. Try again.</span>
                  )}
                  {nextToken && (
                    <button
                      type="button"
                      className={SECONDARY_BUTTON}
                      disabled={loadingMore}
                      onClick={() => void loadMore()}
                    >
                      {loadingMore && <Spinner />}
                      {loadingMore ? 'Loading…' : 'Load more'}
                    </button>
                  )}
                </span>
              </div>
            </Card>
          )}
        </div>
      </PageBody>
    </>
  );
}

function ResourcesView() {
  const params = useSearchParams();
  const arn = params.get('arn') ?? '';
  const depth = params.get('depth') ?? '2';
  return arn ? <ResourceDetailView arn={arn} depth={depth} /> : <ResourceSearchView />;
}

export default function ResourcesPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading…" />}>
      <ResourcesView />
    </Suspense>
  );
}
