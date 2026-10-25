'use client';

import Link from 'next/link';
import { Fragment, useEffect, useMemo, useState } from 'react';
import { getAccounts, getSecretReaderCounts, getSecrets } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import {
  FACET_OPTIONS,
  SECRET_FILTERS,
  STALE_DAYS,
  compareSecrets,
  datesCollected,
  daysSince,
  isRotationOff,
  lastAccessedLabel,
  matchesFacets,
  matchesSearch,
  facetValues,
  severityCounts,
  sharingLabel,
  type SecretFacet,
  type SecretFilter,
} from '@/lib/secrets';
import { secretHref } from '@/lib/routes';
import type { SecretInventoryItem } from '@/types';
import { ColumnFilter, type FilterOption } from '@/components/column-filter';
import { SeverityCounts } from '@/components/severity-counts';
import { EmptyState, ErrorState, LoadingState, NoMatchesState } from '@/components/states';
import {
  Badge,
  Card,
  PageBody,
  PageHeader,
  SECONDARY_BUTTON,
  SelectField,
  StatusMessage,
  TONES,
  Table,
  Td,
  TextField,
  Th,
} from '@/components/ui';

const PAGE_SIZE = 30;
const KIND_LABEL: Record<SecretInventoryItem['kind'], string> = {
  'secrets-manager': 'Secrets Manager',
  'ssm-parameter': 'SSM SecureString',
  'ssm-plaintext': 'SSM String (plain text)',
};
const KIND_MIX: Array<{ kind: SecretInventoryItem['kind']; swatch: string }> = [
  { kind: 'secrets-manager', swatch: 'bg-indigo-600' },
  { kind: 'ssm-parameter', swatch: 'bg-indigo-300' },
  { kind: 'ssm-plaintext', swatch: 'bg-red-400' },
];

type Risk = Exclude<SecretFilter, 'all'>;
const RISK_GROUPS: Array<{
  title: string;
  risks: Array<{
    key: Risk;
    label: string;
    number: string;
    bar: string;
    needsDates?: boolean;
  }>;
}> = [
  {
    title: 'Rotation and use',
    risks: [
      { key: 'rotationOff', label: 'Rotation off', number: 'text-red-700', bar: 'bg-red-500' },
      {
        key: 'stale',
        label: `Not rotated in ${STALE_DAYS}+ days`,
        number: 'text-orange-700',
        bar: 'bg-orange-400',
        needsDates: true,
      },
      {
        key: 'unused',
        label: `Unused ${STALE_DAYS}+ days`,
        number: 'text-orange-700',
        bar: 'bg-orange-400',
        needsDates: true,
      },
    ],
  },
  {
    title: 'Exposure',
    risks: [
      {
        key: 'plaintext',
        label: 'Possibly unencrypted secrets',
        number: 'text-red-700',
        bar: 'bg-red-500',
      },
      {
        key: 'outside',
        label: 'Shared outside the org',
        number: 'text-red-700',
        bar: 'bg-red-500',
      },
      {
        key: 'shared',
        label: 'Shared across accounts',
        number: 'text-yellow-700',
        bar: 'bg-yellow-400',
      },
      { key: 'issues', label: 'With open issues', number: 'text-red-700', bar: 'bg-red-500' },
    ],
  },
];
const RISK_LABEL = Object.fromEntries(
  RISK_GROUPS.flatMap((group) => group.risks.map((risk) => [risk.key, risk.label]))
) as Record<Risk, string>;

// Account is filtered from the toolbar, next to search and region.
// Account is filtered from the toolbar, so it has no funnel. Env, owner and
// encryption are on the secret's own page.
const COLUMNS: Array<{ key: string; label: string; width: string; facet?: SecretFacet }> = [
  { key: 'secret', label: 'Secret', width: 'w-[22%]', facet: 'type' },
  { key: 'account', label: 'Account', width: 'w-[12%]' },
  { key: 'created', label: 'Created', width: 'w-[10%]' },
  { key: 'rotation', label: 'Rotation', width: 'w-[12%]', facet: 'rotation' },
  { key: 'access', label: 'Last accessed', width: 'w-[9%]', facet: 'access' },
  { key: 'sharing', label: 'Shared with', width: 'w-[12%]', facet: 'sharing' },
  { key: 'readers', label: 'Readable by', width: 'w-[11%]', facet: 'readers' },
  { key: 'issues', label: 'Open issues', width: 'w-[12%]', facet: 'issues' },
];

const SUMMARY_BUTTON =
  'rounded-lg border border-transparent text-left transition-colors hover:border-gray-200 hover:bg-gray-50 aria-pressed:border-indigo-200 aria-pressed:bg-indigo-50 disabled:cursor-not-allowed disabled:hover:border-transparent disabled:hover:bg-transparent';

// The bar is to scale against all secrets; any count above zero keeps a sliver.
function barWidth(count: number, total: number): string {
  return `${count && total ? Math.max((count / total) * 100, 1.2) : 0}%`;
}

function Summary({
  items,
  now,
  filter,
  onFilter,
  dated,
}: {
  items: SecretInventoryItem[];
  now: number;
  filter: SecretFilter;
  onFilter: (filter: SecretFilter) => void;
  dated: boolean;
}) {
  const total = items.length;
  const mix = KIND_MIX.map((entry) => ({
    ...entry,
    count: items.filter((item) => item.kind === entry.kind).length,
  })).filter((entry) => entry.count > 0);
  return (
    <div
      role="group"
      aria-label="Filter secrets"
      className="mb-6 grid grid-cols-1 rounded-xl border border-gray-200 bg-white shadow-sm lg:grid-cols-[17.5rem_1fr_1fr]"
    >
      <button
        type="button"
        aria-pressed={filter === 'all'}
        onClick={() => onFilter('all')}
        className={`${SUMMARY_BUTTON} m-2 flex flex-col items-start justify-center gap-3 px-4 py-5`}
      >
        <span className="text-xs font-semibold uppercase tracking-wider text-gray-500">
          All secrets
        </span>
        <span className="text-5xl font-bold tabular-nums leading-none text-gray-900">
          {total.toLocaleString('en-US')}
        </span>
        <span
          aria-hidden="true"
          className="flex h-2 w-full overflow-hidden rounded-full bg-gray-100"
        >
          {mix.map((entry) => (
            <span
              key={entry.kind}
              className={`h-full ${entry.swatch}`}
              style={{ width: barWidth(entry.count, total) }}
            />
          ))}
        </span>
        <span className="flex w-full flex-col gap-1.5 text-sm text-gray-600">
          {mix.map((entry) => (
            <span key={entry.kind} className="flex items-center gap-2">
              <span aria-hidden="true" className={`h-2.5 w-2.5 rounded-sm ${entry.swatch}`} />
              {KIND_LABEL[entry.kind]}
              <span className="ml-auto font-semibold tabular-nums text-gray-900">
                {entry.count.toLocaleString('en-US')}
              </span>
            </span>
          ))}
        </span>
      </button>
      {RISK_GROUPS.map((group) => (
        <div
          key={group.title}
          className="flex min-w-0 flex-col gap-0.5 border-t border-gray-200 p-4 lg:border-l lg:border-t-0"
        >
          <span className="mb-2 ml-3 mt-1 text-xs font-semibold uppercase tracking-wider text-gray-500">
            {group.title}
          </span>
          {group.risks.map((risk) => {
            const pending = risk.needsDates && !dated;
            const count = items.filter((item) => SECRET_FILTERS[risk.key](item, now)).length;
            return (
              <button
                key={risk.key}
                type="button"
                aria-pressed={filter === risk.key}
                disabled={pending}
                title={pending ? 'Fills in after the next collection run' : undefined}
                onClick={() => onFilter(filter === risk.key ? 'all' : risk.key)}
                className={`${SUMMARY_BUTTON} flex flex-col gap-2 px-3 py-2.5`}
              >
                <span className="flex items-baseline justify-between gap-3">
                  <span className="text-sm font-medium text-gray-900">{risk.label}</span>
                  <span
                    className={`text-2xl font-bold tabular-nums leading-none ${
                      pending ? 'text-gray-400' : risk.number
                    }`}
                  >
                    {pending ? '—' : count.toLocaleString('en-US')}
                  </span>
                </span>
                <span aria-hidden="true" className="h-2 overflow-hidden rounded-full bg-gray-100">
                  {!pending && (
                    <span
                      className={`block h-full rounded-full ${risk.bar}`}
                      style={{ width: barWidth(count, total) }}
                    />
                  )}
                </span>
              </button>
            );
          })}
        </div>
      ))}
    </div>
  );
}

function Rotation({ item, now }: { item: SecretInventoryItem; now: number }) {
  if (item.kind !== 'secrets-manager') {
    const modified = daysSince(item.lastModified, now);
    return (
      <>
        <Badge tone={TONES.neutral}>No rotation</Badge>
        {modified !== null && (
          <div className="mt-1 text-xs text-gray-500">Modified {modified} days ago</div>
        )}
      </>
    );
  }
  const rotated = daysSince(item.lastRotated, now);
  const off = isRotationOff(item);
  // Off says enough on its own; on but never rotated usually means it is failing.
  const note = rotated !== null ? `Rotated ${rotated} days ago` : off ? null : 'Never rotated';
  return (
    <>
      <Badge tone={off ? TONES.danger : TONES.success}>{off ? 'Off' : 'On'}</Badge>
      {note && <div className="mt-1 text-xs text-gray-500">{note}</div>}
    </>
  );
}

const CREATED = new Intl.DateTimeFormat('en-US', {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
});

// Secrets Manager reports creation; Parameter Store does not, so parameters
// show a dash, as do secrets before the collector recorded dates.
function Created({ item, now }: { item: SecretInventoryItem; now: number }) {
  const days = daysSince(item.createdAt, now);
  if (!item.createdAt || days === null) return <span className="text-gray-400">—</span>;
  return (
    <>
      <div className="whitespace-nowrap">{CREATED.format(new Date(item.createdAt))}</div>
      <div className="text-xs text-gray-500">{days === 0 ? 'Today' : `${days} days ago`}</div>
    </>
  );
}

function ReadableBy({ item }: { item: SecretInventoryItem }) {
  if (item.readers === undefined && item.kind === 'secrets-manager') {
    return (
      <span className="text-gray-400">
        <span aria-hidden="true">…</span>
        <span className="sr-only">Counting</span>
      </span>
    );
  }
  if (!item.readers) return <span className="text-gray-400">—</span>;
  return (
    <Link
      href={`${secretHref(item.id)}#readers`}
      aria-label={`${item.readers.partial ? 'At least ' : ''}${item.readers.total} principals can read ${item.name}${
        item.readers.broad ? `, ${item.readers.broad} broadly` : ''
      }`}
      title={item.readers.partial ? 'At least this many: not every policy was read' : undefined}
      className="block hover:underline"
    >
      <span className="font-semibold tabular-nums text-gray-900">
        {item.readers.partial && '≥'}
        {item.readers.total}
      </span>
      {item.readers.broad > 0 && (
        <span className="block text-xs text-orange-700">{item.readers.broad} broad</span>
      )}
    </Link>
  );
}

function sharingTone(item: SecretInventoryItem): string {
  if (item.sharing?.scope === 'outside') return TONES.danger;
  if (item.sharing?.scope === 'org' || item.sharing?.scope === 'collected') return TONES.warning;
  return TONES.neutral;
}

// Breaks a path-like name only after a slash, never mid-word.
function SecretName({ name }: { name: string }) {
  const parts = name.split('/');
  return (
    <>
      {parts.map((part, index) => (
        <Fragment key={index}>
          {part}
          {index < parts.length - 1 && (
            <>
              /<wbr />
            </>
          )}
        </Fragment>
      ))}
    </>
  );
}

function SecretRow({
  item,
  accountName,
  now,
}: {
  item: SecretInventoryItem;
  accountName: string;
  now: number;
}) {
  const counts = severityCounts(item);
  const access = lastAccessedLabel(item, now);
  return (
    <tr>
      <Td className="align-top">
        <Link
          href={secretHref(item.id)}
          aria-label={item.name}
          className="font-medium text-indigo-600 [overflow-wrap:anywhere] hover:text-indigo-900"
        >
          <SecretName name={item.name} />
        </Link>
        {/* The Plain text badge below says the rest. */}
        <div className="text-xs text-gray-500">
          {item.kind === 'ssm-plaintext' ? 'SSM String' : KIND_LABEL[item.kind]}
        </div>
        {item.kind === 'ssm-plaintext' && (
          <div className="mt-1">
            <Badge tone={TONES.danger}>Plain text</Badge>
          </div>
        )}
        {item.collectionRestricted && (
          <div className="mt-1">
            <Badge tone={TONES.warning}>Policy unreadable</Badge>
          </div>
        )}
      </Td>
      <Td className="align-top">
        <div className="[overflow-wrap:anywhere]">{accountName}</div>
        <div className="text-xs text-gray-500">{item.region}</div>
      </Td>
      <Td className="align-top">
        <Created item={item} now={now} />
      </Td>
      <Td className="align-top">
        <Rotation item={item} now={now} />
      </Td>
      <Td className="align-top">
        {access === 'Not collected yet' ? <span className="text-gray-400">—</span> : access}
      </Td>
      <Td className="align-top">
        <Badge tone={sharingTone(item)}>{sharingLabel(item)}</Badge>
      </Td>
      <Td className="align-top">
        <ReadableBy item={item} />
      </Td>
      <Td className="align-top">
        {counts.length === 0 ? (
          <span className="text-gray-400">—</span>
        ) : (
          <Link href={secretHref(item.id)} className="inline-flex rounded-full">
            <SeverityCounts counts={counts} />
          </Link>
        )}
      </Td>
    </tr>
  );
}

export default function SecretsPage() {
  const secrets = useRequest((signal) => getSecrets({ signal }), []);
  const readerCounts = useRequest((signal) => getSecretReaderCounts({ signal }), []);
  const accounts = useRequest((signal) => getAccounts({ signal }), []);
  const [filter, setFilter] = useState<SecretFilter>('all');
  const [search, setSearch] = useState('');
  const [account, setAccount] = useState('');
  const [region, setRegion] = useState('');
  const [facets, setFacets] = useState<Partial<Record<SecretFacet, string[]>>>({});
  const [page, setPage] = useState(1);
  const [now] = useState(() => Date.now());

  const accountNames = useMemo(
    () =>
      new Map(
        (accounts.status === 'success' ? accounts.data.accounts : []).map((a) => [a.id, a.name])
      ),
    [accounts]
  );
  // Counts arrive separately; until then a secret's readers stay undefined.
  const items = useMemo(() => {
    if (secrets.status !== 'success') return [];
    const counts = readerCounts.status === 'success' ? readerCounts.data.counts : null;
    return secrets.data.items
      .map((item) => ({
        ...item,
        readers:
          item.kind !== 'secrets-manager'
            ? null
            : readerCounts.status === 'loading'
              ? undefined
              : counts && Object.hasOwn(counts, item.id)
                ? counts[item.id]
                : null,
      }))
      .sort(compareSecrets);
  }, [secrets, readerCounts]);
  const dated = datesCollected(items);
  const query = search.trim().toLowerCase();
  const accountName = (id: string) => accountNames.get(id) || id;
  const base = items.filter(
    (item) =>
      SECRET_FILTERS[filter](item, now) &&
      (!account || item.accountId === account) &&
      (!region || item.region === region) &&
      matchesSearch(item, query, accountName(item.accountId))
  );
  const matches = base.filter((item) => matchesFacets(item, facets, now));
  useEffect(() => setPage(1), [filter, search, account, region, facets]);
  const pages = Math.max(1, Math.ceil(matches.length / PAGE_SIZE));
  // A shorter result after a reload can leave the page past the end.
  const current = Math.min(page, pages);
  const first = (current - 1) * PAGE_SIZE;
  const last = Math.min(first + PAGE_SIZE, matches.length);
  const accountOptions = [...new Set(items.map((item) => item.accountId))]
    .map((id) => ({ value: id, label: accountName(id) }))
    .sort((a, b) => a.label.localeCompare(b.label));
  const regionOptions = [...new Set(items.map((item) => item.region))].filter(Boolean).sort();
  function optionLabel(facet: SecretFacet, value: string): string {
    return FACET_OPTIONS[facet].find((option) => option.value === value)?.label ?? value;
  }
  function optionsFor(facet: SecretFacet): FilterOption[] {
    const pool = base.filter((item) => matchesFacets(item, facets, now, facet));
    return FACET_OPTIONS[facet].map((option) => ({
      ...option,
      count: pool.filter((item) => facetValues(facet, item, now).includes(option.value)).length,
    }));
  }
  function setFacet(facet: SecretFacet, values: string[]): void {
    setFacets((previous) => ({ ...previous, [facet]: values }));
  }

  const chips = COLUMNS.flatMap(({ facet, label }) =>
    !facet
      ? []
      : (facets[facet] ?? []).map((value) => ({
          facet,
          value,
          label: `${label}: ${optionLabel(facet, value)}`,
        }))
  );
  const activeFilters = [
    filter !== 'all' ? RISK_LABEL[filter] : '',
    query ? `Search "${search.trim()}"` : '',
    account ? `Account ${accountName(account)}` : '',
    region ? `Region ${region}` : '',
    ...chips.map((chip) => chip.label),
  ].filter(Boolean);
  function clear(): void {
    setFilter('all');
    setSearch('');
    setAccount('');
    setRegion('');
    setFacets({});
  }

  const header = (
    <thead>
      <tr>
        {COLUMNS.map(({ key, facet, label }) => (
          <Th key={key} className="px-4">
            {!facet ? (
              label
            ) : (
              <ColumnFilter
                label={label}
                options={optionsFor(facet)}
                selected={facets[facet] ?? []}
                onChange={(values) => setFacet(facet, values)}
              />
            )}
          </Th>
        ))}
      </tr>
    </thead>
  );

  let rows;
  if (matches.length === 0) {
    rows = (
      <tr>
        <Td colSpan={COLUMNS.length}>
          <NoMatchesState noun="secrets" activeFilters={activeFilters} onClear={clear} />
        </Td>
      </tr>
    );
  } else {
    rows = matches
      .slice(first, last)
      .map((item) => (
        <SecretRow key={item.id} item={item} accountName={accountName(item.accountId)} now={now} />
      ));
  }

  let body;
  if (secrets.status === 'error') {
    body = <ErrorState error={secrets.error} onRetry={secrets.reload} className="m-4" />;
  } else if (secrets.status !== 'success') {
    body = <LoadingState label="Loading secrets…" />;
  } else if (items.length === 0) {
    body = (
      <EmptyState
        title="No secrets collected"
        description="No Secrets Manager secrets or SecureString parameters are in the graph yet."
      />
    );
  } else {
    body = (
      <>
        <Table caption="Secrets" className="min-w-[76rem] table-fixed">
          <colgroup>
            {COLUMNS.map(({ key, width }) => (
              <col key={key} className={width} />
            ))}
          </colgroup>
          {header}
          <tbody className="divide-y divide-gray-200 bg-white">{rows}</tbody>
        </Table>
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-gray-200 px-6 py-3 text-sm text-gray-600">
          <span className="tabular-nums">
            Showing {pages > 1 ? `${first + 1}–${last}` : matches.length} of {matches.length}{' '}
            {matches.length === 1 ? 'secret' : 'secrets'}
          </span>
          {pages > 1 && (
            <nav aria-label="Pages" className="flex items-center gap-3">
              <button
                type="button"
                className={SECONDARY_BUTTON}
                disabled={current === 1}
                onClick={() => setPage(current - 1)}
              >
                Previous
              </button>
              <span className="tabular-nums" aria-live="polite">
                Page {current} of {pages}
              </span>
              <button
                type="button"
                className={SECONDARY_BUTTON}
                disabled={current === pages}
                onClick={() => setPage(current + 1)}
              >
                Next
              </button>
            </nav>
          )}
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Secrets"
        description="Secrets Manager secrets and SecureString parameters across collected accounts: rotation, how each is shared, and open issues. Metadata only; Khalifa never reads secret values."
      />
      <PageBody>
        {secrets.status === 'success' && secrets.data.truncated && (
          <StatusMessage tone="warning" className="mb-4">
            More secrets exist than this page loads; some are not shown.
          </StatusMessage>
        )}
        {secrets.status === 'success' && secrets.data.issuesUnavailable && (
          <StatusMessage tone="warning" className="mb-4">
            Open issues could not be loaded, so issue counts may be incomplete.
          </StatusMessage>
        )}
        {readerCounts.status === 'error' && (
          <StatusMessage tone="warning" className="mb-4">
            Readers could not be counted, so Readable by shows a dash.
          </StatusMessage>
        )}
        {readerCounts.status === 'success' && readerCounts.data.unavailableAccounts > 0 && (
          <StatusMessage tone="warning" className="mb-4">
            Readers could not be counted for {readerCounts.data.unavailableAccounts}{' '}
            {readerCounts.data.unavailableAccounts === 1 ? 'account' : 'accounts'}; their secrets
            show a dash.
          </StatusMessage>
        )}
        {secrets.status === 'success' && items.length > 0 && !dated && (
          <StatusMessage tone="info" className="mb-4">
            Rotation ages and last access fill in after the next collection run. Until then, those
            counts show a dash.
          </StatusMessage>
        )}

        {secrets.status === 'success' && items.length > 0 && (
          <Summary items={items} now={now} filter={filter} onFilter={setFilter} dated={dated} />
        )}

        <Card flush>
          {secrets.status === 'success' && items.length > 0 && (
            <div className="grid grid-cols-1 gap-4 border-b border-gray-200 p-4 md:grid-cols-[minmax(0,2fr)_minmax(0,1fr)_minmax(0,1fr)]">
              <TextField
                label="Search"
                type="search"
                placeholder="Name, ARN, account, owner or env"
                value={search}
                maxLength={200}
                onChange={(event) => setSearch(event.target.value)}
              />
              <SelectField
                label="Account"
                value={account}
                onChange={(event) => setAccount(event.target.value)}
              >
                <option value="">All accounts</option>
                {accountOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </SelectField>
              <SelectField
                label="Region"
                value={region}
                onChange={(event) => setRegion(event.target.value)}
              >
                <option value="">All regions</option>
                {regionOptions.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </SelectField>
            </div>
          )}
          {chips.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 border-b border-gray-200 px-4 py-3">
              {chips.map((chip) => (
                <button
                  key={`${chip.facet}:${chip.value}`}
                  type="button"
                  onClick={() =>
                    setFacet(
                      chip.facet,
                      (facets[chip.facet] ?? []).filter((value) => value !== chip.value)
                    )
                  }
                  aria-label={`Remove filter: ${chip.label}`}
                  className="inline-flex items-center gap-1 rounded-full border border-indigo-500 bg-indigo-50 px-3 py-0.5 text-xs font-medium text-indigo-800 hover:bg-indigo-100"
                >
                  {chip.label}
                  <span aria-hidden="true">×</span>
                </button>
              ))}
              <button
                type="button"
                className="text-sm font-medium text-indigo-600 hover:text-indigo-900"
                onClick={() => setFacets({})}
              >
                Clear all filters
              </button>
            </div>
          )}
          <div aria-busy={secrets.status === 'loading'}>{body}</div>
        </Card>
      </PageBody>
    </>
  );
}
