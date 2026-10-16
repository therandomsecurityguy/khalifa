'use client';

import Link from 'next/link';
import { Fragment, useState } from 'react';
import { getDataSources } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import type {
  AccountCoverage,
  DetectionCoverage,
  DetectionState,
  JobOutput,
  ServiceCoverage,
} from '@/types';
import { ErrorState, LoadingState } from '@/components/states';
import { Badge, LINK, PageBody, PageHeader, TONES, Table, Td, Th } from '@/components/ui';

type Section = 'attention' | 'accounts' | 'services' | 'detection' | 'jobs';

const SOURCES: Array<[keyof DetectionCoverage, string, string]> = [
  ['securityHub', 'Security Hub', 'Truncated: more active findings than one run collects.'],
  ['guardDuty', 'GuardDuty', 'Missing: no detector in the collected region (RULE-017).'],
  ['config', 'AWS Config', 'Off: recorder stopped (RULE-028); missing: no recorder.'],
  ['accessAnalyzer', 'Access Analyzer', 'Missing: no account analyzer (RULE-025).'],
];
const STATE_LABEL: Record<DetectionState, string> = {
  on: 'On',
  truncated: 'Truncated',
  off: 'Off',
  missing: 'Missing',
  unknown: 'Unknown: the check failed',
};

type JobStatus = 'on-time' | 'overdue' | 'quiet' | 'none';
// Late is more than twice the schedule; a job that writes only on findings is
// quiet rather than broken when it has nothing recent.
function jobStatus(job: JobOutput): JobStatus {
  const recent =
    job.lastOutputAt !== null &&
    Date.now() - Date.parse(job.lastOutputAt) <= job.everyHours * 2 * 3_600_000;
  if (recent) return 'on-time';
  if (job.quietWhenClean) return 'quiet';
  return job.lastOutputAt ? 'overdue' : 'none';
}
const every = (hours: number) => (hours === 24 ? 'Daily' : `Every ${hours}h`);

const fmt = (n: number) => n.toLocaleString('en-US');

function ago(at: string | null): string {
  if (!at) return 'never';
  const minutes = Math.max(0, Math.round((Date.now() - Date.parse(at)) / 60_000));
  if (minutes < 60) return `${minutes}m ago`;
  if (minutes < 48 * 60) return `${Math.round(minutes / 60)}h ago`;
  return `${Math.round(minutes / (24 * 60))}d ago`;
}

const accountName = (a: AccountCoverage) => a.name || a.id;
const failed = (s: ServiceCoverage) => s.status === 'FAILED';

function Mark({ ok }: { ok: boolean }) {
  return ok ? (
    <span className="text-green-700" aria-label="Collected">
      ✓
    </span>
  ) : (
    <span className="text-red-700" aria-label="Failed">
      ✕
    </span>
  );
}

function Stat({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div className="bg-white px-5 py-4">
      <dt className="text-xs font-medium uppercase tracking-wider text-gray-500">{label}</dt>
      <dd className="mt-1 text-2xl font-semibold tabular-nums text-gray-900">{value}</dd>
      <dd className="text-xs text-gray-500">{note}</dd>
    </div>
  );
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="overflow-hidden rounded-lg bg-white shadow">
      <h2 className="border-b border-sky-200 bg-sky-100 px-6 py-3 text-base font-medium text-gray-900">
        {title}
      </h2>
      {children}
    </section>
  );
}

// Rows that expand in place; several can be open at once.
function useOpenRows() {
  const [open, setOpen] = useState<Set<string>>(new Set());
  const toggle = (key: string) =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  const show = (key: string) => setOpen((current) => new Set(current).add(key));
  return { open, toggle, show };
}

function ExpandButton({
  open,
  onClick,
  children,
}: {
  open: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      aria-expanded={open}
      onClick={onClick}
      className="flex items-start gap-2 text-left"
    >
      <span className="w-3 text-gray-400" aria-hidden="true">
        {open ? '▾' : '▸'}
      </span>
      <span>{children}</span>
    </button>
  );
}

function Attention({
  accounts,
  jobs,
  onOpen,
  onSection,
}: {
  accounts: AccountCoverage[];
  jobs: JobOutput[];
  onOpen: (accountId: string) => void;
  onSection: (section: Section) => void;
}) {
  const failures = accounts.flatMap((a) =>
    a.services.filter(failed).map((service) => ({ account: a, service }))
  );
  const uncollected = accounts.filter((a) => a.status === 'not-collected');
  const truncated = accounts.filter((a) => a.detection.securityHub === 'truncated').length;
  const late = jobs.filter((job) => ['overdue', 'none'].includes(jobStatus(job)));
  if (!failures.length && !uncollected.length && !truncated && !late.length) {
    return (
      <p className="px-6 py-4 text-sm text-gray-500">
        Every account collected every service on its last run.
      </p>
    );
  }
  return (
    <div className="divide-y divide-gray-200">
      {failures.length > 0 && (
        <section className="px-6 py-4">
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Collection failing · {failures.length}
          </h3>
          <p className="mb-3 text-sm text-gray-500">
            Stale data in these accounts is not removed until the service succeeds.
          </p>
          <div className="overflow-hidden rounded-md border border-gray-200">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50 text-left text-xs font-medium text-gray-500">
                <tr>
                  <th className="px-4 py-2">Account</th>
                  <th className="px-4 py-2">Service</th>
                  <th className="px-4 py-2">Error</th>
                  <th className="px-4 py-2">Last success</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {failures.map(({ account, service }) => (
                  <tr key={`${account.id}/${service.service}/${service.region}`}>
                    <td className="px-4 py-2.5">
                      <span className="font-medium text-gray-900">{accountName(account)}</span>{' '}
                      <span className="font-mono text-xs text-gray-500">{account.id}</span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-gray-800">
                      {service.service}
                    </td>
                    <td className="px-4 py-2.5 text-red-700">
                      {service.error || service.failureType || 'Failed'}
                    </td>
                    <td className="px-4 py-2.5 text-gray-500">{ago(service.lastSuccessAt)}</td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        type="button"
                        className={`text-sm ${LINK}`}
                        onClick={() => onOpen(account.id)}
                      >
                        Open →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {truncated > 0 && (
        <section className="flex items-start justify-between gap-3 px-6 py-4">
          <div>
            <p className="text-sm font-medium text-gray-900">
              Security Hub findings truncated in {truncated} of {accounts.length} accounts
            </p>
            <p className="text-sm text-gray-500">
              These accounts have more active findings than one run collects, so some are missing
              from the graph.
            </p>
          </div>
          <button
            type="button"
            className={`shrink-0 text-sm ${LINK}`}
            onClick={() => onSection('detection')}
          >
            See sources →
          </button>
        </section>
      )}
      {late.length > 0 && (
        <section className="flex items-start justify-between gap-3 px-6 py-4">
          <div>
            <p className="text-sm font-medium text-gray-900">
              {late.map((job) => job.name).join(', ')} {late.length === 1 ? 'has' : 'have'} no
              recent output
            </p>
            <p className="text-sm text-gray-500">
              Nothing written in over twice the schedule; check the job, or whether it is suspended.
            </p>
          </div>
          <button
            type="button"
            className={`shrink-0 text-sm ${LINK}`}
            onClick={() => onSection('jobs')}
          >
            See jobs →
          </button>
        </section>
      )}
      {uncollected.length > 0 && (
        <section className="px-6 py-4">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wider text-gray-500">
            Not collected · {uncollected.length}
          </h3>
          <p className="text-sm text-gray-700">
            {uncollected.map(accountName).join(', ')} {uncollected.length === 1 ? 'is' : 'are'} in
            the organization but {uncollected.length === 1 ? 'has' : 'have'} no collection record.
          </p>
        </section>
      )}
    </div>
  );
}

function Accounts({
  accounts,
  rows,
}: {
  accounts: AccountCoverage[];
  rows: ReturnType<typeof useOpenRows>;
}) {
  const ordered = [...accounts].sort(
    (a, b) =>
      Number(b.status !== 'ok') - Number(a.status !== 'ok') ||
      accountName(a).localeCompare(accountName(b))
  );
  return (
    <Table caption="Accounts">
      <thead>
        <tr>
          <Th>Account</Th>
          <Th className="text-right">Resources</Th>
          <Th className="text-right">env=prod</Th>
          <Th>Last collected</Th>
          <Th>Status</Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-200 bg-white">
        {ordered.map((a) => {
          const key = `account:${a.id}`;
          const open = rows.open.has(key);
          const failing = a.services.filter(failed);
          return (
            <Fragment key={a.id}>
              <tr>
                <Td>
                  <ExpandButton open={open} onClick={() => rows.toggle(key)}>
                    <span className="font-medium text-gray-900">{accountName(a)}</span>
                    <span className="block font-mono text-xs text-gray-500">{a.id}</span>
                  </ExpandButton>
                </Td>
                <Td className="text-right tabular-nums">
                  {a.resources === null ? '—' : fmt(a.resources)}
                </Td>
                <Td className="text-right tabular-nums">{a.prod ? fmt(a.prod) : '—'}</Td>
                <Td className="text-gray-500">{ago(a.collectedAt)}</Td>
                <Td>
                  {a.status === 'not-collected' ? (
                    <Badge tone={TONES.neutral}>Not collected</Badge>
                  ) : failing.length ? (
                    <Badge tone={TONES.danger}>
                      {failing.map((s) => s.service).join(', ')} failing
                    </Badge>
                  ) : (
                    <Badge tone={TONES.success}>All {a.services.length} services</Badge>
                  )}
                </Td>
              </tr>
              {open && (
                <tr className="bg-gray-50">
                  <td colSpan={5} className="px-6 py-3 pl-12">
                    {a.services.length ? (
                      <ul className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2 lg:grid-cols-3">
                        {a.services.map((s) => (
                          <li
                            key={`${s.service}/${s.region}`}
                            className="flex items-baseline gap-2"
                          >
                            <Mark ok={!failed(s)} />
                            <span className="text-gray-900">{s.service}</span>
                            <span className="truncate text-xs text-gray-500">
                              {failed(s)
                                ? s.error || s.failureType
                                : s.nodes !== null
                                  ? `${fmt(s.nodes)} nodes`
                                  : ''}
                            </span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-gray-500">
                        No collection record for this account.
                      </p>
                    )}
                    <Link
                      href={`/resources?label=*&property=account_id&value=${encodeURIComponent(a.id)}`}
                      className={`mt-3 inline-block text-sm ${LINK}`}
                    >
                      Browse this account&apos;s resources →
                    </Link>
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </Table>
  );
}

function Services({
  accounts,
  rows,
}: {
  accounts: AccountCoverage[];
  rows: ReturnType<typeof useOpenRows>;
}) {
  const collected = accounts.filter((a) => a.services.length);
  const names = [...new Set(collected.flatMap((a) => a.services.map((s) => s.service)))].sort();
  return (
    <Table caption="Services">
      <thead>
        <tr>
          <Th>Service</Th>
          <Th>Collected in</Th>
          <Th>Status</Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-200 bg-white">
        {names.map((name) => {
          const failures = collected.flatMap((a) =>
            a.services
              .filter((s) => s.service === name && failed(s))
              .map((s) => ({ account: a, service: s }))
          );
          const failingAccounts = new Set(failures.map((f) => f.account.id)).size;
          const key = `service:${name}`;
          const open = rows.open.has(key);
          return (
            <Fragment key={name}>
              <tr>
                <Td>
                  <ExpandButton open={open} onClick={() => rows.toggle(key)}>
                    <span className="font-medium text-gray-900">{name}</span>
                  </ExpandButton>
                </Td>
                <Td className="text-gray-700">
                  {collected.length - failingAccounts} of {collected.length} accounts
                </Td>
                <Td>
                  {failingAccounts ? (
                    <Badge tone={TONES.danger}>{failingAccounts} failing</Badge>
                  ) : (
                    <Badge tone={TONES.success}>OK</Badge>
                  )}
                </Td>
              </tr>
              {open && (
                <tr className="bg-gray-50">
                  <td colSpan={3} className="px-6 py-3 pl-12">
                    {failures.length ? (
                      <ul className="space-y-1 text-sm">
                        {failures.map(({ account, service }) => (
                          <li
                            key={`${account.id}/${service.region}`}
                            className="flex items-baseline gap-2"
                          >
                            <Mark ok={false} />
                            <span className="text-gray-900">{accountName(account)}</span>
                            <span className="text-xs text-gray-500">
                              {service.error || service.failureType} · last success{' '}
                              {ago(service.lastSuccessAt)}
                            </span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="text-sm text-gray-500">
                        Collected in every account on the last run.
                      </p>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </Table>
  );
}

function Detection({
  accounts,
  rows,
}: {
  accounts: AccountCoverage[];
  rows: ReturnType<typeof useOpenRows>;
}) {
  return (
    <Table caption="Detection sources">
      <thead>
        <tr>
          <Th>Source</Th>
          <Th>On in</Th>
          <Th>Status</Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-200 bg-white">
        {SOURCES.map(([key, name, note]) => {
          const notOn = accounts.filter((a) => a.detection[key] !== 'on');
          const counts = notOn.reduce<Partial<Record<DetectionState, number>>>((acc, a) => {
            acc[a.detection[key]] = (acc[a.detection[key]] ?? 0) + 1;
            return acc;
          }, {});
          const rowKey = `source:${key}`;
          const open = rows.open.has(rowKey);
          return (
            <Fragment key={key}>
              <tr>
                <Td>
                  <ExpandButton open={open} onClick={() => rows.toggle(rowKey)}>
                    <span className="font-medium text-gray-900">{name}</span>
                  </ExpandButton>
                </Td>
                <Td className="text-gray-700">
                  {accounts.length - notOn.length} of {accounts.length} accounts
                </Td>
                <Td>
                  {notOn.length === 0 ? (
                    <Badge tone={TONES.success}>On everywhere</Badge>
                  ) : (
                    <span className="flex flex-wrap gap-1.5">
                      {(Object.entries(counts) as Array<[DetectionState, number]>).map(
                        ([state, n]) => (
                          <Badge
                            key={state}
                            tone={
                              state === 'truncated' || state === 'unknown'
                                ? TONES.warning
                                : TONES.danger
                            }
                          >
                            {n} {state}
                          </Badge>
                        )
                      )}
                    </span>
                  )}
                </Td>
              </tr>
              {open && (
                <tr className="bg-gray-50">
                  <td colSpan={3} className="px-6 py-3 pl-12">
                    {notOn.length ? (
                      <>
                        <ul className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2 lg:grid-cols-3">
                          {notOn.map((a) => (
                            <li key={a.id} className="flex items-baseline gap-2">
                              <Mark ok={false} />
                              <span className="text-gray-900">{accountName(a)}</span>
                              <span className="text-xs text-gray-500">
                                {STATE_LABEL[a.detection[key]]}
                              </span>
                            </li>
                          ))}
                        </ul>
                        <p className="mt-2 text-xs text-gray-500">{note}</p>
                      </>
                    ) : (
                      <p className="text-sm text-gray-500">On in every account.</p>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          );
        })}
      </tbody>
    </Table>
  );
}

function Jobs({ jobs }: { jobs: JobOutput[] }) {
  return (
    <Table caption="Analysis jobs">
      <thead>
        <tr>
          <Th>Job</Th>
          <Th>Schedule</Th>
          <Th>Last output</Th>
          <Th>Produced</Th>
          <Th>Status</Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-200 bg-white">
        {jobs.map((job) => {
          const status = jobStatus(job);
          return (
            <tr key={job.id}>
              <Td className="font-medium text-gray-900">{job.name}</Td>
              <Td className="text-gray-500">{every(job.everyHours)}</Td>
              <Td className="text-gray-700">{ago(job.lastOutputAt)}</Td>
              <Td className="text-gray-500">{job.produced || '—'}</Td>
              <Td>
                {status === 'on-time' ? (
                  <Badge tone={TONES.success}>On time</Badge>
                ) : status === 'quiet' ? (
                  <span title="This job writes only when it finds something">
                    <Badge tone={TONES.neutral}>No recent findings</Badge>
                  </span>
                ) : status === 'overdue' ? (
                  <Badge tone={TONES.warning}>Overdue</Badge>
                ) : (
                  <Badge tone={TONES.danger}>No output</Badge>
                )}
              </Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

export default function DataSourcesPage() {
  const data = useRequest((signal) => getDataSources({ signal }), []);
  const [section, setSection] = useState<Section>('accounts');
  const rows = useOpenRows();

  const accounts = data.status === 'success' ? data.data.accounts : [];
  const jobs = data.status === 'success' ? data.data.jobs : [];
  const healthy = accounts.filter((a) => a.status === 'ok').length;
  const attention =
    accounts.flatMap((a) => a.services.filter(failed)).length +
    accounts.filter((a) => a.status === 'not-collected').length +
    (accounts.some((a) => a.detection.securityHub === 'truncated') ? 1 : 0) +
    (jobs.some((job) => ['overdue', 'none'].includes(jobStatus(job))) ? 1 : 0);
  const serviceCount = new Set(accounts.flatMap((a) => a.services.map((s) => s.service))).size;
  const latest = accounts
    .map((a) => a.collectedAt)
    .filter((at): at is string => at !== null)
    .sort()
    .pop();
  const sections: Array<[Section, string, number, boolean]> = [
    ['attention', 'Needs attention', attention, attention > 0],
    ['accounts', 'Accounts', accounts.length, false],
    ['services', 'Services', serviceCount, false],
    ['detection', 'Detection sources', SOURCES.length, false],
    ['jobs', 'Analysis jobs', jobs.length, false],
  ];

  const openAccount = (id: string) => {
    rows.show(`account:${id}`);
    setSection('accounts');
  };

  return (
    <>
      <PageHeader
        title="Data sources"
        description="What Khalifa collects, from which accounts, and whether it is current."
      />
      <PageBody>
        {data.status === 'error' ? (
          <ErrorState error={data.error} onRetry={data.reload} />
        ) : data.status !== 'success' ? (
          <LoadingState label="Loading data sources…" />
        ) : (
          <div className="space-y-4">
            <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg bg-gray-200 shadow sm:grid-cols-4">
              <Stat
                label="Accounts"
                value={fmt(accounts.length)}
                note={`${healthy} fully collected`}
              />
              <Stat
                label="Resources"
                value={fmt(accounts.reduce((sum, a) => sum + (a.resources ?? 0), 0))}
                note="in the last collection"
              />
              <Stat
                label="Production"
                value={fmt(accounts.reduce((sum, a) => sum + a.prod, 0))}
                note="resources tagged env=prod"
              />
              <Stat label="Last collection" value={ago(latest ?? null)} note="org collector" />
            </dl>
            <div className="grid gap-6 lg:grid-cols-[220px_minmax(0,1fr)]">
              <nav aria-label="Data source sections" className="space-y-1">
                {sections.map(([key, label, count, alert]) => (
                  <button
                    key={key}
                    type="button"
                    aria-current={key === section ? 'page' : undefined}
                    onClick={() => setSection(key)}
                    className={`flex w-full items-center justify-between rounded-md px-3 py-2 text-left text-sm font-medium ${
                      key === section ? 'bg-gray-900 text-white' : 'text-gray-700 hover:bg-white'
                    }`}
                  >
                    <span>{label}</span>
                    <span
                      className={`rounded-full px-2 py-0.5 text-xs tabular-nums ${
                        key === section
                          ? 'bg-white/20 text-white'
                          : alert
                            ? 'bg-red-50 text-red-800'
                            : 'bg-gray-200 text-gray-700'
                      }`}
                    >
                      {count}
                    </span>
                  </button>
                ))}
              </nav>
              <div>
                {section === 'attention' && (
                  <Panel title="Needs attention">
                    <Attention
                      accounts={accounts}
                      jobs={jobs}
                      onOpen={openAccount}
                      onSection={setSection}
                    />
                  </Panel>
                )}
                {section === 'accounts' && (
                  <Panel title="Accounts">
                    <Accounts accounts={accounts} rows={rows} />
                  </Panel>
                )}
                {section === 'detection' && (
                  <Panel title="Detection sources">
                    <Detection accounts={accounts} rows={rows} />
                  </Panel>
                )}
                {section === 'jobs' && (
                  <Panel title="Analysis jobs">
                    <Jobs jobs={jobs} />
                  </Panel>
                )}
                {section === 'services' && (
                  <Panel title="Services">
                    <Services accounts={accounts} rows={rows} />
                  </Panel>
                )}
              </div>
            </div>
          </div>
        )}
      </PageBody>
    </>
  );
}
