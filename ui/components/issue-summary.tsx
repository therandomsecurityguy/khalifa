'use client';

import type { IssueStatus, Severity, SeverityStatusCounts } from '@/types';

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const STATUSES: IssueStatus[] = ['open', 'suppressed', 'resolved'];

const SEVERITY_FILL: Record<Severity, string> = {
  critical: 'bg-red-700',
  high: 'bg-orange-500',
  medium: 'bg-yellow-400',
  low: 'bg-blue-700',
};

const STATUS_DOT: Record<IssueStatus, string> = {
  open: 'bg-red-700',
  suppressed: 'bg-gray-400',
  resolved: 'bg-green-700',
};

const label = (value: string) => value[0].toUpperCase() + value.slice(1);

// Each side counts within the other side's selection, so picking a status
// recounts the severity bar and picking a severity recounts the statuses.
export function IssueSummary({
  counts,
  severity,
  status,
  onToggleSeverity,
  onStatus,
}: {
  counts: SeverityStatusCounts;
  severity: Severity[];
  status: IssueStatus[];
  onToggleSeverity: (value: Severity) => void;
  onStatus: (value: IssueStatus[]) => void;
}) {
  const inSeverity = (value: Severity) => !severity.length || severity.includes(value);
  const inStatus = (value: IssueStatus) => !status.length || status.includes(value);

  const total = SEVERITIES.reduce(
    (sum, sv) => sum + STATUSES.reduce((inner, st) => inner + counts[sv][st], 0),
    0
  );
  const open = SEVERITIES.reduce((sum, sv) => sum + counts[sv].open, 0);
  const byStatus = STATUSES.map((st) => ({
    status: st,
    count: SEVERITIES.filter(inSeverity).reduce((sum, sv) => sum + counts[sv][st], 0),
  }));
  const bySeverity = SEVERITIES.map((sv) => ({
    severity: sv,
    count: STATUSES.filter(inStatus).reduce((sum, st) => sum + counts[sv][st], 0),
  }));
  const scope = status.length ? status.map(label).join(' + ') : 'All statuses';

  return (
    <section className="grid overflow-hidden rounded-lg bg-white shadow md:grid-cols-[minmax(0,1fr)_minmax(0,1.6fr)]">
      <div className="space-y-3 border-b border-gray-200 p-5 md:border-b-0 md:border-r">
        <p className="text-xs font-medium uppercase tracking-wider text-gray-500">
          Actionable issues
        </p>
        <p className="tabular-nums text-gray-900">
          <span className="text-4xl font-bold">{open}</span>
          <span className="text-lg text-gray-500"> / {total}</span>
        </p>
        <div className="flex flex-wrap gap-2" role="group" aria-label="Status">
          {byStatus.map(({ status: st, count }) => {
            const active = status.length === 1 && status[0] === st;
            return (
              <button
                key={st}
                type="button"
                aria-pressed={active}
                onClick={() => onStatus(active ? [] : [st])}
                className={`inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm ${
                  active
                    ? 'border-indigo-500 bg-indigo-50 text-gray-900'
                    : 'border-gray-200 bg-white text-gray-700 hover:border-indigo-400'
                }`}
              >
                <span className={`h-2 w-2 rounded-full ${STATUS_DOT[st]}`} aria-hidden="true" />
                {label(st)}
                <span className="font-semibold tabular-nums text-gray-900">{count}</span>
              </button>
            );
          })}
        </div>
        <button
          type="button"
          className="text-sm font-medium text-indigo-600 hover:text-indigo-900 disabled:text-gray-400"
          disabled={!status.length}
          onClick={() => onStatus([])}
        >
          Show all statuses
        </button>
      </div>

      <div className="space-y-3 p-5">
        <p className="text-xs font-medium uppercase tracking-wider text-gray-500">
          By severity · {scope}
        </p>
        <div className="flex h-3.5 gap-0.5 overflow-hidden rounded-full bg-orange-50">
          {bySeverity.map(({ severity: sv, count }) =>
            count ? (
              <button
                key={sv}
                type="button"
                title={`${label(sv)}: ${count}`}
                aria-label={`${label(sv)}: ${count}`}
                aria-pressed={severity.includes(sv)}
                onClick={() => onToggleSeverity(sv)}
                style={{ flexGrow: count }}
                className={`min-w-[6px] ${SEVERITY_FILL[sv]} ${
                  severity.length && !severity.includes(sv) ? 'opacity-40' : ''
                }`}
              />
            ) : null
          )}
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-1.5" role="group" aria-label="Severity">
          {bySeverity.map(({ severity: sv, count }) => {
            const active = severity.includes(sv);
            return (
              <button
                key={sv}
                type="button"
                aria-pressed={active}
                onClick={() => onToggleSeverity(sv)}
                className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-sm ${
                  active
                    ? 'border-indigo-500 bg-indigo-50 text-gray-900'
                    : 'border-transparent text-gray-700 hover:border-gray-200'
                }`}
              >
                <span
                  className={`h-2.5 w-2.5 rounded-sm ${SEVERITY_FILL[sv]}`}
                  aria-hidden="true"
                />
                {label(sv)}
                <span className="font-semibold tabular-nums text-gray-900">{count}</span>
              </button>
            );
          })}
        </div>
        <p className="text-xs text-gray-500">
          Click a severity or a status to filter the list. Click again to clear.
        </p>
      </div>
    </section>
  );
}
