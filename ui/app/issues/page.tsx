'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { getAccounts, getIssueSummary, getIssues, listRules } from '@/lib/api';
import { issueSubject } from '@/lib/issue-subject';
import { useRequest } from '@/lib/use-request';
import type { Issue, IssueStatus, Severity, SeverityStatusCounts } from '@/types';
import { EmptyState, ErrorState, LoadingState, NoMatchesState } from '@/components/states';
import { ColumnFilter } from '@/components/column-filter';
import { IssueSummary } from '@/components/issue-summary';
import { IssueRunTimes } from '@/components/issue-run-times';
import {
  Card,
  IssueStatusBadge,
  LINK,
  PageBody,
  PageHeader,
  SECONDARY_BUTTON,
  SeverityBadge,
  Spinner,
  Table,
  Td,
  Th,
} from '@/components/ui';

interface Filters {
  severity: Severity[];
  status: IssueStatus[];
  rule: string[];
  team: string[];
}

const DEFAULT_FILTERS: Filters = { severity: [], status: ['open'], rule: [], team: [] };
const NO_FILTERS: Filters = { severity: [], status: [], rule: [], team: [] };
const COLUMNS = 8;
const PAGE_SIZE = 50;
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const STATUSES: IssueStatus[] = ['open', 'suppressed', 'resolved'];

// The summary counts every severity and status, so it knows the total for
// those filters; rule and team filters it cannot count.
function expectedTotal(counts: SeverityStatusCounts, filters: Filters): number | undefined {
  if (filters.rule.length || filters.team.length) return undefined;
  const severities = filters.severity.length ? filters.severity : SEVERITIES;
  const statuses = filters.status.length ? filters.status : STATUSES;
  return severities.reduce(
    (sum, severity) =>
      sum + statuses.reduce((inner, status) => inner + counts[severity][status], 0),
    0
  );
}

function describeFilters(filters: Filters): string[] {
  const active: string[] = [];
  if (filters.severity.length) active.push(`Severity ${filters.severity.join(', ')}`);
  if (filters.rule.length) active.push(`Rule ${filters.rule.join(', ')}`);
  if (filters.team.length) active.push(`Team ${filters.team.join(', ')}`);
  if (filters.status.length) active.push(`Status ${filters.status.join(', ')}`);
  return active;
}

function IssueRow({
  issue,
  title,
  accountNames,
}: {
  issue: Issue;
  title: string;
  accountNames: Map<string, string>;
}) {
  const subject = issueSubject(issue, accountNames);
  return (
    <tr className="hover:bg-gray-50">
      <Td className="whitespace-nowrap">
        <SeverityBadge severity={issue.severity} />
      </Td>
      <Td>
        <div className="text-xs font-medium text-gray-500">{issue.ruleId}</div>
        <div className="font-medium text-gray-900">{title}</div>
      </Td>
      <Td>
        {subject ? (
          <>
            <div className="break-all text-gray-900">
              {subject.name} <span className="text-xs text-gray-500">({subject.type})</span>
            </div>
            <div className="text-xs text-gray-500">
              {[subject.account, subject.matches].filter(Boolean).join(' · ')}
            </div>
          </>
        ) : (
          <span className="text-gray-400">—</span>
        )}
      </Td>
      <Td className="whitespace-nowrap text-gray-500">{issue.owningTeam}</Td>
      <Td className="whitespace-nowrap text-gray-500">{issue.riskScore.toFixed(1)}</Td>
      <Td className="whitespace-nowrap">
        <IssueStatusBadge status={issue.status} />
        {issue.status === 'resolved' && issue.resolvedAt && (
          <div className="mt-1 text-xs text-gray-500">
            {new Date(issue.resolvedAt).toLocaleDateString()}
          </div>
        )}
        {issue.status === 'suppressed' && issue.suppression && (
          <div className="mt-1 text-xs text-gray-500">
            until {new Date(issue.suppression.until).toLocaleDateString()}
          </div>
        )}
      </Td>
      <Td className="whitespace-nowrap text-gray-500">
        {new Date(issue.createdAt).toLocaleDateString()}
      </Td>
      <Td className="whitespace-nowrap">
        <Link href={`/issues/${issue.id}`} className={LINK}>
          View
        </Link>
      </Td>
    </tr>
  );
}

export default function IssuesPage() {
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [order, setOrder] = useState<'desc' | 'asc'>('desc');
  const query = {
    severity: filters.severity,
    status: filters.status,
    ruleId: filters.rule,
    team: filters.team,
    order,
    limit: PAGE_SIZE,
  };
  const issues = useRequest(
    (signal) => getIssues(query, { signal }),
    [
      filters.severity.join(','),
      filters.status.join(','),
      filters.rule.join(','),
      filters.team.join(','),
      order,
    ]
  );
  const summary = useRequest((signal) => getIssueSummary({ signal }), []);

  // Pages after the first, appended by "Load more"; any filter change starts over.
  const [more, setMore] = useState<{ items: Issue[]; nextToken?: string } | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState(false);
  useEffect(() => {
    setMore(null);
    setMoreError(false);
  }, [issues.data]);
  const loaded = issues.status === 'success' ? [...issues.data.items, ...(more?.items ?? [])] : [];
  const nextToken = more
    ? more.nextToken
    : issues.status === 'success'
      ? issues.data.nextToken
      : undefined;
  const total = summary.status === 'success' ? expectedTotal(summary.data, filters) : undefined;

  async function loadMore(): Promise<void> {
    if (!nextToken) return;
    setLoadingMore(true);
    setMoreError(false);
    try {
      const page = await getIssues({ ...query, nextToken });
      setMore((previous) => ({
        items: [...(previous?.items ?? []), ...page.items],
        nextToken: page.nextToken,
      }));
    } catch {
      setMoreError(true);
    } finally {
      setLoadingMore(false);
    }
  }
  const rules = useRequest((signal) => listRules({ signal }), []);
  const catalog = rules.status === 'success' ? rules.data.rules : [];
  const ruleNames = new Map(catalog.map((rule) => [rule.id, rule.name]));
  const accounts = useRequest((signal) => getAccounts({ signal }), []);
  const accountNames = new Map(
    (accounts.status === 'success' ? accounts.data.accounts : []).map((a) => [a.id, a.name])
  );
  const ruleOptions = catalog
    .map((rule) => rule.id)
    .sort()
    .map((id) => ({ value: id, label: id }));
  const teamOptions = [...new Set(catalog.map((rule) => rule.ownerTeam))]
    .sort()
    .map((team) => ({ value: team, label: team }));
  const activeFilters = describeFilters(filters);

  function update<K extends keyof Filters>(key: K, values: Filters[K]): void {
    setFilters((previous) => ({ ...previous, [key]: values }));
  }

  function toggleSeverity(value: Severity): void {
    setFilters((previous) => ({
      ...previous,
      severity: previous.severity.includes(value)
        ? previous.severity.filter((item) => item !== value)
        : [...previous.severity, value],
    }));
  }

  const nothingRecorded =
    issues.status === 'success' && loaded.length === 0 && !nextToken && activeFilters.length === 0;

  let body;
  if (issues.status === 'success' && loaded.length > 0) {
    body = loaded.map((issue) => (
      <IssueRow
        key={issue.id}
        issue={issue}
        accountNames={accountNames}
        title={
          (typeof issue.metadata?.ruleName === 'string' && issue.metadata.ruleName) ||
          ruleNames.get(issue.ruleId) ||
          issue.ruleId
        }
      />
    ));
  } else if (issues.status === 'success' && nextToken) {
    // The read budget ran out before any match; keep searching on request.
    body = (
      <tr>
        <Td colSpan={COLUMNS}>
          <p className="py-6 text-center text-sm text-gray-500">
            No matches yet in the issues read so far.
          </p>
        </Td>
      </tr>
    );
  } else if (issues.status === 'success') {
    body = (
      <tr>
        <Td colSpan={COLUMNS}>
          <NoMatchesState
            noun="issues"
            activeFilters={activeFilters}
            onClear={() => setFilters(NO_FILTERS)}
          />
        </Td>
      </tr>
    );
  } else {
    body = (
      <tr>
        <Td colSpan={COLUMNS}>
          <LoadingState label="Loading issues…" />
        </Td>
      </tr>
    );
  }

  return (
    <>
      <PageHeader title="Security issues" actions={<IssueRunTimes />} />
      <PageBody>
        {summary.status === 'error' ? (
          <ErrorState error={summary.error} onRetry={summary.reload} className="mb-6" />
        ) : summary.status !== 'success' ? (
          <div className="mb-6 rounded-lg bg-white shadow" aria-busy="true">
            <LoadingState label="Loading summary…" />
          </div>
        ) : (
          <div className="mb-6">
            <IssueSummary
              counts={summary.data}
              severity={filters.severity}
              status={filters.status}
              onToggleSeverity={toggleSeverity}
              onStatus={(values) => update('status', values)}
            />
          </div>
        )}

        {filters.severity.length > 0 && (
          <div className="mb-4 flex flex-wrap items-center gap-2">
            {filters.severity.map((value) => (
              <button
                key={value}
                type="button"
                onClick={() => toggleSeverity(value)}
                aria-label={`Remove severity filter: ${value}`}
                className="inline-flex items-center gap-1 rounded-full border border-indigo-500 bg-indigo-50 px-3 py-0.5 text-xs font-medium text-indigo-800 hover:bg-indigo-100"
              >
                Severity: {value}
                <span aria-hidden="true">×</span>
              </button>
            ))}
            <button
              type="button"
              className="text-sm font-medium text-indigo-600 hover:text-indigo-900"
              onClick={() => setFilters(NO_FILTERS)}
            >
              Clear all filters
            </button>
          </div>
        )}

        <Card flush>
          <div aria-busy={issues.status === 'loading'}>
            {issues.status === 'error' ? (
              <ErrorState error={issues.error} onRetry={issues.reload} className="m-4" />
            ) : nothingRecorded ? (
              <EmptyState
                title="No issues recorded"
                description="The risk runner has not written any issues yet. Check back after the next collection."
              />
            ) : (
              // The header stays mounted through reloads so an open column filter
              // keeps its panel while the list refreshes.
              <Table caption="Security issues">
                <thead>
                  <tr>
                    <Th>Severity</Th>
                    <Th>
                      <ColumnFilter
                        label="Rule"
                        options={ruleOptions}
                        selected={filters.rule}
                        onChange={(values) => update('rule', values)}
                      />
                    </Th>
                    <Th>Resources</Th>
                    <Th>
                      <ColumnFilter
                        label="Team"
                        options={teamOptions}
                        selected={filters.team}
                        onChange={(values) => update('team', values)}
                      />
                    </Th>
                    <Th>Risk score</Th>
                    <Th>Status</Th>
                    <Th>
                      <button
                        type="button"
                        onClick={() => setOrder(order === 'desc' ? 'asc' : 'desc')}
                        aria-label={`Created, ${order === 'desc' ? 'newest' : 'oldest'} first`}
                        className="inline-flex items-center gap-1 uppercase tracking-wider hover:text-gray-900"
                      >
                        Created
                        <span aria-hidden="true">{order === 'desc' ? '↓' : '↑'}</span>
                      </button>
                    </Th>
                    <Th>Actions</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 bg-white">{body}</tbody>
              </Table>
            )}
            {issues.status === 'success' && (loaded.length > 0 || nextToken) && (
              <div className="flex flex-wrap items-center justify-between gap-3 border-t border-gray-200 px-6 py-3 text-sm text-gray-600">
                <span className="tabular-nums">
                  Showing {loaded.length}
                  {total !== undefined ? ` of ${total}` : ''}{' '}
                  {loaded.length === 1 ? 'issue' : 'issues'}
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
            )}
          </div>
        </Card>
      </PageBody>
    </>
  );
}
