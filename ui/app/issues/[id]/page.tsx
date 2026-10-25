'use client';

import Link from 'next/link';
import { Fragment, useId, useState, type ReactNode } from 'react';
import { useParams } from 'next/navigation';
import {
  getAccounts,
  getIssue,
  getRule,
  getSession,
  isNotFound,
  reopenIssue,
  suppressIssue,
} from '@/lib/api';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import { formatNodeLabel } from '@/lib/graph-labels';
import { evidenceFor } from '@/lib/evidence';
import { FINDING_LABEL, groupFindings, type FindingGroup } from '@/lib/finding-groups';
import { resourceHref } from '@/lib/routes';
import { ErrorState, LoadingState, NotFoundState } from '@/components/states';
import {
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  SECONDARY_BUTTON,
  SeverityBadge,
  Spinner,
  StatusMessage,
} from '@/components/ui';
import { AttackGraph } from '@/components/attack-graph';
import type { IssueDetail, IssueStatus } from '@/types';

const SUPPRESSION_DAYS = [7, 30, 90];
const MAX_REASON_LENGTH = 500;
const STATUS_LABELS: Record<IssueStatus, string> = {
  open: 'Open',
  resolved: 'Resolved',
  suppressed: 'Suppressed',
};
const STATUS_TEXT: Record<IssueStatus, string> = {
  open: 'text-red-700',
  resolved: 'text-green-700',
  suppressed: 'text-gray-700',
};
const DAY_MS = 24 * 60 * 60 * 1000;

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

const FACTOR_LABELS: Record<string, string> = {
  exposureContribution: 'Exposure',
  identityContribution: 'Identity blast radius',
  dataClassificationContribution: 'Data classification',
  environmentContribution: 'Environment',
  crownJewelContribution: 'Crown jewel / short path',
};

function metaString(
  metadata: Record<string, unknown> | undefined,
  key: string
): string | undefined {
  const value = metadata?.[key];
  return typeof value === 'string' && value.trim() ? value : undefined;
}

function factorLabel(key: string): string {
  return FACTOR_LABELS[key] ?? key.replace(/([A-Z])/g, ' $1').replace(/^./, (c) => c.toUpperCase());
}

const BACK = { backHref: '/issues', backLabel: '← Back to Issues' };

function FindingGroups({ groups, total }: { groups: FindingGroup[]; total: number }) {
  return (
    <div className="mt-4 border-l-2 border-gray-200 pl-4">
      <h3 className="text-sm font-medium text-gray-900">
        {total} Security Hub findings on this resource
      </h3>
      <p className="text-xs text-gray-500">
        Grouped by what fixes them: the affected package for Inspector findings, otherwise the
        finding title.
      </p>
      <ul className="mt-3 space-y-2">
        {groups.map((group) => (
          <li key={group.fix}>
            <details className="rounded-md border border-gray-200">
              <summary className="flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
                <span className="break-all font-medium text-gray-900">{group.fix}</span>
                <span className="text-gray-500">
                  {group.items.length} {group.items.length === 1 ? 'finding' : 'findings'}
                </span>
                {group.severities.map(([severity, count]) => (
                  <span key={severity} className="inline-flex items-center gap-1">
                    <SeverityBadge severity={severity.toLowerCase()} tone="soft" />
                    <span className="text-xs tabular-nums text-gray-500">{count}</span>
                  </span>
                ))}
              </summary>
              <ul className="divide-y divide-gray-100 border-t border-gray-200">
                {group.items.map((item) => (
                  <li
                    key={item.resource.resourceId}
                    className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-sm"
                  >
                    <Link href={resourceHref(item.resource.resourceId)} className={LINK}>
                      {item.name}
                    </Link>
                    {item.severity && (
                      <SeverityBadge severity={item.severity.toLowerCase()} tone="soft" />
                    )}
                  </li>
                ))}
              </ul>
            </details>
          </li>
        ))}
      </ul>
    </div>
  );
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-500">{label}</dt>
      <dd className="mt-1 text-sm text-gray-900">{children}</dd>
    </div>
  );
}

function StatusDetails({ issue }: { issue: IssueDetail }) {
  const history = [...(issue.statusHistory ?? [])].reverse();
  return (
    <Card title="Status">
      <dl className="space-y-4">
        <p className="text-sm font-semibold text-gray-900">
          Current status:{' '}
          <span className={STATUS_TEXT[issue.status]}>{STATUS_LABELS[issue.status]}</span>
        </p>
        {issue.status === 'resolved' &&
          (issue.resolvedAt ? (
            <>
              <Field label="Resolved">{formatTime(issue.resolvedAt)}</Field>
              <Field label="Reason">{issue.resolvedReason}</Field>
            </>
          ) : (
            <p className="text-sm text-gray-500">
              Resolved before resolution times and reasons were recorded.
            </p>
          ))}
        {issue.status === 'suppressed' &&
          (issue.suppression ? (
            <>
              <Field label="Suppressed by">{issue.suppression.by}</Field>
              <Field label="Suppressed">{formatTime(issue.suppression.at)}</Field>
              <Field label="Reason">{issue.suppression.reason}</Field>
              <Field label="Expires">{formatTime(issue.suppression.until)}</Field>
              <Field label="Severity when suppressed">
                <SeverityBadge severity={issue.suppression.severity} tone="soft" />
              </Field>
            </>
          ) : (
            <p className="text-sm text-gray-500">
              Suppressed before reasons and expiries were recorded. The next rule run reopens it.
            </p>
          ))}
      </dl>
      {history.length > 0 && (
        <div className="mt-6">
          <h3 className="text-sm font-medium text-gray-500">History</h3>
          <ol className="mt-2 space-y-3 border-l border-gray-200 pl-4">
            {history.map((change) => (
              <li key={`${change.at}-${change.to}`} className="text-sm">
                <div className="text-gray-900">
                  {change.from} → <span className="font-medium">{change.to}</span>
                </div>
                <div className="text-gray-700">{change.reason}</div>
                <div className="text-xs text-gray-500">
                  {formatTime(change.at)} · {change.by}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </Card>
  );
}

const DATE_ONLY = new Intl.DateTimeFormat('en-US', {
  month: 'short',
  day: 'numeric',
  year: 'numeric',
});

function SuppressForm({
  reason,
  days,
  pending,
  onReason,
  onDays,
  onSubmit,
}: {
  reason: string;
  days: number;
  pending: boolean;
  onReason: (value: string) => void;
  onDays: (value: number) => void;
  onSubmit: () => void;
}) {
  const id = useId();
  const reopensOn = DATE_ONLY.format(new Date(Date.now() + days * DAY_MS));
  return (
    <form
      className="space-y-2.5 border-t border-gray-200 pt-4"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        if (reason.trim()) onSubmit();
      }}
    >
      <div>
        <h3 className="text-sm font-semibold text-gray-900">Suppress this issue</h3>
        <p className="text-xs text-gray-500">
          Removes it from open counts until the date below. It reopens sooner if its severity rises.
        </p>
      </div>

      <div>
        <label htmlFor={`${id}-reason`} className="block text-xs font-medium text-gray-700">
          Reason
        </label>
        <textarea
          id={`${id}-reason`}
          rows={2}
          maxLength={MAX_REASON_LENGTH}
          placeholder="Why this risk is accepted, and what will fix it"
          className="mt-1 block w-full resize-y rounded-md border border-gray-300 bg-white px-2.5 py-1.5 text-sm text-gray-900 shadow-sm focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20"
          value={reason}
          onChange={(event) => onReason(event.target.value)}
        />
        <div className="mt-0.5 text-right text-xs tabular-nums text-gray-500">
          {reason.length} / {MAX_REASON_LENGTH}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <fieldset>
          <legend className="sr-only">Duration</legend>
          <div className="inline-flex rounded-md border border-orange-100 bg-orange-50 p-0.5">
            {SUPPRESSION_DAYS.map((value) => (
              <label key={value} className="relative cursor-pointer">
                <input
                  type="radio"
                  name={`${id}-days`}
                  value={value}
                  checked={days === value}
                  onChange={() => onDays(value)}
                  className="peer sr-only"
                />
                <span className="block rounded px-3 py-0.5 text-sm font-medium text-gray-600 peer-checked:bg-white peer-checked:text-gray-900 peer-checked:shadow-sm peer-focus-visible:ring-2 peer-focus-visible:ring-indigo-500">
                  {value} days
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <span className="text-xs text-gray-500">Reopens on {reopensOn}</span>
        <button
          type="submit"
          className={`${PRIMARY_BUTTON} w-full sm:ml-auto sm:w-auto`}
          disabled={pending || !reason.trim()}
        >
          {pending && <Spinner />}
          {pending ? 'Suppressing…' : `Suppress for ${days} days`}
        </button>
      </div>
    </form>
  );
}

export default function IssueDetailPage() {
  const { id } = useParams<{ id: string }>();
  const issue = useRequest((signal) => getIssue(id, { signal }), [id]);
  const ruleId = issue.status === 'success' ? issue.data.ruleId : '';
  const rule = useRequest((signal) => getRule(ruleId, { signal }), [ruleId], {
    enabled: Boolean(ruleId),
  });
  const session = useRequest((signal) => getSession({ signal }), []);
  const accounts = useRequest((signal) => getAccounts({ signal }), []);
  const accountNames =
    accounts.status === 'success'
      ? Object.fromEntries(accounts.data.accounts.map((account) => [account.id, account.name]))
      : {};
  const [reason, setReason] = useState('');
  const [days, setDays] = useState(30);
  const [notice, setNotice] = useState<string | null>(null);
  const statusChange = useAsyncAction(async (action: 'suppress' | 'reopen') => {
    setNotice(null);
    await (action === 'suppress'
      ? suppressIssue(id, reason.trim(), new Date(Date.now() + days * DAY_MS).toISOString())
      : reopenIssue(id));
    setNotice(action === 'suppress' ? 'Issue suppressed.' : 'Issue reopened.');
    setReason('');
    issue.reload();
  });

  if (issue.status === 'error') {
    if (isNotFound(issue.error)) {
      return (
        <NotFoundState
          title="Issue"
          message="That issue does not exist or was removed."
          {...BACK}
        />
      );
    }
    return (
      <>
        <PageHeader title="Issue" {...BACK} />
        <PageBody>
          <ErrorState error={issue.error} onRetry={issue.reload} />
        </PageBody>
      </>
    );
  }

  if (issue.status !== 'success') {
    return (
      <>
        <PageHeader title="Issue" {...BACK} />
        <PageBody>
          <LoadingState label="Loading issue…" />
        </PageBody>
      </>
    );
  }

  const detail = issue.data;
  const lastCollected = metaString(detail.metadata, 'lastRefreshedAt');
  const catalog = rule.status === 'success' ? rule.data : undefined;
  const ruleName = metaString(detail.metadata, 'ruleName') || catalog?.name || detail.ruleId;
  const ruleDescription = metaString(detail.metadata, 'ruleDescription') || catalog?.description;
  const canManage = session.status === 'success' && session.data.canManageIssues;
  // Path vertices win: they carry the placeholder for a resource gone from the graph.
  const vertices = new Map(
    [...(detail.involvedResources ?? []), ...(detail.attackPath?.nodes ?? [])].map((node) => [
      node.id,
      node,
    ])
  );
  // Several findings on one resource read as a list of CVEs under it, not as
  // resources of their own.
  const findings = detail.resourcesInvolved.filter((r) => r.resourceType === FINDING_LABEL);
  const findingGroups = findings.length > 1 ? groupFindings(findings, vertices) : [];
  const listed = findingGroups.length
    ? detail.resourcesInvolved.filter((r) => r.resourceType !== FINDING_LABEL)
    : detail.resourcesInvolved;
  const nestUnder = listed.length === 1 ? listed[0].resourceId : undefined;
  const findingList = findingGroups.length > 0 && (
    <FindingGroups groups={findingGroups} total={findings.length} />
  );

  return (
    <>
      <PageHeader
        title={ruleName}
        description={ruleDescription}
        {...BACK}
        actions={<SeverityBadge severity={detail.severity} size="md" />}
      />
      <PageBody>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            <Card title="Issue details">
              <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <dt className="text-sm font-medium text-gray-500">Rule</dt>
                  <dd className="mt-1 text-sm text-gray-900">{detail.ruleId}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Owning team</dt>
                  <dd className="mt-1 text-sm text-gray-900">{detail.owningTeam}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Risk score</dt>
                  <dd className="mt-1 text-sm text-gray-900">{detail.riskScore.toFixed(2)}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Created</dt>
                  <dd className="mt-1 text-sm text-gray-900">
                    {new Date(detail.createdAt).toLocaleString()}
                  </dd>
                </div>
              </dl>

              <div className="mt-6">
                <h3 className="text-sm font-medium text-gray-500">Remediation hint</h3>
                <p className="mt-2 rounded-md bg-orange-50 p-4 text-sm text-gray-900">
                  {detail.remediationHint}
                </p>
              </div>

              {session.status === 'error' && (
                <StatusMessage tone="warning" className="mt-6">
                  Could not confirm your permissions, so issue actions are hidden.{' '}
                  <button type="button" className={LINK} onClick={session.reload}>
                    Try again
                  </button>
                </StatusMessage>
              )}

              {canManage && (
                <div className="mt-6 space-y-3">
                  {notice && <StatusMessage tone="success">{notice}</StatusMessage>}
                  {statusChange.error !== undefined && <ErrorState error={statusChange.error} />}
                  {detail.status === 'open' && (
                    <SuppressForm
                      reason={reason}
                      days={days}
                      pending={statusChange.pending}
                      onReason={setReason}
                      onDays={setDays}
                      onSubmit={() => void statusChange.run('suppress')}
                    />
                  )}
                  <div className="flex flex-wrap items-end gap-3">
                    {detail.status === 'suppressed' && (
                      <button
                        type="button"
                        className={SECONDARY_BUTTON}
                        disabled={statusChange.pending}
                        onClick={() => void statusChange.run('reopen')}
                      >
                        {statusChange.pending && <Spinner />}
                        {statusChange.pending ? 'Reopening…' : 'Reopen'}
                      </button>
                    )}
                  </div>
                </div>
              )}
            </Card>

            <Card
              title="Involved resources"
              description={`Each resource and what made it match. Values are from the latest collection${
                lastCollected ? `, ${formatTime(lastCollected)}` : ''
              }.`}
            >
              <ul className="divide-y divide-gray-200">
                {listed.map((resource) => {
                  const vertex = vertices.get(resource.resourceId);
                  const facts =
                    vertex && !vertex.properties?.missing ? evidenceFor(vertex, detail.ruleId) : [];
                  return (
                    <li key={resource.resourceId} className="py-4 first:pt-0 last:pb-0">
                      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                        <span className="text-sm font-medium text-gray-900">
                          {formatNodeLabel(resource.resourceType)}
                        </span>
                        <span className="truncate text-sm">
                          {resource.resourceId.startsWith('arn:') ? (
                            <Link href={resourceHref(resource.resourceId)} className={LINK}>
                              {resource.resourceName || resource.resourceId}
                            </Link>
                          ) : (
                            <span className="text-gray-500">
                              {resource.resourceName || resource.resourceId}
                            </span>
                          )}
                        </span>
                      </div>
                      {resource.accountId && (
                        <div className="text-xs text-gray-500">
                          {accountNames[resource.accountId] || resource.accountId}
                          {resource.region ? ` · ${resource.region}` : ''}
                        </div>
                      )}
                      {vertex?.properties?.missing === true && (
                        <p className="mt-2 text-sm italic text-gray-500">
                          No longer in the graph. The next rule run resolves this issue if nothing
                          else matches.
                        </p>
                      )}
                      {facts.length > 0 && (
                        <dl className="mt-3 grid grid-cols-[max-content_minmax(0,1fr)] gap-x-6 gap-y-1.5 text-sm">
                          {facts.map((fact) => (
                            <Fragment key={fact.id}>
                              <dt className="text-gray-500">{fact.label}</dt>
                              <dd className="break-words text-gray-900">
                                {fact.decisive ? (
                                  <span className="rounded bg-red-50 px-1.5 font-semibold text-red-800">
                                    {fact.value}
                                  </span>
                                ) : (
                                  fact.value
                                )}
                              </dd>
                            </Fragment>
                          ))}
                        </dl>
                      )}
                      {resource.resourceId === nestUnder && findingList}
                    </li>
                  );
                })}
              </ul>
              {!nestUnder && findingList}
            </Card>
          </div>

          <div className="space-y-6">
            <StatusDetails issue={detail} />

            {detail.metadata?.scoringFactors != null && (
              <Card title="Scoring factors">
                <dl className="space-y-2">
                  {Object.entries(detail.metadata.scoringFactors as Record<string, unknown>).map(
                    ([key, value]) => (
                      <div key={key} className="flex justify-between gap-3">
                        <dt className="text-sm text-gray-500">{factorLabel(key)}</dt>
                        <dd className="text-sm font-medium text-gray-900">
                          {typeof value === 'number' ? value.toFixed(2) : String(value)}
                        </dd>
                      </div>
                    )
                  )}
                </dl>
              </Card>
            )}
          </div>
        </div>

        <Card
          className="mt-6"
          title="Attack path"
          description="Where an attacker gets in and what they can reach. Click a node for details."
        >
          <AttackGraph
            paths={detail.attackPath?.nodes?.length ? [detail.attackPath] : []}
            entries={
              detail.attackPath?.entry && detail.attackPath.nodes[0]
                ? { [detail.attackPath.nodes[0].id]: detail.attackPath.entry }
                : undefined
            }
            accountNames={accountNames}
            empty="No attack path recorded for this issue."
          />
        </Card>
      </PageBody>
    </>
  );
}
