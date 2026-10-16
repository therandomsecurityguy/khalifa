'use client';

import Link from 'next/link';
import { Fragment, useState } from 'react';
import { getLeastPrivilegeFindings, getLeastPrivilegeSummary } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { principalHref, resourceHref } from '@/lib/routes';
import { EmptyState, ErrorState, LoadingState, NoMatchesState } from '@/components/states';
import {
  Card,
  LINK,
  PageBody,
  PageHeader,
  RiskBadge,
  SelectField,
  StatCard,
  Table,
  Td,
  Th,
} from '@/components/ui';

const NO_FILTERS = { riskLevel: '', principalType: '' };

export default function LeastPrivilegePage() {
  const [filters, setFilters] = useState(NO_FILTERS);
  const [expanded, setExpanded] = useState<string | null>(null);
  const findings = useRequest(
    (signal) => getLeastPrivilegeFindings(filters, { signal }),
    [filters.riskLevel, filters.principalType]
  );
  const summary = useRequest((signal) => getLeastPrivilegeSummary({ signal }), []);
  const activeFilters = [
    filters.riskLevel && `Risk ${filters.riskLevel}`,
    filters.principalType && `Type ${filters.principalType}`,
  ].filter((item): item is string => Boolean(item));

  const stat = (read: (data: NonNullable<typeof summary.data>) => number) =>
    summary.status === 'success' ? read(summary.data) : '…';

  return (
    <>
      <PageHeader
        title="IAM least-privilege sweep"
        backHref="/identity"
        backLabel="← Back to Identity"
      />
      <PageBody>
        {summary.status === 'error' ? (
          <ErrorState error={summary.error} onRetry={summary.reload} className="mb-6" />
        ) : (
          <div
            className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-5"
            aria-busy={summary.status === 'loading'}
          >
            <StatCard label="Accounts" value={stat((data) => data.accountsSwept)} />
            <StatCard label="Principals" value={stat((data) => data.principalsSwept)} />
            <StatCard
              label="High risk"
              value={stat((data) => data.byRiskLevel.high)}
              bar="critical"
            />
            <StatCard
              label="Medium risk"
              value={stat((data) => data.byRiskLevel.medium)}
              bar="medium"
            />
            <StatCard
              label="Removed actions"
              value={stat((data) => data.totalRemovedActions)}
              bar="low"
            />
          </div>
        )}

        <Card flush>
          <form
            className="flex flex-wrap gap-4 border-b border-orange-100 bg-orange-50 p-4"
            onSubmit={(event) => event.preventDefault()}
          >
            <SelectField
              label="Risk level"
              value={filters.riskLevel}
              onChange={(event) =>
                setFilters((previous) => ({ ...previous, riskLevel: event.target.value }))
              }
            >
              <option value="">All</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </SelectField>
            <SelectField
              label="Principal type"
              value={filters.principalType}
              onChange={(event) =>
                setFilters((previous) => ({ ...previous, principalType: event.target.value }))
              }
            >
              <option value="">All</option>
              <option value="role">Role</option>
              <option value="user">User</option>
            </SelectField>
          </form>

          <div aria-busy={findings.status === 'loading'}>
            {findings.status === 'error' ? (
              <ErrorState error={findings.error} onRetry={findings.reload} className="m-4" />
            ) : findings.status !== 'success' ? (
              <LoadingState label="Loading findings…" />
            ) : findings.data.items.length === 0 ? (
              activeFilters.length > 0 ? (
                <NoMatchesState
                  noun="findings"
                  activeFilters={activeFilters}
                  onClear={() => setFilters(NO_FILTERS)}
                />
              ) : (
                <EmptyState
                  title="No findings yet"
                  description="The least-privilege sweep has not recorded any principals to trim."
                />
              )
            ) : (
              <Table caption="Least-privilege findings">
                <thead>
                  <tr>
                    <Th>Account</Th>
                    <Th>Principal</Th>
                    <Th>Type</Th>
                    <Th>Risk</Th>
                    <Th>Removed</Th>
                    <Th>Kept</Th>
                    <Th>Last swept</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 bg-white">
                  {findings.data.items.map((finding) => {
                    const open = expanded === finding.principalArn;
                    return (
                      <Fragment key={finding.principalArn}>
                        <tr className="hover:bg-gray-50">
                          <Td className="whitespace-nowrap text-gray-900">{finding.accountId}</Td>
                          <Td>
                            <Link
                              href={resourceHref(finding.principalArn)}
                              className={`block max-w-xs truncate ${LINK}`}
                            >
                              {finding.principalArn}
                            </Link>
                            <button
                              type="button"
                              className="mt-1 text-xs text-gray-500 hover:text-gray-900"
                              aria-expanded={open}
                              onClick={() => setExpanded(open ? null : finding.principalArn)}
                            >
                              {open ? 'Hide details' : 'Show details'}
                            </button>
                          </Td>
                          <Td className="whitespace-nowrap text-gray-500">
                            {finding.principalType}
                          </Td>
                          <Td className="whitespace-nowrap">
                            <RiskBadge level={finding.riskLevel} />
                          </Td>
                          <Td className="whitespace-nowrap text-gray-500">
                            {finding.removedActionCount}
                          </Td>
                          <Td className="whitespace-nowrap text-gray-500">
                            {finding.keptActionCount}
                          </Td>
                          <Td className="whitespace-nowrap text-gray-500">
                            {new Date(finding.lastSweptAt).toLocaleDateString()}
                          </Td>
                        </tr>
                        {open && (
                          <tr>
                            <Td colSpan={7} className="bg-orange-50">
                              <div className="mb-4 flex flex-wrap gap-3">
                                <Link
                                  href={principalHref(
                                    '/identity/effective-permissions',
                                    finding.principalArn
                                  )}
                                  className={LINK}
                                >
                                  Effective permissions
                                </Link>
                                <Link
                                  href={principalHref(
                                    '/identity/rightsizing',
                                    finding.principalArn
                                  )}
                                  className={LINK}
                                >
                                  Rightsizing
                                </Link>
                                <Link
                                  href={principalHref(
                                    '/identity/unused-permissions',
                                    finding.principalArn
                                  )}
                                  className={LINK}
                                >
                                  Unused permissions
                                </Link>
                              </div>
                              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                                <div>
                                  <h4 className="mb-2 text-sm font-semibold text-gray-900">
                                    Removed actions ({finding.removedActions.length})
                                  </h4>
                                  <div className="max-h-48 overflow-y-auto rounded border border-gray-200 bg-white p-2">
                                    {finding.removedActions.map((action) => (
                                      <div key={action} className="py-0.5 font-mono text-xs">
                                        {action}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                                <div>
                                  <h4 className="mb-2 text-sm font-semibold text-gray-900">
                                    Recommended policy
                                  </h4>
                                  <pre className="max-h-48 overflow-y-auto rounded border border-gray-200 bg-white p-2 text-xs">
                                    {JSON.stringify(finding.recommendedPolicy, null, 2)}
                                  </pre>
                                </div>
                              </div>
                            </Td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </Table>
            )}
          </div>
        </Card>
      </PageBody>
    </>
  );
}
