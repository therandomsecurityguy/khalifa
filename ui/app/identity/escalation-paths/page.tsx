'use client';

import Link from 'next/link';
import { Suspense, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { getEscalationPaths } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { resourceHref } from '@/lib/routes';
import { EmptyState, ErrorState, LoadingState, NoMatchesState } from '@/components/states';
import {
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  RiskBadge,
  SelectField,
  Table,
  Td,
  TextField,
  Th,
} from '@/components/ui';

const FILTER_KEYS = ['sourceAccount', 'targetRole', 'escalationType', 'riskLevel'] as const;
type FilterKey = (typeof FILTER_KEYS)[number];
type Filters = Record<FilterKey, string>;

const FILTER_LABELS: Record<FilterKey, string> = {
  sourceAccount: 'Source account',
  targetRole: 'Target role',
  escalationType: 'Type',
  riskLevel: 'Risk',
};

function EscalationPathsView() {
  const router = useRouter();
  const params = useSearchParams();
  const query = Object.fromEntries(
    FILTER_KEYS.map((key) => [key, params.get(key) ?? ''])
  ) as Filters;
  const [form, setForm] = useState<Filters>(query);
  const paths = useRequest(
    (signal) => getEscalationPaths(query, { signal }),
    FILTER_KEYS.map((key) => query[key])
  );
  const activeFilters = FILTER_KEYS.filter((key) => query[key]).map(
    (key) => `${FILTER_LABELS[key]} ${query[key]}`
  );

  function navigate(next: Filters): void {
    const search = new URLSearchParams();
    for (const key of FILTER_KEYS) {
      if (next[key]) search.set(key, next[key]);
    }
    router.push(`/identity/escalation-paths?${search.toString()}`);
  }

  return (
    <>
      <PageHeader
        title="Escalation paths"
        backHref="/identity"
        backLabel="← Back to Identity"
        description="Filter by account, target role, type, or risk."
      />
      <PageBody>
        <form
          className="mb-6 grid grid-cols-1 gap-4 rounded-lg bg-white p-4 shadow md:grid-cols-5"
          onSubmit={(event) => {
            event.preventDefault();
            navigate(form);
          }}
        >
          <TextField
            label={FILTER_LABELS.sourceAccount}
            value={form.sourceAccount}
            onChange={(event) => setForm({ ...form, sourceAccount: event.target.value })}
          />
          <TextField
            label={FILTER_LABELS.targetRole}
            value={form.targetRole}
            onChange={(event) => setForm({ ...form, targetRole: event.target.value })}
          />
          <SelectField
            label={FILTER_LABELS.escalationType}
            value={form.escalationType}
            onChange={(event) => setForm({ ...form, escalationType: event.target.value })}
          >
            <option value="">All</option>
            <option value="admin">admin</option>
            <option value="privilege_escalation">privilege_escalation</option>
            <option value="lateral_movement">lateral_movement</option>
          </SelectField>
          <SelectField
            label={FILTER_LABELS.riskLevel}
            value={form.riskLevel}
            onChange={(event) => setForm({ ...form, riskLevel: event.target.value })}
          >
            <option value="">All</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </SelectField>
          <div className="flex items-end">
            <button type="submit" className={PRIMARY_BUTTON}>
              Filter
            </button>
          </div>
        </form>

        <div aria-busy={paths.status === 'loading'}>
          {paths.status === 'error' ? (
            <ErrorState error={paths.error} onRetry={paths.reload} />
          ) : paths.status !== 'success' ? (
            <LoadingState label="Loading escalation paths…" />
          ) : paths.data.paths.length === 0 ? (
            <Card flush>
              {activeFilters.length > 0 ? (
                <NoMatchesState
                  noun="escalation paths"
                  activeFilters={activeFilters}
                  onClear={() => {
                    const cleared = Object.fromEntries(
                      FILTER_KEYS.map((key) => [key, ''])
                    ) as Filters;
                    setForm(cleared);
                    navigate(cleared);
                  }}
                />
              ) : (
                <EmptyState
                  title="No escalation paths detected"
                  description="The graph has no privilege-escalation or lateral-movement paths right now."
                />
              )}
            </Card>
          ) : (
            <Card flush>
              <Table caption="Escalation paths">
                <thead>
                  <tr>
                    <Th>Source</Th>
                    <Th>Target</Th>
                    <Th>Type</Th>
                    <Th>Risk</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {paths.data.paths.map((path) => (
                    <tr key={path.id}>
                      <Td>
                        <Link className={`break-all ${LINK}`} href={resourceHref(path.sourceArn)}>
                          {path.sourceArn}
                        </Link>
                      </Td>
                      <Td>
                        <Link className={`break-all ${LINK}`} href={resourceHref(path.targetArn)}>
                          {path.targetArn}
                        </Link>
                      </Td>
                      <Td className="text-gray-500">{path.escalationType}</Td>
                      <Td>
                        <RiskBadge level={path.riskLevel} />
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>
          )}
        </div>
      </PageBody>
    </>
  );
}

export default function EscalationPathsPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading…" />}>
      <EscalationPathsView />
    </Suspense>
  );
}
