'use client';

import Link from 'next/link';
import { useState } from 'react';
import { useParams } from 'next/navigation';
import { assessmentCounts, getFrameworkControls, getFrameworkSummary } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { frameworkLabel } from '@/lib/compliance';
import { EmptyState, ErrorState, LoadingState, NoMatchesState } from '@/components/states';
import {
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  SECONDARY_BUTTON,
  SelectField,
  RegionScopeBadge,
  SeverityBadge,
  StatusBadge,
  SummaryTile,
  Table,
  Td,
  Th,
} from '@/components/ui';

const NO_FILTERS = { section: '', status: '', severity: '', automated: '' };
type Filters = typeof NO_FILTERS;

const FILTER_LABELS: Record<keyof Filters, string> = {
  section: 'Section',
  status: 'Status',
  severity: 'Severity',
  automated: 'Type',
};

export default function FrameworkDetailPage() {
  const { framework } = useParams<{ framework: string }>();
  const summary = useRequest((signal) => getFrameworkSummary(framework, { signal }), [framework]);
  const controls = useRequest((signal) => getFrameworkControls(framework, { signal }), [framework]);
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);

  const allControls = controls.status === 'success' ? controls.data.controls : [];
  const filteredControls = allControls.filter((control) => {
    if (filters.section && control.section !== filters.section) return false;
    if (filters.status && control.status !== filters.status) return false;
    if (filters.severity && control.severity !== filters.severity) return false;
    if (filters.automated !== '' && control.automated !== (filters.automated === 'true'))
      return false;
    return true;
  });
  const sections = [...new Set(allControls.map((control) => control.section))].sort();
  const activeFilters = (Object.keys(filters) as (keyof Filters)[])
    .filter((key) => filters[key] !== '')
    .map((key) =>
      key === 'automated'
        ? `${FILTER_LABELS.automated} ${filters.automated === 'true' ? 'Automated' : 'Manual'}`
        : `${FILTER_LABELS[key]} ${filters[key]}`
    );

  function update(key: keyof Filters, value: string): void {
    setFilters((previous) => ({ ...previous, [key]: value }));
  }

  return (
    <>
      <PageHeader
        title={frameworkLabel(framework)}
        backHref="/compliance"
        backLabel="← Back to Compliance"
        actions={
          <>
            <Link href={`/compliance/${framework}/report`} className={PRIMARY_BUTTON}>
              Report
            </Link>
            <Link href={`/compliance/${framework}/drift`} className={SECONDARY_BUTTON}>
              View drift
            </Link>
          </>
        }
      />
      <PageBody>
        <section className="mb-6" aria-busy={summary.status === 'loading'}>
          {summary.status === 'error' ? (
            <ErrorState error={summary.error} onRetry={summary.reload} />
          ) : summary.status !== 'success' ? (
            <LoadingState label="Loading assessment summary…" />
          ) : (
            <div className="grid grid-cols-2 gap-4 md:grid-cols-6">
              <SummaryTile
                label="Controls"
                value={summary.data.totalControls}
                hint="Checklist items, not resources"
              />
              <SummaryTile
                label="Passed"
                value={assessmentCounts(summary.data).passed}
                hint="Controls that met the check"
                tone="success"
              />
              <SummaryTile
                label="Failed"
                value={assessmentCounts(summary.data).failed}
                hint="Controls that did not meet it"
                tone="danger"
              />
              <SummaryTile
                label="Needs a person"
                value={assessmentCounts(summary.data).manual}
                hint="Waiting on human attestation"
                tone="warning"
              />
              <SummaryTile
                label="Machine-checkable"
                value={summary.data.automatedControls}
                hint="Khalifa can evaluate from the graph"
                tone="info"
              />
              <SummaryTile
                label="Auto coverage"
                value={`${summary.data.coveragePercent}%`}
                hint="Automated controls that got a result"
                tone="accent"
              />
            </div>
          )}
        </section>

        <Card flush>
          <form
            className="flex flex-wrap gap-4 border-b border-orange-100 bg-orange-50 p-4"
            onSubmit={(event) => event.preventDefault()}
          >
            <SelectField
              label={FILTER_LABELS.section}
              value={filters.section}
              onChange={(event) => update('section', event.target.value)}
            >
              <option value="">All sections</option>
              {sections.map((section) => (
                <option key={section} value={section}>
                  {section}
                </option>
              ))}
            </SelectField>
            <SelectField
              label={FILTER_LABELS.status}
              value={filters.status}
              onChange={(event) => update('status', event.target.value)}
            >
              <option value="">All statuses</option>
              <option value="PASS">Pass</option>
              <option value="FAIL">Fail</option>
              <option value="MANUAL">Manual</option>
              <option value="NOT_EVALUATED">Not evaluated</option>
              <option value="NOT_APPLICABLE">N/A</option>
            </SelectField>
            <SelectField
              label={FILTER_LABELS.severity}
              value={filters.severity}
              onChange={(event) => update('severity', event.target.value)}
            >
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </SelectField>
            <SelectField
              label={FILTER_LABELS.automated}
              value={filters.automated}
              onChange={(event) => update('automated', event.target.value)}
            >
              <option value="">All</option>
              <option value="true">Automated</option>
              <option value="false">Manual</option>
            </SelectField>
          </form>

          <div aria-busy={controls.status === 'loading'}>
            {controls.status === 'error' ? (
              <ErrorState error={controls.error} onRetry={controls.reload} className="m-4" />
            ) : controls.status !== 'success' ? (
              <LoadingState label="Loading controls…" />
            ) : filteredControls.length === 0 ? (
              activeFilters.length > 0 ? (
                <NoMatchesState
                  noun="controls"
                  activeFilters={activeFilters}
                  onClear={() => setFilters(NO_FILTERS)}
                />
              ) : (
                <EmptyState
                  title="No controls published"
                  description="This framework has no controls in the catalog yet."
                />
              )
            ) : (
              <Table caption={`${frameworkLabel(framework)} controls`}>
                <thead>
                  <tr>
                    <Th>Control ID</Th>
                    <Th>Title</Th>
                    <Th>Section</Th>
                    <Th>Severity</Th>
                    <Th>Type</Th>
                    <Th>Status</Th>
                    <Th>Related rules</Th>
                    <Th>Actions</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 bg-white">
                  {filteredControls.map((control) => (
                    <tr key={control.id} className="hover:bg-gray-50">
                      <Td className="whitespace-nowrap font-medium text-gray-900">{control.id}</Td>
                      <Td>
                        <div className="max-w-md truncate text-gray-900" title={control.title}>
                          {control.title}
                        </div>
                      </Td>
                      <Td className="whitespace-nowrap text-gray-500">{control.section}</Td>
                      <Td className="whitespace-nowrap">
                        <SeverityBadge severity={control.severity} tone="soft" />
                      </Td>
                      <Td className="whitespace-nowrap text-gray-500">
                        {control.automated ? 'Automated' : 'Manual'}
                      </Td>
                      <Td className="whitespace-nowrap">
                        <span className="inline-flex items-center gap-1">
                          <StatusBadge status={control.status} />
                          <RegionScopeBadge regions={control.regionsEvaluated} />
                        </span>
                      </Td>
                      <Td className="whitespace-nowrap text-gray-500">
                        {control.relatedRules?.join(', ') || '—'}
                      </Td>
                      <Td className="whitespace-nowrap">
                        <Link
                          href={`/compliance/${framework}/controls/${control.id}`}
                          className={LINK}
                        >
                          View
                        </Link>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </div>
        </Card>
      </PageBody>
    </>
  );
}
