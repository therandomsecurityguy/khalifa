'use client';

import { useState } from 'react';
import { useParams } from 'next/navigation';
import { assessmentCounts, getComplianceReport, getComplianceReportCsv } from '@/lib/api';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import { frameworkLabel } from '@/lib/compliance';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import {
  Card,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  SeverityBadge,
  Spinner,
  StatusBadge,
  StatusMessage,
  SummaryTile,
  Table,
  Td,
  Th,
} from '@/components/ui';

function saveBlob(blob: Blob, filename: string): void {
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(anchor);
}

export default function ComplianceReportPage() {
  const { framework } = useParams<{ framework: string }>();
  const report = useRequest((signal) => getComplianceReport(framework, { signal }), [framework]);
  const [downloaded, setDownloaded] = useState<string | null>(null);
  const download = useAsyncAction(async () => {
    setDownloaded(null);
    const filename = `${framework}-compliance-report-${new Date().toISOString().split('T')[0]}.csv`;
    saveBlob(await getComplianceReportCsv(framework), filename);
    setDownloaded(filename);
  });
  const back = {
    backHref: `/compliance/${framework}`,
    backLabel: `← ${frameworkLabel(framework)}`,
  };
  const counts = assessmentCounts(report.status === 'success' ? report.data : null);

  return (
    <>
      <PageHeader
        title="Compliance report"
        {...back}
        actions={
          <button
            type="button"
            className={PRIMARY_BUTTON}
            disabled={download.pending}
            onClick={() => void download.run()}
          >
            {download.pending && <Spinner />}
            {download.pending ? 'Preparing CSV…' : 'Download CSV'}
          </button>
        }
      />
      <PageBody>
        {download.error !== undefined && <ErrorState error={download.error} className="mb-6" />}
        {downloaded && (
          <StatusMessage tone="success" className="mb-6">
            Downloaded {downloaded}.
          </StatusMessage>
        )}

        {report.status === 'error' ? (
          <ErrorState error={report.error} onRetry={report.reload} />
        ) : report.status !== 'success' ? (
          <LoadingState label="Loading report…" />
        ) : (
          <>
            <section className="mb-8">
              <h2 className="mb-4 text-xl font-bold text-gray-900">Executive summary</h2>
              <div className="grid grid-cols-2 gap-4 md:grid-cols-6">
                <SummaryTile label="Total controls" value={counts.totalControls} />
                <SummaryTile label="Passed" value={counts.passed} tone="success" />
                <SummaryTile label="Failed" value={counts.failed} tone="danger" />
                <SummaryTile label="Manual" value={counts.manual} tone="warning" />
                <SummaryTile label="Not evaluated" value={counts.notEvaluated} />
                <SummaryTile label="Coverage" value={`${counts.coveragePercent}%`} tone="accent" />
              </div>
              <p className="mt-6 rounded-lg bg-orange-50 p-4 text-sm text-gray-700">
                <strong>Assessment date:</strong>{' '}
                {new Date(report.data.generatedAt).toLocaleString()} | <strong>Framework:</strong>{' '}
                {frameworkLabel(framework)} | <strong>Coverage:</strong> {counts.coveragePercent}%
                of automated controls evaluated
              </p>
            </section>

            <Card flush>
              {report.data.controls.length === 0 ? (
                <EmptyState
                  title="No controls in this report"
                  description="The assessment has no control results to show."
                />
              ) : (
                <Table caption="Control results">
                  <thead>
                    <tr>
                      <Th>Control ID</Th>
                      <Th>Title</Th>
                      <Th>Section</Th>
                      <Th>Severity</Th>
                      <Th>Type</Th>
                      <Th>Status</Th>
                      <Th>Issues</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 bg-white">
                    {report.data.controls.map((result) => (
                      <tr key={result.control.id} className="hover:bg-gray-50">
                        <Td className="whitespace-nowrap font-medium text-gray-900">
                          {result.control.id}
                        </Td>
                        <Td>
                          <div
                            className="max-w-md truncate text-gray-900"
                            title={result.control.title}
                          >
                            {result.control.title}
                          </div>
                        </Td>
                        <Td className="whitespace-nowrap text-gray-500">
                          {result.control.section}
                        </Td>
                        <Td className="whitespace-nowrap">
                          <SeverityBadge severity={result.control.severity} tone="soft" />
                        </Td>
                        <Td className="whitespace-nowrap text-gray-500">
                          {result.control.automated ? 'Automated' : 'Manual'}
                        </Td>
                        <Td className="whitespace-nowrap">
                          <StatusBadge status={result.status} />
                        </Td>
                        <Td className="text-gray-500">
                          {result.issues && result.issues.length > 0 ? (
                            <ul className="list-inside list-disc">
                              {result.issues.map((issue) => (
                                <li key={issue}>{issue}</li>
                              ))}
                            </ul>
                          ) : (
                            '—'
                          )}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
          </>
        )}
      </PageBody>
    </>
  );
}
