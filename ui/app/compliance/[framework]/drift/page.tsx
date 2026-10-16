'use client';

import { useParams } from 'next/navigation';
import { getDriftReport } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { frameworkLabel } from '@/lib/compliance';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import {
  Badge,
  Card,
  PageBody,
  PageHeader,
  SeverityBadge,
  SummaryTile,
  Table,
  Td,
  Th,
  TONES,
} from '@/components/ui';

export default function DriftReportPage() {
  const { framework } = useParams<{ framework: string }>();
  const drift = useRequest((signal) => getDriftReport(framework, { signal }), [framework]);

  return (
    <>
      <PageHeader
        title="Configuration drift report"
        description="Detected compliance violations since the last assessment."
        backHref={`/compliance/${framework}`}
        backLabel={`← ${frameworkLabel(framework)}`}
        actions={
          drift.status === 'success' && (
            <Badge tone={TONES.severitySoft.critical}>
              {drift.data.totalDriftItems} drift items
            </Badge>
          )
        }
      />
      <PageBody>
        {drift.status === 'error' ? (
          <ErrorState error={drift.error} onRetry={drift.reload} />
        ) : drift.status !== 'success' ? (
          <LoadingState label="Loading drift report…" />
        ) : (
          <>
            <div className="mb-8 grid grid-cols-1 gap-4 md:grid-cols-4">
              <SummaryTile label="Critical" value={drift.data.criticalDrift} tone="danger" />
              <SummaryTile label="High" value={drift.data.highDrift} tone="danger" />
              <SummaryTile label="Medium" value={drift.data.mediumDrift} tone="warning" />
              <SummaryTile label="Low" value={drift.data.lowDrift} tone="info" />
            </div>

            <Card flush>
              {drift.data.driftItems.length === 0 ? (
                <EmptyState
                  title="No configuration drift detected"
                  description="All automated controls are currently passing."
                />
              ) : (
                <Table caption="Drift items">
                  <thead>
                    <tr>
                      <Th>Control ID</Th>
                      <Th>Title</Th>
                      <Th>Section</Th>
                      <Th>Severity</Th>
                      <Th>Detected</Th>
                      <Th>Related rules</Th>
                      <Th>Remediation</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 bg-white">
                    {drift.data.driftItems.map((item) => (
                      <tr key={item.controlId} className="hover:bg-gray-50">
                        <Td className="whitespace-nowrap font-medium text-gray-900">
                          {item.controlId}
                        </Td>
                        <Td className="font-medium text-gray-900">{item.controlTitle}</Td>
                        <Td className="whitespace-nowrap text-gray-500">{item.section}</Td>
                        <Td className="whitespace-nowrap">
                          <SeverityBadge severity={item.severity} tone="soft" />
                        </Td>
                        <Td className="whitespace-nowrap text-gray-500">
                          {new Date(item.detectedAt).toLocaleString()}
                        </Td>
                        <Td className="whitespace-nowrap text-gray-500">
                          {item.relatedRules?.join(', ') || '—'}
                        </Td>
                        <Td className="max-w-md text-gray-600">{item.remediation}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>

            <p className="mt-6 rounded-lg bg-orange-50 p-4 text-sm text-gray-600">
              <strong>Report generated:</strong> {new Date(drift.data.generatedAt).toLocaleString()}{' '}
              | <strong>Framework:</strong> {frameworkLabel(framework)}
            </p>
          </>
        )}
      </PageBody>
    </>
  );
}
