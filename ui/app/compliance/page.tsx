'use client';

import Link from 'next/link';
import { assessmentCounts, formatTimestamp, getFrameworks } from '@/lib/api';
import type { ComplianceFrameworkSummary } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { FRAMEWORKS, frameworkLabel } from '@/lib/compliance';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import { Card, LINK, PageBody, PageHeader, SummaryTile } from '@/components/ui';

function FrameworkCard({ framework }: { framework: ComplianceFrameworkSummary }) {
  const counts = assessmentCounts(framework);
  const coverage = framework.coveragePercent ?? 0;
  return (
    <Card flush>
      <div className="p-6">
        <div className="mb-4 flex flex-col md:flex-row md:items-center md:justify-between">
          <div>
            <Link
              href={`/compliance/${framework.framework}`}
              className="text-2xl font-bold text-gray-900 hover:text-indigo-600"
            >
              {frameworkLabel(framework.framework)}
            </Link>
            <p className="mt-1 text-sm text-gray-500">
              {FRAMEWORKS[framework.framework]?.description}
            </p>
          </div>
          <div className="mt-4 flex items-center space-x-4 md:mt-0">
            <div className="text-right">
              <div className="text-3xl font-bold text-gray-900">{coverage}%</div>
              <div className="text-sm text-gray-500">Coverage</div>
            </div>
            <svg
              viewBox="0 0 36 36"
              className="h-24 w-24 -rotate-90"
              role="img"
              aria-label={`${coverage}% coverage`}
            >
              <circle cx="18" cy="18" r="15.915" fill="none" stroke="#e5e7eb" strokeWidth="3" />
              <circle
                cx="18"
                cy="18"
                r="15.915"
                fill="none"
                stroke="#4f46e5"
                strokeWidth="3"
                strokeDasharray={`${coverage}, 100`}
                strokeLinecap="round"
                className="transition-all duration-500"
              />
            </svg>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
          <SummaryTile label="Passed" value={counts.passed} tone="success" />
          <SummaryTile label="Failed" value={counts.failed} tone="danger" />
          <SummaryTile label="Manual" value={counts.manual} tone="warning" />
          <SummaryTile label="Not evaluated" value={counts.notEvaluated} />
          <SummaryTile label="N/A" value={counts.notApplicable} tone="info" />
        </div>

        <p className="mt-4 text-sm text-gray-500">
          Last assessed:{' '}
          <span className="font-medium">{formatTimestamp(framework.lastAssessment)}</span>
          <span className="mx-2">|</span>
          Version: {framework.version}
        </p>
      </div>
      <div className="border-t border-orange-100 bg-orange-50 px-6 py-4">
        <Link href={`/compliance/${framework.framework}`} className={`text-sm ${LINK}`}>
          View details →
        </Link>
      </div>
    </Card>
  );
}

export default function CompliancePage() {
  const frameworks = useRequest((signal) => getFrameworks({ signal }), []);

  return (
    <>
      <PageHeader
        title="Compliance posture"
        description="Monitor the CIS AWS Foundations Benchmark and the Khalifa baseline"
      />
      <PageBody>
        {frameworks.status === 'error' ? (
          <ErrorState error={frameworks.error} onRetry={frameworks.reload} />
        ) : frameworks.status !== 'success' ? (
          <LoadingState label="Loading compliance frameworks…" />
        ) : frameworks.data.frameworks.length === 0 ? (
          <Card flush>
            <EmptyState
              title="No compliance frameworks available"
              description="The compliance job has not published an assessment yet."
            />
          </Card>
        ) : (
          <div className="space-y-6">
            {frameworks.data.frameworks.map((framework) => (
              <FrameworkCard key={framework.framework} framework={framework} />
            ))}
          </div>
        )}
      </PageBody>
    </>
  );
}
