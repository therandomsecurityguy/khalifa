'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { getControlDetails, isNotFound } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { frameworkLabel } from '@/lib/compliance';
import { formatNodeLabel } from '@/lib/graph-labels';
import { ErrorState, LoadingState, NotFoundState } from '@/components/states';
import {
  Badge,
  Card,
  LINK,
  PageBody,
  PageHeader,
  RegionScopeBadge,
  SeverityBadge,
  StatusBadge,
  Table,
  Td,
  Th,
  TONES,
} from '@/components/ui';

export default function ControlDetailPage() {
  const { framework, controlId } = useParams<{ framework: string; controlId: string }>();
  const control = useRequest(
    (signal) => getControlDetails(framework, controlId, { signal }),
    [framework, controlId]
  );
  const back = {
    backHref: `/compliance/${framework}`,
    backLabel: `← ${frameworkLabel(framework)}`,
  };

  if (control.status === 'error') {
    if (isNotFound(control.error)) {
      return (
        <NotFoundState
          title={controlId}
          message={`Control ${controlId} is not part of ${frameworkLabel(framework)}.`}
          {...back}
        />
      );
    }
    return (
      <>
        <PageHeader title={controlId} {...back} />
        <PageBody>
          <ErrorState error={control.error} onRetry={control.reload} />
        </PageBody>
      </>
    );
  }

  if (control.status !== 'success') {
    return (
      <>
        <PageHeader title={controlId} {...back} />
        <PageBody>
          <LoadingState label="Loading control details…" />
        </PageBody>
      </>
    );
  }

  const detail = control.data;

  return (
    <>
      <PageHeader
        title={detail.title}
        description={`Control ID: ${detail.id}`}
        {...back}
        actions={
          <>
            <StatusBadge status={detail.status} />
            <RegionScopeBadge regions={detail.regionsEvaluated} />
            <SeverityBadge severity={detail.severity} tone="soft" />
            <Badge tone={detail.automated ? TONES.info : TONES.neutral}>
              {detail.automated ? 'Automated' : 'Manual'}
            </Badge>
          </>
        }
      />
      <PageBody>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            <Card title="Description">
              <p className="text-gray-600">{detail.description || 'No description available.'}</p>
            </Card>

            <Card title="Remediation guidance">
              <p className="text-gray-600">
                {detail.remediationHint ||
                  'Review and remediate the identified security issue according to best practices.'}
              </p>
            </Card>

            {detail.relatedRules && detail.relatedRules.length > 0 && (
              <Card title="Related security rules">
                <div className="flex flex-wrap gap-2">
                  {detail.relatedRules.map((ruleId) => (
                    <Badge key={ruleId} tone={TONES.accent}>
                      {ruleId}
                    </Badge>
                  ))}
                </div>
              </Card>
            )}

            {detail.mappedControls && detail.mappedControls.length > 0 && (
              <Card title="Evidenced by">
                <ul className="space-y-2">
                  {detail.mappedControls.map((mapped) => (
                    <li
                      key={`${mapped.framework}:${mapped.controlId}`}
                      className="flex flex-wrap items-center gap-3"
                    >
                      <StatusBadge status={mapped.status} />
                      <Link
                        href={`/compliance/${encodeURIComponent(mapped.framework)}/controls/${encodeURIComponent(mapped.controlId)}`}
                        className={LINK}
                      >
                        {frameworkLabel(mapped.framework)} · {mapped.controlId}
                      </Link>
                    </li>
                  ))}
                </ul>
                <p className="mt-3 text-sm text-gray-600">
                  This requirement passes only while every mapped control passes; a failing or
                  unevaluated control keeps it from passing.
                </p>
              </Card>
            )}

            {detail.citedBy && detail.citedBy.length > 0 && (
              <Card title="Cited by framework requirements">
                <ul className="space-y-2">
                  {detail.citedBy.map((citation) => (
                    <li
                      key={`${citation.framework}:${citation.requirement}`}
                      className="flex flex-wrap items-center gap-3"
                    >
                      <Badge tone={TONES.accent}>{frameworkLabel(citation.framework)}</Badge>
                      <Link
                        href={`/compliance/${encodeURIComponent(citation.framework)}/controls/${encodeURIComponent(citation.requirement)}`}
                        className={LINK}
                      >
                        {citation.requirement} — {citation.title}
                      </Link>
                    </li>
                  ))}
                </ul>
              </Card>
            )}

            {detail.evidence && detail.evidence.length > 0 && (
              <Card title="Evidence" flush>
                <Table caption="Evidence">
                  <thead>
                    <tr>
                      <Th>Resource</Th>
                      <Th>Type</Th>
                      <Th>Status</Th>
                      <Th>Collected</Th>
                      <Th>Details</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200 bg-white">
                    {detail.evidence.map((evidence) => (
                      <tr key={evidence.resourceId} className="hover:bg-gray-50">
                        <Td className="max-w-xs truncate whitespace-nowrap font-medium text-gray-900">
                          {evidence.resourceId}
                        </Td>
                        <Td className="whitespace-nowrap text-gray-500">
                          {formatNodeLabel(evidence.resourceType)}
                        </Td>
                        <Td className="whitespace-nowrap">
                          <StatusBadge status={evidence.status} />
                        </Td>
                        <Td className="whitespace-nowrap text-gray-500">
                          {new Date(evidence.collectedAt).toLocaleString()}
                        </Td>
                        <Td className="max-w-md text-gray-500">
                          <pre className="whitespace-pre-wrap text-xs">
                            {JSON.stringify(evidence.details, null, 2)}
                          </pre>
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </Card>
            )}

            {detail.relatedIssues && detail.relatedIssues.length > 0 && (
              <Card title="Related risk rules">
                <ul className="divide-y divide-gray-200">
                  {detail.relatedIssues.map((rule) => (
                    <li key={rule.ruleId} className="py-3 first:pt-0 last:pb-0">
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <span className="font-medium text-gray-900">{rule.ruleId}</span>
                          <span className="ml-2 text-sm text-gray-500">{rule.ruleName}</span>
                        </div>
                        {rule.openCount === null ? (
                          <Badge tone={TONES.neutral}>Unavailable</Badge>
                        ) : rule.openCount === 0 ? (
                          <Badge tone={TONES.neutral}>No open issues</Badge>
                        ) : (
                          <div className="flex items-center gap-2">
                            <Badge tone={TONES.neutral}>{rule.openCount} open</Badge>
                            {rule.highestSeverity && (
                              <SeverityBadge severity={rule.highestSeverity} tone="soft" />
                            )}
                          </div>
                        )}
                      </div>
                      {rule.issues.length > 0 && (
                        <ul className="mt-2 space-y-1">
                          {rule.issues.map((issue) => (
                            <li key={issue.id} className="flex items-center gap-2 text-sm">
                              <SeverityBadge severity={issue.severity} tone="soft" />
                              <Link href={`/issues/${issue.id}`} className={`truncate ${LINK}`}>
                                {issue.resourceName || issue.resourceId || issue.id}
                              </Link>
                            </li>
                          ))}
                          {rule.openCount !== null && rule.openCount > rule.issues.length && (
                            <li className="text-sm text-gray-500">
                              and {rule.openCount - rule.issues.length} more
                            </li>
                          )}
                        </ul>
                      )}
                    </li>
                  ))}
                </ul>
              </Card>
            )}
          </div>

          <div className="space-y-6">
            <Card title="Control metadata">
              <dl className="divide-y divide-gray-200">
                <div className="flex justify-between gap-3 py-3 first:pt-0">
                  <dt className="text-sm font-medium text-gray-500">Framework</dt>
                  <dd className="text-sm text-gray-900">{frameworkLabel(framework)}</dd>
                </div>
                <div className="flex justify-between gap-3 py-3">
                  <dt className="text-sm font-medium text-gray-500">Section</dt>
                  <dd className="text-sm text-gray-900">{detail.section}</dd>
                </div>
                <div className="flex justify-between gap-3 py-3">
                  <dt className="text-sm font-medium text-gray-500">Severity</dt>
                  <dd>
                    <SeverityBadge severity={detail.severity} tone="soft" />
                  </dd>
                </div>
                <div className="flex justify-between gap-3 py-3">
                  <dt className="text-sm font-medium text-gray-500">Type</dt>
                  <dd className="text-sm text-gray-900">
                    {detail.automated ? 'Automated' : 'Manual'}
                  </dd>
                </div>
                <div className="flex justify-between gap-3 py-3 last:pb-0">
                  <dt className="text-sm font-medium text-gray-500">Last evaluated</dt>
                  <dd className="text-sm text-gray-900">
                    {detail.lastEvaluated
                      ? new Date(detail.lastEvaluated).toLocaleString()
                      : 'Never'}
                  </dd>
                </div>
              </dl>
            </Card>

            {detail.evidenceRequirements && detail.evidenceRequirements.length > 0 && (
              <Card title="Evidence requirements">
                <ul className="list-inside list-disc space-y-2 text-gray-600">
                  {detail.evidenceRequirements.map((requirement) => (
                    <li key={requirement}>{requirement}</li>
                  ))}
                </ul>
              </Card>
            )}
          </div>
        </div>
      </PageBody>
    </>
  );
}
