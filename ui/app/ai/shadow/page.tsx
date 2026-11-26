'use client';

import { getAccounts, getAiShadow, formatTimestamp } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { Card, PageBody, PageHeader, Table, Td, Th } from '@/components/ui';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';

const FRESHNESS_NOTES: Record<string, string> = {
  fresh: 'The analyzer recorded an anomaly within the last two days.',
  aging:
    'The last analyzer marker is more than two days old — recent usage may not be reflected yet.',
  stale: 'The last analyzer marker is more than four days old; treat this view as out of date.',
  unknown:
    'The analyzer has recorded no marker in the graph. It writes vertices only when it finds something, so this is unknown freshness, not a clean estate.',
};

export default function ShadowAiPage() {
  const shadow = useRequest((signal) => getAiShadow({}, { signal }), []);
  const accounts = useRequest((signal) => getAccounts({ signal }), []);

  const names = new Map(
    (accounts.status === 'success' ? accounts.data.accounts : []).map((account) => [
      account.id,
      account.name,
    ])
  );
  const coverage = shadow.status === 'success' ? shadow.data.coverage : null;
  const anomalies = shadow.status === 'success' ? shadow.data.anomalies : [];

  return (
    <>
      <PageHeader
        title="Shadow AI"
        description="Bedrock and SageMaker API usage by principals outside the deployment's approved allowlist (AI_PRINCIPAL_ALLOWLIST), from the CloudTrail analyzer's last windows."
      />
      <PageBody>
        {shadow.status === 'error' ? (
          <ErrorState error={shadow.error} onRetry={shadow.reload} />
        ) : shadow.status !== 'success' ? (
          <LoadingState label="Loading shadow-AI usage…" />
        ) : (
          <div className="space-y-6">
            <Card title="Coverage" description={coverage?.detail ?? ''}>
              <dl className="grid gap-4 text-sm sm:grid-cols-3">
                <div>
                  <dt className="text-xs font-medium uppercase tracking-wide text-gray-500">
                    Plane
                  </dt>
                  <dd className="mt-1 text-gray-900">{coverage?.plane ?? 'unknown'}</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium uppercase tracking-wide text-gray-500">
                    Window
                  </dt>
                  <dd className="mt-1 text-gray-900">last {coverage?.windowDays ?? 7} days</dd>
                </div>
                <div>
                  <dt className="text-xs font-medium uppercase tracking-wide text-gray-500">
                    Last analyzer marker
                  </dt>
                  <dd className="mt-1 text-gray-900">
                    {coverage?.lastAnomalyObservedAt
                      ? formatTimestamp(coverage.lastAnomalyObservedAt)
                      : 'none recorded'}
                  </dd>
                </div>
              </dl>
              <p className="mt-4 text-sm text-gray-600">
                {FRESHNESS_NOTES[coverage?.freshness ?? 'unknown']}
              </p>
            </Card>

            <Card title={`Anomalies (${anomalies.length})`} flush>
              {anomalies.length === 0 ? (
                <EmptyState
                  title="No shadow-AI usage recorded"
                  description="That is the management-plane view: model-invocation calls appear only when CloudTrail data events are enabled, and an empty list is not proof that no AI usage exists."
                />
              ) : (
                <Table caption="Active shadow-AI anomalies">
                  <thead>
                    <tr>
                      <Th>Principal</Th>
                      <Th>Account</Th>
                      <Th>Source IP</Th>
                      <Th>Calls</Th>
                      <Th>Events</Th>
                      <Th>Last seen</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {anomalies.map((anomaly) => (
                      <tr key={anomaly.arn}>
                        <Td className="font-mono text-xs text-gray-900">{anomaly.principalArn}</Td>
                        <Td className="text-gray-500">
                          {names.get(anomaly.accountId) ?? anomaly.accountId ?? '—'}
                        </Td>
                        <Td className="text-gray-500">{anomaly.sourceIp || '—'}</Td>
                        <Td className="text-gray-600">{anomaly.detail || '—'}</Td>
                        <Td className="text-gray-500">{anomaly.eventCount ?? '—'}</Td>
                        <Td className="text-gray-500">{formatTimestamp(anomaly.lastSeen)}</Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card>
          </div>
        )}
      </PageBody>
    </>
  );
}
