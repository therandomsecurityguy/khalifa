'use client';

import { getIntegrationsStatus } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import type { IntegrationsStatus } from '@/types';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import { Card, PageBody, PageHeader, Table, Td, Th } from '@/components/ui';

function SinkTable({ status }: { status: IntegrationsStatus }) {
  const sinks = Array.from(new Set([...status.configuredSinks, ...Object.keys(status.health)]));
  if (sinks.length === 0) {
    return (
      <EmptyState
        title="No sinks configured"
        description="Issue delivery is off until an issue sink is set in the API configuration."
      />
    );
  }
  return (
    <Table caption="Issue sinks">
      <thead>
        <tr>
          <Th>Sink</Th>
          <Th>Configured</Th>
          <Th>Health</Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-gray-200">
        {sinks.map((sink) => {
          const health = status.health[sink];
          return (
            <tr key={sink}>
              <Td className="text-gray-900">{sink}</Td>
              <Td className="text-gray-500">
                {status.configuredSinks.includes(sink) ? 'Yes' : 'No'}
              </Td>
              <Td
                className={
                  health === undefined
                    ? 'text-gray-500'
                    : health
                      ? 'text-green-700'
                      : 'text-red-700'
                }
              >
                {health === undefined ? 'Unknown' : health ? 'Healthy' : 'Unhealthy'}
              </Td>
            </tr>
          );
        })}
      </tbody>
    </Table>
  );
}

export default function IntegrationsPage() {
  const status = useRequest((signal) => getIntegrationsStatus({ signal }), []);

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Issue sink configuration and health from the API."
      />
      <PageBody>
        {status.status === 'error' ? (
          <ErrorState error={status.error} onRetry={status.reload} />
        ) : status.status !== 'success' ? (
          <LoadingState label="Loading integrations…" />
        ) : (
          <Card flush>
            <SinkTable status={status.data} />
          </Card>
        )}
      </PageBody>
    </>
  );
}
