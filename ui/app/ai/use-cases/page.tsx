'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import {
  createAiUseCase,
  formatTimestamp,
  getAiUseCaseCoverage,
  getAiUseCases,
  getSession,
} from '@/lib/api';
import { aiUseCaseHref, resourceHref } from '@/lib/routes';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import type { AiUseCase } from '@/types';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import {
  Badge,
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  RiskBadge,
  Spinner,
  Table,
  Td,
  TextField,
  Th,
  TONES,
} from '@/components/ui';

const MAX_UNREGISTERED_SHOWN = 10;

const STATUS_TONES: Record<AiUseCase['status'], string> = {
  draft: TONES.neutral,
  approved: TONES.success,
  retired: TONES.muted,
};

function CreateForm({ onCreated }: { onCreated: (id: string) => void }) {
  const [name, setName] = useState('');
  const [owner, setOwner] = useState('');
  const create = useAsyncAction(async () => {
    const created = await createAiUseCase({
      name: name.trim(),
      ...(owner.trim() ? { owner: owner.trim() } : {}),
    });
    onCreated(created.id);
  });

  return (
    <Card
      title="Register a use case"
      description="Creates a draft owned by you; assets and the lite impact assessment are filled in on the detail page."
    >
      <form
        className="space-y-4"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (name.trim()) void create.run();
        }}
      >
        <div className="grid gap-4 sm:grid-cols-2">
          <TextField
            label="Name"
            maxLength={200}
            placeholder="Support assistant"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <TextField
            label="Owner"
            maxLength={120}
            placeholder="Defaults to you"
            value={owner}
            onChange={(event) => setOwner(event.target.value)}
          />
        </div>
        {create.error !== undefined && <ErrorState error={create.error} />}
        <button type="submit" className={PRIMARY_BUTTON} disabled={create.pending || !name.trim()}>
          {create.pending && <Spinner />}
          {create.pending ? 'Creating…' : 'Create use case'}
        </button>
      </form>
    </Card>
  );
}

export default function AiUseCasesPage() {
  const router = useRouter();
  const useCases = useRequest((signal) => getAiUseCases({ signal }), []);
  const coverage = useRequest((signal) => getAiUseCaseCoverage({ signal }), []);
  const session = useRequest((signal) => getSession({ signal }), []);

  const role = session.status === 'success' ? session.data.role : null;
  const canManage = role === 'Admin' || role === 'Analyst';
  const items = useCases.status === 'success' ? useCases.data.items : [];

  return (
    <>
      <PageHeader
        title="AI use cases"
        description="The deployment's hand-maintained registry: what AI is used for, who owns it, and the lite impact assessment — joined against the collected estate so unregistered assets surface."
      />
      <PageBody>
        {useCases.status === 'error' ? (
          <ErrorState error={useCases.error} onRetry={useCases.reload} />
        ) : useCases.status !== 'success' ? (
          <LoadingState label="Loading AI use cases…" />
        ) : (
          <div className="space-y-6">
            {canManage && <CreateForm onCreated={(id) => router.push(aiUseCaseHref(id))} />}

            <Card
              title="Coverage"
              description={
                coverage.status === 'success'
                  ? `${coverage.data.useCaseCount} use case(s) cover ${coverage.data.registeredAssets} collected asset(s).`
                  : 'The registry joined against the collected AI estate.'
              }
            >
              {coverage.status === 'error' ? (
                <ErrorState error={coverage.error} onRetry={coverage.reload} />
              ) : coverage.status !== 'success' ? (
                <LoadingState label="Loading coverage…" />
              ) : coverage.data.unregistered.length === 0 && coverage.data.missing.length === 0 ? (
                <p className="text-sm text-gray-600">
                  Every collected AI asset is covered, and every registered asset is in the graph.
                </p>
              ) : (
                <div className="space-y-4 text-sm">
                  <div>
                    <h3 className="font-medium text-gray-900">
                      Collected assets no use case covers ({coverage.data.unregistered.length})
                    </h3>
                    {coverage.data.unregistered.length === 0 ? (
                      <p className="mt-1 text-gray-600">None.</p>
                    ) : (
                      <ul className="mt-1 space-y-0.5">
                        {coverage.data.unregistered
                          .slice(0, MAX_UNREGISTERED_SHOWN)
                          .map((asset) => (
                            <li key={asset.arn}>
                              <Link href={resourceHref(asset.arn)} className={LINK}>
                                {asset.name ?? asset.arn}
                              </Link>{' '}
                              <span className="text-gray-500">
                                ({asset.label}
                                {asset.region ? `, ${asset.region}` : ''})
                              </span>
                            </li>
                          ))}
                      </ul>
                    )}
                  </div>
                  <div>
                    <h3 className="font-medium text-gray-900">
                      Registered assets not in the graph ({coverage.data.missing.length})
                    </h3>
                    {coverage.data.missing.length === 0 ? (
                      <p className="mt-1 text-gray-600">None.</p>
                    ) : (
                      <ul className="mt-1 space-y-0.5">
                        {coverage.data.missing.map((entry) => (
                          <li key={`${entry.useCaseId}:${entry.arn}`}>
                            <Link href={aiUseCaseHref(entry.useCaseId)} className={LINK}>
                              {entry.useCaseId}
                            </Link>{' '}
                            <span className="text-gray-500">{entry.arn}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                  {coverage.data.truncated && (
                    <p className="text-xs text-gray-500">
                      Lists are bounded; more exists than shown here.
                    </p>
                  )}
                </div>
              )}
            </Card>

            <Card title={`Use cases (${items.length})`} flush>
              {items.length === 0 ? (
                <EmptyState
                  title="No use cases registered"
                  description="Register the first one above; governance questions about unregistered AI usage are exactly what this registry answers."
                />
              ) : (
                <Table caption="AI use cases">
                  <thead>
                    <tr>
                      <Th>Name</Th>
                      <Th>Status</Th>
                      <Th>Owner</Th>
                      <Th>Risk tier</Th>
                      <Th>Assets</Th>
                      <Th>Updated</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {items.map((useCase) => (
                      <tr key={useCase.id}>
                        <Td className="text-gray-900">
                          <Link href={aiUseCaseHref(useCase.id)} className={LINK}>
                            {useCase.name}
                          </Link>
                        </Td>
                        <Td>
                          <Badge tone={STATUS_TONES[useCase.status]}>{useCase.status}</Badge>
                        </Td>
                        <Td className="text-gray-500">{useCase.owner || '—'}</Td>
                        <Td>
                          {useCase.assessment ? (
                            <RiskBadge level={useCase.assessment.riskTier} />
                          ) : (
                            <span className="text-gray-400">—</span>
                          )}
                        </Td>
                        <Td className="text-gray-500">{useCase.assets.length}</Td>
                        <Td className="text-gray-500">{formatTimestamp(useCase.updatedAt)}</Td>
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
