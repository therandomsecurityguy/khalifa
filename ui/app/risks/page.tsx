'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { createRisk, formatTimestamp, getRisks, getSession } from '@/lib/api';
import { riskHref } from '@/lib/routes';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import type { RiskRegisterEntry } from '@/types';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import {
  Badge,
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  RiskBadge,
  SelectField,
  Spinner,
  Table,
  Td,
  TextField,
  Th,
  TONES,
} from '@/components/ui';

const STATUS_TONES: Record<RiskRegisterEntry['status'], string> = {
  open: TONES.danger,
  monitoring: TONES.warning,
  accepted: TONES.neutral,
  closed: TONES.success,
};

const RATINGS = [1, 2, 3, 4, 5];

function isOverdue(nextReviewAt: string | null): boolean {
  return Boolean(nextReviewAt && Date.parse(nextReviewAt) < Date.now());
}

function CreateForm({ onCreated }: { onCreated: (id: string) => void }) {
  const [title, setTitle] = useState('');
  const [likelihood, setLikelihood] = useState(3);
  const [impact, setImpact] = useState(3);
  const create = useAsyncAction(async () => {
    const created = await createRisk({
      title: title.trim(),
      inherent: { likelihood, impact },
    });
    onCreated(created.id);
  });

  return (
    <Card
      title="Register a risk"
      description="Requires the inherent likelihood and impact up front; the rest — residual rating, treatment, acceptance, links — is filled in on the detail page."
    >
      <form
        className="space-y-4"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          if (title.trim()) void create.run();
        }}
      >
        <div className="grid gap-4 sm:grid-cols-3">
          <TextField
            label="Title"
            maxLength={200}
            placeholder="Shared admin role reaches crown jewels"
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
          <SelectField
            label="Inherent likelihood (1-5)"
            value={likelihood}
            onChange={(event) => setLikelihood(Number(event.target.value))}
          >
            {RATINGS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </SelectField>
          <SelectField
            label="Inherent impact (1-5)"
            value={impact}
            onChange={(event) => setImpact(Number(event.target.value))}
          >
            {RATINGS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </SelectField>
        </div>
        {create.error !== undefined && <ErrorState error={create.error} />}
        <button type="submit" className={PRIMARY_BUTTON} disabled={create.pending || !title.trim()}>
          {create.pending && <Spinner />}
          {create.pending ? 'Creating…' : 'Create risk'}
        </button>
      </form>
    </Card>
  );
}

export default function RiskRegisterPage() {
  const router = useRouter();
  const risks = useRequest((signal) => getRisks({ signal }), []);
  const session = useRequest((signal) => getSession({ signal }), []);

  const role = session.status === 'success' ? session.data.role : null;
  const canManage = role === 'Admin' || role === 'Analyst';
  const items = risks.status === 'success' ? risks.data.items : [];

  return (
    <>
      <PageHeader
        title="Risk register"
        description="Workflow risk objects over the collected estate: inherent and residual ratings, treatment, acceptance with expiry, review cadence, and links to issues and controls."
      />
      <PageBody>
        {risks.status === 'error' ? (
          <ErrorState error={risks.error} onRetry={risks.reload} />
        ) : risks.status !== 'success' ? (
          <LoadingState label="Loading risk register…" />
        ) : (
          <div className="space-y-6">
            {canManage && <CreateForm onCreated={(id) => router.push(riskHref(id))} />}

            <Card title={`Risks (${items.length})`} flush>
              {items.length === 0 ? (
                <EmptyState
                  title="No risks registered"
                  description="Register the first one above; a register that never disagrees with reality is a register nobody updates."
                />
              ) : (
                <Table caption="Risk register">
                  <thead>
                    <tr>
                      <Th>Risk</Th>
                      <Th>Category</Th>
                      <Th>Status</Th>
                      <Th>Owner</Th>
                      <Th>Inherent</Th>
                      <Th>Residual</Th>
                      <Th>Next review</Th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {items.map((risk) => (
                      <tr key={risk.id}>
                        <Td className="text-gray-900">
                          <Link href={riskHref(risk.id)} className={LINK}>
                            {risk.title}
                          </Link>
                        </Td>
                        <Td className="text-gray-500">{risk.category}</Td>
                        <Td>
                          <Badge tone={STATUS_TONES[risk.status]}>{risk.status}</Badge>
                        </Td>
                        <Td className="text-gray-500">{risk.owner || '—'}</Td>
                        <Td>
                          <span className="inline-flex items-center gap-2">
                            <RiskBadge level={risk.inherentLevel} />
                            <span className="text-xs text-gray-500">{risk.inherentScore}</span>
                          </span>
                        </Td>
                        <Td>
                          {risk.residualLevel === null ? (
                            <span className="text-gray-400">—</span>
                          ) : (
                            <span className="inline-flex items-center gap-2">
                              <RiskBadge level={risk.residualLevel} />
                              <span className="text-xs text-gray-500">{risk.residualScore}</span>
                            </span>
                          )}
                        </Td>
                        <Td
                          className={
                            isOverdue(risk.nextReviewAt)
                              ? 'font-medium text-red-700'
                              : 'text-gray-500'
                          }
                        >
                          {risk.nextReviewAt ? formatTimestamp(risk.nextReviewAt) : '—'}
                          {isOverdue(risk.nextReviewAt) && ' — overdue'}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
              {risks.data.truncated && (
                <p className="border-t border-gray-200 px-6 py-2 text-xs text-gray-500">
                  The register is bounded; more risks exist than shown here.
                </p>
              )}
            </Card>
          </div>
        )}
      </PageBody>
    </>
  );
}
