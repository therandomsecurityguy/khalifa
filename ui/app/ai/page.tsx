'use client';

import Link from 'next/link';
import { getAccounts, getAiInventory } from '@/lib/api';
import { aiAgentHref, resourceHref } from '@/lib/routes';
import { useRequest } from '@/lib/use-request';
import type { AiInventoryItem, AiInventorySection, AiInventoryType } from '@/types';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import { Card, LINK, PageBody, PageHeader, Table, Td, Th } from '@/components/ui';

// Display order; the API returns the same fixed set, but agents and compute
// belong at the top of the page and reference data at the bottom.
const SECTION_ORDER: AiInventoryType[] = [
  'agents',
  'endpoints',
  'notebooks',
  'domains',
  'knowledgeBases',
  'models',
  'guardrails',
];

const SECTION_LABELS: Record<AiInventoryType, string> = {
  agents: 'AI agents',
  endpoints: 'SageMaker endpoints',
  notebooks: 'SageMaker notebooks',
  domains: 'Studio domains',
  knowledgeBases: 'Knowledge bases',
  models: 'Custom models',
  guardrails: 'Guardrails',
};

const SECTION_DESCRIPTIONS: Record<AiInventoryType, string> = {
  agents:
    'Bedrock agents and AgentCore runtimes, with the role each runs as and whether a guardrail protects it.',
  endpoints:
    'SageMaker endpoints with data capture, KMS, and network facts read from their configuration.',
  notebooks:
    'SageMaker notebook instances: direct internet access, root access, and volume encryption.',
  domains: 'SageMaker Studio domains: auth mode, app network access, and execution role.',
  knowledgeBases: 'Bedrock knowledge bases, their service role, and the S3 buckets they ground on.',
  models: 'Custom models this account owns.',
  guardrails: 'Bedrock guardrails that can protect agents.',
};

function factText(value: string | number | boolean): string {
  if (value === true) return 'yes';
  if (value === false) return 'no';
  return String(value);
}

function FactsCell({ facts }: { facts: AiInventoryItem['facts'] }) {
  const entries = Object.entries(facts).slice(0, 4);
  if (entries.length === 0) return <span className="text-gray-400">—</span>;
  return (
    <span>
      {entries.map(([key, value]) => `${key.replace(/_/g, ' ')}: ${factText(value)}`).join(' · ')}
    </span>
  );
}

function Section({
  section,
  accountName,
}: {
  section: AiInventorySection;
  accountName: (id: string | null) => string | null;
}) {
  const label = SECTION_LABELS[section.type];
  const description = [
    SECTION_DESCRIPTIONS[section.type],
    section.truncated && section.count !== null
      ? `Showing the first ${section.items.length} of ${section.count}.`
      : null,
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <Card
      title={`${label}${section.count !== null ? ` (${section.count})` : ''}`}
      description={description}
      flush
    >
      {section.items.length === 0 ? (
        <EmptyState
          title={`No ${label.toLowerCase()} collected`}
          description="The collector records these read-only; none exist in the collected accounts yet."
        />
      ) : (
        <Table caption={label}>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Status</Th>
              <Th>Account</Th>
              <Th>Region</Th>
              <Th>Facts</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {section.items.map((item) => (
              <tr key={item.arn}>
                <Td className="text-gray-900">
                  <Link
                    href={
                      section.type === 'agents' ? aiAgentHref(item.arn) : resourceHref(item.arn)
                    }
                    className={LINK}
                  >
                    {item.name ?? item.arn}
                  </Link>
                </Td>
                <Td className="text-gray-500">{item.status ?? '—'}</Td>
                <Td className="text-gray-500">
                  {accountName(item.account_id) ?? item.account_id ?? '—'}
                </Td>
                <Td className="text-gray-500">{item.region ?? '—'}</Td>
                <Td className="text-gray-600">
                  <FactsCell facts={item.facts} />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

export default function AiInventoryPage() {
  const inventory = useRequest((signal) => getAiInventory({}, { signal }), []);
  const accounts = useRequest((signal) => getAccounts({ signal }), []);

  // Account names are a convenience; an unresolved id renders as itself.
  const names = new Map(
    (accounts.status === 'success' ? accounts.data.accounts : []).map((account) => [
      account.id,
      account.name,
    ])
  );
  const byType = new Map(
    (inventory.status === 'success' ? inventory.data.types : []).map((section) => [
      section.type,
      section,
    ])
  );

  return (
    <>
      <PageHeader
        title="AI inventory"
        description="Bedrock agents, knowledge bases, guardrails and custom models, AgentCore runtimes, and SageMaker endpoints, notebooks and Studio domains — collected agentlessly and read-only."
      />
      <PageBody>
        {inventory.status === 'error' ? (
          <ErrorState error={inventory.error} onRetry={inventory.reload} />
        ) : inventory.status !== 'success' ? (
          <LoadingState label="Loading AI inventory…" />
        ) : (
          <div className="space-y-6">
            {SECTION_ORDER.filter((type) => byType.has(type)).map((type) => (
              <Section
                key={type}
                section={byType.get(type) as AiInventorySection}
                accountName={(id) => (id ? (names.get(id) ?? null) : null)}
              />
            ))}
          </div>
        )}
      </PageBody>
    </>
  );
}
