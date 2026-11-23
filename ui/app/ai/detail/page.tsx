'use client';

import Link from 'next/link';
import { Suspense, type ReactNode } from 'react';
import { useSearchParams } from 'next/navigation';
import { getAiAgent, isNotFound } from '@/lib/api';
import { resourceHref } from '@/lib/routes';
import { useRequest } from '@/lib/use-request';
import type { AiAgentDetail, GraphVertex } from '@/types';
import { ErrorState, LoadingState, NotFoundState } from '@/components/states';
import { Badge, Card, LINK, PageBody, PageHeader, SeverityBadge, TONES } from '@/components/ui';

const BACK = { backHref: '/ai', backLabel: '← Back to AI inventory' };
// Both agent shapes: classic `agent/<id>` and AgentCore `runtime/<id>`. The API
// checks this too; checking here avoids a request for a bad link.
const AGENT_ARN =
  /^arn:aws(?:-[a-z]+)*:bedrock(?:-agentcore)?:[a-z0-9-]+:\d{12}:(?:agent|runtime)\/[\x21-\x7e]{1,512}$/;

function nameOf(vertex: GraphVertex): string {
  const name = vertex.properties?.name;
  if (typeof name === 'string' && name) return name;
  return vertex.id;
}

function ResourceLink({ vertex }: { vertex: GraphVertex }) {
  return (
    <Link href={resourceHref(vertex.id)} className={LINK}>
      {nameOf(vertex)}
    </Link>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-500">{label}</dt>
      <dd className="mt-1 text-sm text-gray-900">{children}</dd>
    </div>
  );
}

function textProp(vertex: GraphVertex, key: string): string | null {
  const value = vertex.properties?.[key];
  return typeof value === 'string' && value ? value : null;
}

function ResourceList({ vertices, empty }: { vertices: GraphVertex[]; empty: string }) {
  if (vertices.length === 0) {
    return <p className="text-sm text-gray-500">{empty}</p>;
  }
  return (
    <ul className="space-y-2">
      {vertices.map((vertex) => (
        <li key={vertex.id}>
          <ResourceLink vertex={vertex} />
        </li>
      ))}
    </ul>
  );
}

function AiAgentView({ arn }: { arn: string }) {
  const detail = useRequest((signal) => getAiAgent(arn, { signal }), [arn]);

  if (detail.status === 'error') {
    if (isNotFound(detail.error)) {
      return (
        <NotFoundState
          title="AI agent"
          message="No AI agent with that ARN is in the collected graph."
          {...BACK}
        />
      );
    }
    return (
      <>
        <PageHeader title="AI agent" description={arn} {...BACK} />
        <PageBody>
          <ErrorState error={detail.error} onRetry={detail.reload} />
        </PageBody>
      </>
    );
  }

  if (detail.status !== 'success') {
    return <LoadingState label="Loading AI agent…" />;
  }

  const { agent, role, knowledgeBases, guardrail, tools, model, issues }: AiAgentDetail =
    detail.data;
  const platform = textProp(agent, 'platform') === 'agentcore' ? 'AgentCore' : 'Bedrock';

  return (
    <>
      <PageHeader title={nameOf(agent)} description={arn} {...BACK} />
      <PageBody>
        <div className="space-y-6">
          <Card title="Overview">
            <dl className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <Fact label="Platform">
                <Badge tone={TONES.neutral}>{platform}</Badge>
              </Fact>
              <Fact label="Status">{textProp(agent, 'status') ?? '—'}</Fact>
              <Fact label="Execution role">
                {role ? <ResourceLink vertex={role} /> : (textProp(agent, 'role_arn') ?? '—')}
              </Fact>
              <Fact label="Foundation model">{textProp(agent, 'foundation_model') ?? '—'}</Fact>
              <Fact label="Guardrail">
                {guardrail ? (
                  <ResourceLink vertex={guardrail} />
                ) : agent.properties?.guardrail_configured === true ? (
                  'Configured (guardrail not in the graph)'
                ) : (
                  'None configured'
                )}
              </Fact>
              <Fact label="Custom model">{model ? <ResourceLink vertex={model} /> : '—'}</Fact>
              <Fact label="Instruction">
                {agent.properties?.has_instruction === true ? 'Set (never stored)' : '—'}
              </Fact>
              <Fact label="Memory">
                {agent.properties?.has_memory === true ? 'Configured' : '—'}
              </Fact>
              <Fact label="Network">{textProp(agent, 'network_mode') ?? '—'}</Fact>
            </dl>
          </Card>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <Card title="Knowledge bases">
              <ResourceList
                vertices={knowledgeBases}
                empty="This agent retrieves from no knowledge base."
              />
            </Card>
            <Card
              title="Tools"
              description="Lambda functions behind action groups; what each can reach is its own role."
            >
              <ResourceList vertices={tools} empty="This agent has no Lambda-backed tools." />
            </Card>
          </div>

          <Card title="Open issues">
            {issues.length === 0 ? (
              <p className="text-sm text-gray-500">No open issues on this agent.</p>
            ) : (
              <ul className="divide-y divide-gray-200">
                {issues.map((issue) => (
                  <li key={issue.id} className="flex items-center justify-between gap-4 py-3">
                    <div className="flex items-center gap-3">
                      <SeverityBadge severity={issue.severity} />
                      <div className="min-w-0">
                        <div className="font-medium text-gray-900">{issue.ruleId}</div>
                        <div className="text-xs text-gray-500">{issue.status}</div>
                      </div>
                    </div>
                    <Link
                      href={`/issues/${encodeURIComponent(issue.id)}`}
                      className={`text-sm ${LINK}`}
                    >
                      View issue →
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title="Explore">
            <div className="flex flex-col gap-2">
              <Link
                href={`/attack-paths?from=any&to=resource&toResource=${encodeURIComponent(arn)}&hops=4`}
                className={`text-sm ${LINK}`}
              >
                Attack paths to this agent →
              </Link>
              <Link href={resourceHref(arn)} className={`text-sm ${LINK}`}>
                Open in the resource explorer →
              </Link>
            </div>
          </Card>
        </div>
      </PageBody>
    </>
  );
}

function AiAgentDetail() {
  const arn = useSearchParams().get('arn') ?? '';
  if (!AGENT_ARN.test(arn)) {
    return (
      <NotFoundState
        title="AI agent"
        message="That link does not name a Bedrock agent or AgentCore runtime ARN."
        {...BACK}
      />
    );
  }
  return <AiAgentView arn={arn} />;
}

export default function AiAgentDetailPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading…" />}>
      <AiAgentDetail />
    </Suspense>
  );
}
