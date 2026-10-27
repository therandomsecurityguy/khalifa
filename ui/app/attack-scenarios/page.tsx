'use client';

import { useState } from 'react';
import { listAttackScenarios, runAttackScenario } from '@/lib/api';
import { useAsyncAction, useRequest } from '@/lib/use-request';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import { Badge, Card, PageBody, PageHeader } from '@/components/ui';
import type { AttackScenarioDetail, AttackScenarioRunResponse } from '@/types';

// A compact last-segment view of a resource id; the full value stays in the
// title attribute.
function shortId(id: string): string {
  const tail = id.split('/').pop() ?? id;
  return tail.length > 32 ? `${tail.slice(0, 29)}…` : tail;
}

function ScenarioCard({ scenario }: { scenario: AttackScenarioDetail }) {
  const [run, setRun] = useState<AttackScenarioRunResponse | null>(null);
  const action = useAsyncAction(async () => {
    setRun(null);
    setRun(await runAttackScenario(scenario.id));
  });
  const results = new Map((run?.steps ?? []).map((step) => [step.ruleId, step]));

  return (
    <Card
      title={scenario.name}
      description={scenario.description}
      actions={
        run ? (
          <Badge tone={run.matchedSteps > 0 ? 'warning' : 'success'}>
            {run.matchedSteps}/{run.totalSteps} steps matched
          </Badge>
        ) : undefined
      }
    >
      <p className="text-xs text-gray-500">
        {scenario.techniques.map((technique) => (
          <span key={technique.id} className="mr-2 inline-block rounded bg-gray-100 px-1.5 py-0.5">
            {technique.id} · {technique.name}
          </span>
        ))}
      </p>
      <ol className="mt-4 space-y-2 text-sm">
        {scenario.steps.map((step, index) => {
          const result = results.get(step.ruleId);
          return (
            <li key={`${index}-${step.ruleId}`} className="flex flex-wrap items-baseline gap-x-2">
              <span className="w-5 text-xs text-gray-400">{index + 1}.</span>
              <span className="font-medium text-gray-900">{step.ruleId}</span>
              <span className="text-gray-600">{step.description}</span>
              {result && (
                <span
                  data-testid="scenario-step-result"
                  className={`text-xs ${result.error ? 'text-red-700' : 'text-gray-500'}`}
                >
                  {result.error
                    ? `error: ${result.error}`
                    : result.matchedPaths > 0
                      ? `${result.matchedPaths} matched path${result.matchedPaths === 1 ? '' : 's'} · ${result.resources.map(shortId).join(', ')}${result.truncated ? ' (capped)' : ''}`
                      : 'no matches'}
                </span>
              )}
            </li>
          );
        })}
      </ol>
      <div className="mt-4 flex items-center gap-3">
        <button
          type="button"
          className="rounded bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
          disabled={action.pending}
          onClick={() => void action.run()}
        >
          {action.pending ? 'Running…' : 'Run scenario'}
        </button>
        <span className="text-xs text-gray-500">
          Graph-only: re-runs each step's rule against the live graph. Nothing is executed.
        </span>
      </div>
      {action.error !== undefined && (
        <div className="mt-3">
          <ErrorState error={action.error} />
        </div>
      )}
    </Card>
  );
}

export default function AttackScenariosPage() {
  const scenarios = useRequest((signal) => listAttackScenarios({ signal }), []);

  return (
    <>
      <PageHeader
        title="Adversary scenarios"
        description="Curated technique chains evaluated against your graph — which steps your current findings already match."
      />
      <PageBody>
        {scenarios.status === 'error' ? (
          <ErrorState error={scenarios.error} onRetry={scenarios.reload} />
        ) : scenarios.status === 'loading' ? (
          <LoadingState label="Loading scenarios…" />
        ) : scenarios.data === undefined || scenarios.data.scenarios.length === 0 ? (
          <EmptyState
            title="No scenarios available"
            description="Scenarios ship with the catalogue; an empty list means the API returned none."
          />
        ) : (
          <div className="space-y-6">
            {scenarios.data.scenarios.map((scenario) => (
              <ScenarioCard key={scenario.id} scenario={scenario} />
            ))}
          </div>
        )}
      </PageBody>
    </>
  );
}
