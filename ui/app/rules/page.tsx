'use client';

import { getRuleQuality } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import { Badge, Card, PageBody, PageHeader, Table, Td, Th, TONES } from '@/components/ui';
import type { RuleQualityItem } from '@/types';

const VERDICT_TONES: Record<RuleQualityItem['verdict'], string> = {
  noisy: 'danger',
  mixed: 'warning',
  'insufficient-data': 'neutral',
  reliable: 'success',
};

const VERDICT_LABELS: Record<RuleQualityItem['verdict'], string> = {
  noisy: 'Noisy',
  mixed: 'Mixed',
  'insufficient-data': 'Not enough data',
  reliable: 'Reliable',
};

function dismissal(item: RuleQualityItem): string {
  return item.dismissalRate === null ? '—' : `${Math.round(item.dismissalRate * 100)}%`;
}

function corroboration(item: RuleQualityItem): string {
  if (item.corroborationRate === null) return '—';
  return `${Math.round(item.corroborationRate * 100)}% of ${item.labeled ?? 0}`;
}

export default function RulesPage() {
  const quality = useRequest((signal) => getRuleQuality({ signal }), []);

  return (
    <>
      <PageHeader
        title="Rule quality"
        description="What happened to every issue each rule raised, so a noisy rule is visible before its tickets are trusted."
      />
      <PageBody>
        {quality.status === 'error' ? (
          <ErrorState error={quality.error} onRetry={quality.reload} />
        ) : quality.status === 'loading' ? (
          <LoadingState label="Loading rule quality…" />
        ) : quality.status === 'idle' || quality.data === undefined ? (
          <EmptyState title="Rule quality is not loaded yet." />
        ) : quality.data.rules.length === 0 ? (
          <EmptyState
            title="No issues recorded yet"
            description="Quality appears once the rule runner has opened, resolved, or seen an issue suppressed."
          />
        ) : (
          <Card
            title="Rules"
            description={`Suppressed means an analyst judged the issue not worth fixing (or accepted the risk); resolved means the graph stopped matching. Dismissal rate = suppressed ÷ closed — a noise proxy, not ground truth. Corroborated is the share of labelled issues whose resources an independent detector (Security Hub / GuardDuty) flagged too; it is published beside the dismissal rate and does not change the verdict. A verdict needs at least ${quality.data.thresholds.minHandled} closed issues.`}
          >
            <Table caption="Rule quality" className="min-w-[64rem]">
              <thead>
                <tr>
                  <Th>Rule</Th>
                  <Th>Team</Th>
                  <Th>Severity</Th>
                  <Th>Auto-ticket</Th>
                  <Th className="text-right">Open</Th>
                  <Th className="text-right">Suppressed</Th>
                  <Th className="text-right">Resolved</Th>
                  <Th className="text-right">Dismissal</Th>
                  <Th className="text-right">Corroborated</Th>
                  <Th>Verdict</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 bg-white">
                {quality.data.rules.map((rule) => (
                  <tr key={rule.ruleId} data-testid="rule-quality-row">
                    <Td>
                      <div className="font-medium text-gray-900">{rule.name}</div>
                      <div className="text-xs text-gray-500">
                        {rule.ruleId}
                        {!rule.inCatalogue && ' · not in the catalogue'}
                        {!rule.enabled && rule.inCatalogue && ' · disabled'}
                      </div>
                    </Td>
                    <Td>{rule.ownerTeam || '—'}</Td>
                    <Td>
                      {rule.severityHint ? (
                        <span
                          className={`rounded px-1.5 py-0.5 text-xs font-semibold ${TONES.severitySoft[rule.severityHint] ?? TONES.severitySoft.unknown}`}
                        >
                          {rule.severityHint}
                        </span>
                      ) : (
                        '—'
                      )}
                    </Td>
                    <Td>{rule.autoTicket ? 'on' : 'off'}</Td>
                    <Td className="text-right tabular-nums">{rule.open}</Td>
                    <Td className="text-right tabular-nums">{rule.suppressed}</Td>
                    <Td className="text-right tabular-nums">{rule.resolved}</Td>
                    <Td className="text-right tabular-nums">{dismissal(rule)}</Td>
                    <Td className="text-right tabular-nums">{corroboration(rule)}</Td>
                    <Td>
                      <Badge tone={VERDICT_TONES[rule.verdict]}>
                        {VERDICT_LABELS[rule.verdict]}
                      </Badge>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>
        )}
      </PageBody>
    </>
  );
}
