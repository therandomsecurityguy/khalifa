'use client';

import Link from 'next/link';
import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { getTrend, listTrendMetrics } from '@/lib/api';
import { useRequest } from '@/lib/use-request';
import {
  deltaTone,
  formatSigned,
  formatTrendDate,
  metricCopy,
  severityChips,
  summarizeTrend,
  TREND_METRICS,
  type DeltaTone,
  type TrendSeverity,
} from '@/lib/trends';
import type { TrendForecast, TrendPoint } from '@/types';
import { EmptyState, ErrorState, LoadingState } from '@/components/states';
import {
  Badge,
  Card,
  LINK,
  PageBody,
  PageHeader,
  PRIMARY_BUTTON,
  SelectField,
  TextField,
  TONES,
} from '@/components/ui';

const DIRECTION_TONES = {
  improving: TONES.success,
  worsening: TONES.danger,
  unchanged: TONES.neutral,
} as const;

const SEVERITY_LETTER: Record<TrendSeverity, string> = {
  critical: 'C',
  high: 'H',
  medium: 'M',
  low: 'L',
};

const DELTA_CLASSES: Record<DeltaTone, string> = {
  good: 'text-green-700',
  bad: 'text-red-700',
  neutral: 'text-gray-500',
};

const CONFIDENCE_TONES: Record<TrendForecast['confidence'], string> = {
  high: 'success',
  medium: 'warning',
  low: 'danger',
};

function TrendSummary({
  metric,
  points,
  days,
  forecast,
}: {
  metric: string;
  points: TrendPoint[];
  days: number;
  forecast?: TrendForecast;
}) {
  const copy = metricCopy(metric);
  const insight = summarizeTrend(metric, points);
  const max = Math.max(...points.map((point) => point.value), 1);
  const accounts = [...new Set(points.flatMap((point) => point.accountIds ?? []))];
  const hasBreakdown = points.some((point) => point.bySeverity);
  const newestFirst = points
    .map((point, index) => ({
      point,
      previous: index > 0 ? points[index - 1] : null,
      latest: index === points.length - 1,
    }))
    .reverse();

  if (!insight) {
    return (
      <Card title={copy.label} description={copy.meaning}>
        <EmptyState
          title="No snapshots in this window"
          description="The runner writes a point when it finishes a rule pass. Widen the window or check back after the next run."
        />
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      <Card
        title={copy.label}
        description={copy.meaning}
        actions={<Badge tone={DIRECTION_TONES[insight.direction]}>{insight.direction}</Badge>}
      >
        <p className="text-base font-medium text-gray-900">{insight.headline}</p>
        <dl className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-gray-500">Latest</dt>
            <dd className="mt-1 text-2xl font-semibold text-gray-900">{insight.current}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-gray-500">
              vs {formatTrendDate(points[0].date)}
            </dt>
            <dd
              className={`mt-1 text-2xl font-semibold ${DELTA_CLASSES[deltaTone(insight.windowDelta, copy.lowerIsBetter)]}`}
            >
              {formatSigned(insight.windowDelta)}
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-gray-500">Peak</dt>
            <dd className="mt-1 text-2xl font-semibold text-gray-900">{insight.peak}</dd>
          </div>
          <div>
            <dt className="text-xs font-medium uppercase tracking-wide text-gray-500">Snapshots</dt>
            <dd className="mt-1 text-2xl font-semibold text-gray-900">{points.length}</dd>
            <dd className="text-xs text-gray-500">
              {points.length} of {days} days have data
            </dd>
          </div>
        </dl>
        <div className="mt-5">
          <Link href={copy.href} className={`text-sm ${LINK}`}>
            {copy.hrefLabel} →
          </Link>
        </div>
        {accounts.length > 0 && (
          <p className="mt-3 text-xs text-gray-500">
            Accounts in this series: {accounts.join(', ')}
          </p>
        )}
        {forecast && (
          <div className="mt-5 rounded-md border border-gray-200 p-3" data-testid="trend-forecast">
            <p className="text-sm font-medium text-gray-900">
              Projection{' '}
              <Badge tone={CONFIDENCE_TONES[forecast.confidence]}>
                {forecast.confidence} confidence
              </Badge>
            </p>
            <ul className="mt-2 space-y-1 text-sm text-gray-700">
              {forecast.projected.map((projection) => (
                <li key={projection.days}>
                  In {projection.days} days:{' '}
                  <span className="font-medium text-gray-900">{projection.value}</span>{' '}
                  <span className="text-gray-500">
                    (range {projection.lower}–{projection.upper})
                  </span>
                </li>
              ))}
            </ul>
            <p className="mt-2 text-xs text-gray-500">
              A straight line over the last {forecast.basisDays} daily points
              {forecast.slopePerDay === 0
                ? '; the recent trend is flat.'
                : `, moving ${formatSigned(forecast.slopePerDay)} per day.`}
              {forecast.note ? ` ${forecast.note}.` : ''}
            </p>
          </div>
        )}
      </Card>

      <Card title="Daily snapshots">
        <div className="overflow-x-auto">
          <ul className={`space-y-2 ${hasBreakdown ? 'min-w-[36rem]' : ''}`}>
            {newestFirst.map(({ point, previous, latest }) => {
              const delta = previous === null ? null : point.value - previous.value;
              const chips = severityChips(point, previous);
              return (
                <li
                  key={`${point.date}-${point.recordedAt ?? ''}`}
                  data-testid="trend-row"
                  className="flex items-center gap-3"
                >
                  <span className="w-16 shrink-0 text-xs text-gray-500">
                    {formatTrendDate(point.date)}
                  </span>
                  <div className="h-3 min-w-16 flex-1 rounded bg-gray-100">
                    {point.value > 0 && (
                      <div
                        data-testid="trend-bar"
                        className={`h-3 rounded ${latest ? 'bg-indigo-600' : 'bg-indigo-400'}`}
                        style={{ width: `${Math.max(4, (point.value / max) * 100)}%` }}
                      />
                    )}
                  </div>
                  <span className="w-10 shrink-0 text-right text-sm font-medium text-gray-900">
                    {point.value}
                  </span>
                  <span
                    className={`w-12 shrink-0 text-right text-xs ${DELTA_CLASSES[deltaTone(delta, copy.lowerIsBetter)]}`}
                  >
                    {delta === null ? '—' : formatSigned(delta)}
                  </span>
                  {hasBreakdown && (
                    <span className="flex w-56 shrink-0 gap-1">
                      {chips.map((chip) => (
                        <span
                          key={chip.severity}
                          data-testid="severity-chip"
                          className={`rounded px-1.5 py-0.5 text-xs font-semibold tabular-nums ${TONES.severitySoft[chip.severity]}`}
                        >
                          <span aria-hidden="true">{SEVERITY_LETTER[chip.severity]}</span>
                          <span className="sr-only">{chip.severity}</span> {chip.text}
                        </span>
                      ))}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      </Card>
    </div>
  );
}

function TrendsView() {
  const router = useRouter();
  const params = useSearchParams();
  const selectedMetric = params.get('metric') ?? '';
  const selectedDays = Number(params.get('days') ?? '90') || 90;
  const [metric, setMetric] = useState(selectedMetric);
  const [days, setDays] = useState(String(selectedDays));

  const metrics = useRequest((signal) => listTrendMetrics({ signal }), []);
  const trend = useRequest(
    (signal) => getTrend(selectedMetric, selectedDays, { signal }),
    [selectedMetric, selectedDays],
    { enabled: Boolean(selectedMetric) }
  );

  // Only metrics the page can describe; others the API still serves stay out of the list.
  const available =
    metrics.status === 'success' ? metrics.data.metrics.filter((item) => TREND_METRICS[item]) : [];

  useEffect(() => {
    if (selectedMetric || available.length === 0) return;
    const fallback = available.includes('openIssuesBySeverity')
      ? 'openIssuesBySeverity'
      : available[0];
    router.replace(`/trends?metric=${encodeURIComponent(fallback)}&days=${selectedDays}`);
  }, [available, selectedMetric, selectedDays, router]);

  function apply(nextMetric: string, nextDays: string): void {
    const next = new URLSearchParams();
    if (nextMetric) next.set('metric', nextMetric);
    next.set('days', nextDays);
    router.push(`/trends?${next.toString()}`);
  }

  return (
    <>
      <PageHeader title="Posture trends" description="Daily snapshots from the risk runner." />
      <PageBody>
        {metrics.status === 'error' && (
          <ErrorState error={metrics.error} onRetry={metrics.reload} className="mb-6" />
        )}
        <form
          className="mb-6 flex flex-wrap items-end gap-4 rounded-lg bg-white p-4 shadow"
          onSubmit={(event) => {
            event.preventDefault();
            apply(metric || selectedMetric, days);
          }}
        >
          <SelectField
            label="Metric"
            className="min-w-72 flex-1"
            value={metric || selectedMetric}
            disabled={metrics.status !== 'success'}
            onChange={(event) => {
              setMetric(event.target.value);
              apply(event.target.value, days);
            }}
          >
            <option value="">{metrics.status === 'loading' ? 'Loading metrics…' : 'Select'}</option>
            {available.map((item) => (
              <option key={item} value={item}>
                {TREND_METRICS[item]?.label ?? item}
              </option>
            ))}
          </SelectField>
          <TextField
            label="Days"
            type="number"
            min={1}
            max={365}
            value={days}
            onChange={(event) => setDays(event.target.value)}
          />
          <button type="submit" className={PRIMARY_BUTTON}>
            Load
          </button>
        </form>

        <div aria-busy={trend.status === 'loading'}>
          {trend.status === 'error' ? (
            <ErrorState error={trend.error} onRetry={trend.reload} />
          ) : trend.status === 'loading' ? (
            <LoadingState label="Loading trend…" />
          ) : trend.status === 'idle' ? (
            <EmptyState title="Select a metric to load posture history." />
          ) : (
            <TrendSummary
              metric={selectedMetric}
              points={trend.data.points ?? []}
              days={selectedDays}
              forecast={trend.data.forecast}
            />
          )}
        </div>
      </PageBody>
    </>
  );
}

export default function TrendsPage() {
  return (
    <Suspense fallback={<LoadingState label="Loading…" />}>
      <TrendsView />
    </Suspense>
  );
}
