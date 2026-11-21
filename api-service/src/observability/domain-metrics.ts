import { DynamoDBIssueRepository, DynamoDBReconciliationStore } from '@khalifa/risk-engine';

/**
 * Cached domain gauges for /metrics, so alerts can fire on posture (not just
 * HTTP): open issues by severity and the CIS reconciliation record's status
 * and age.
 *
 * The values are read on an interval rather than per scrape: the issue counts
 * page through the open issues (the repository has no cheaper count), and a
 * scrape every 30s must not turn into a query every 30s. One refresh every
 * five minutes is enough for the alerts, which all use `for:` windows well
 * above it, and the cache is exactly what makes the scrape side cheap.
 */

const REFRESH_INTERVAL_MS = 5 * 60_000;
const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

export interface ReconciliationSnapshot {
  status: string;
  /** ISO timestamp the record was generated, or null when absent. */
  generatedAt: string | null;
}

export interface DomainMetricsSources {
  openIssueCounts(): Promise<Record<string, number>>;
  reconciliation(): Promise<ReconciliationSnapshot | null>;
}

interface Snapshot {
  ok: boolean;
  refreshedAtMs: number;
  counts: Record<string, number>;
  reconciliation: ReconciliationSnapshot | null;
}

function defaultSources(): DomainMetricsSources {
  const issues = new DynamoDBIssueRepository();
  const reconciliations = new DynamoDBReconciliationStore(
    process.env.REPORTS_TABLE || 'ComplianceReports'
  );
  return {
    openIssueCounts: () => issues.getTotalCounts(),
    reconciliation: async () => {
      const record = await reconciliations.getLatest();
      return record ? { status: record.status, generatedAt: record.generatedAt } : null;
    },
  };
}

let sources: DomainMetricsSources = defaultSources();
let snapshot: Snapshot | null = null;
let refreshing: Promise<void> | null = null;
let timer: NodeJS.Timeout | null = null;

export async function refreshDomainMetrics(): Promise<void> {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    try {
      const [counts, reconciliation] = await Promise.all([
        sources.openIssueCounts(),
        sources.reconciliation(),
      ]);
      snapshot = { ok: true, refreshedAtMs: Date.now(), counts, reconciliation };
    } catch (error) {
      // Keep the last known values (stale is better than a gap) but flip the
      // health gauge so an alert can catch a refresh that never succeeds.
      console.error(
        'Domain metrics refresh failed:',
        error instanceof Error ? error.message : error
      );
      snapshot = {
        ok: false,
        refreshedAtMs: Date.now(),
        counts: snapshot?.counts ?? {},
        reconciliation: snapshot?.reconciliation ?? null,
      };
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

export function startDomainMetrics(intervalMs: number = REFRESH_INTERVAL_MS): () => void {
  void refreshDomainMetrics();
  timer = setInterval(() => {
    void refreshDomainMetrics();
  }, intervalMs);
  timer.unref();
  return stopDomainMetrics;
}

export function stopDomainMetrics(): void {
  if (timer) {
    clearInterval(timer);
    timer = null;
  }
}

export function renderDomainMetrics(now: Date = new Date()): string[] {
  if (!snapshot) return [];

  const lines = [
    '# HELP khalifa_domain_metrics_ok 1 when the last domain metrics refresh succeeded.',
    '# TYPE khalifa_domain_metrics_ok gauge',
    `khalifa_domain_metrics_ok ${snapshot.ok ? 1 : 0}`,
    '# HELP khalifa_open_issues Open issues by severity.',
    '# TYPE khalifa_open_issues gauge',
  ];
  for (const severity of SEVERITIES) {
    lines.push(`khalifa_open_issues{severity="${severity}"} ${snapshot.counts[severity] ?? 0}`);
  }

  const reconciliation = snapshot.reconciliation;
  const status = reconciliation?.status ?? 'MISSING';
  lines.push(
    '# HELP khalifa_reconciliation_ok 1 when the CIS reconciliation record is OK.',
    '# TYPE khalifa_reconciliation_ok gauge',
    `khalifa_reconciliation_ok ${status === 'OK' ? 1 : 0}`,
    '# HELP khalifa_reconciliation_status Current reconciliation status (info style).',
    '# TYPE khalifa_reconciliation_status gauge',
    `khalifa_reconciliation_status{status="${status}"} 1`
  );

  if (reconciliation?.generatedAt) {
    const ageSeconds = Math.max(
      0,
      Math.round((now.getTime() - Date.parse(reconciliation.generatedAt)) / 1000)
    );
    lines.push(
      '# HELP khalifa_reconciliation_age_seconds Age of the latest reconciliation record.',
      '# TYPE khalifa_reconciliation_age_seconds gauge',
      `khalifa_reconciliation_age_seconds ${ageSeconds}`
    );
  }

  return lines;
}

export function resetDomainMetricsForTests(): void {
  snapshot = null;
  refreshing = null;
  stopDomainMetrics();
  sources = defaultSources();
}

export function setDomainMetricsSourcesForTests(next: DomainMetricsSources): void {
  sources = next;
}
