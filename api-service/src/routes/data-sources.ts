import type { Request, Response } from 'express';
import { DynamoDBReportStore, PostureTrendStore } from '@khalifa/risk-engine';
import { getApiNeptuneClient } from '../services/api-dependencies';
import { LeastPrivilegeStore } from '../services/least-privilege-store';
import type { GraphVertex } from '../types';

const neptuneClient = getApiNeptuneClient();
const trendStore = new PostureTrendStore();
const reportStore = new DynamoDBReportStore(process.env.REPORTS_TABLE);
const leastPrivilegeStore = new LeastPrivilegeStore();

// The collector's per-run summary for an account; the rest are services.
const SUMMARY_SERVICE = 'resource-inventory';
// Coverage only moves when the collector runs (every few hours), and counting
// env=prod reads every tagged vertex, so one read serves all callers a while.
const CACHE_TTL_MS = 5 * 60 * 1000;

export interface ServiceCoverage {
  service: string;
  region: string;
  status: string;
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  error: string | null;
  failureType: string | null;
  nodes: number | null;
}

export type DetectionState = 'on' | 'truncated' | 'off' | 'missing' | 'unknown';

export interface DetectionCoverage {
  securityHub: DetectionState;
  guardDuty: DetectionState;
  config: DetectionState;
  accessAnalyzer: DetectionState;
}

// Each job's schedule mirrors deploy/helm/khalifa/values.yaml. quietWhenClean:
// the job writes only when it finds something, so no output can be normal.
export interface JobOutput {
  id: string;
  name: string;
  everyHours: number;
  lastOutputAt: string | null;
  produced: string;
  quietWhenClean: boolean;
}

export interface AccountCoverage {
  id: string;
  name: string;
  resources: number | null;
  prod: number;
  collectedAt: string | null;
  status: 'ok' | 'failing' | 'not-collected';
  services: ServiceCoverage[];
  detection: DetectionCoverage;
}

const text = (value: unknown): string | null => (typeof value === 'string' && value ? value : null);
const count = (value: unknown): number | null =>
  typeof value === 'number' && Number.isFinite(value) ? value : null;

function serviceCoverage(vertex: GraphVertex): ServiceCoverage {
  const p = vertex.properties;
  return {
    service: text(p.service) ?? vertex.id,
    region: text(p.region) ?? '',
    status: text(p.status) ?? 'UNKNOWN',
    lastAttemptAt: text(p.last_attempt_at),
    lastSuccessAt: text(p.last_success_at),
    error: text(p.error),
    failureType: text(p.failure_type),
    nodes: count(p.node_count),
  };
}

const RANK: Record<DetectionState, number> = {
  on: 0,
  truncated: 1,
  unknown: 2,
  off: 3,
  missing: 4,
};
const worst = (states: DetectionState[]): DetectionState | null =>
  states.length ? states.reduce((a, b) => (RANK[b] > RANK[a] ? b : a)) : null;

// One state per source for an account; with several regions the worst wins.
// A source with no record is off only when its check ran cleanly; otherwise
// the state is unknown.
export function detectionFor(
  sources: GraphVertex[],
  services: ServiceCoverage[]
): DetectionCoverage {
  const checked = (service: string) =>
    services.some((s) => s.service === service && s.status !== 'FAILED');
  const of = (label: string) => sources.filter((v) => v.label === label).map((v) => v.properties);
  const absent = (service: string, missing: DetectionState): DetectionState =>
    checked(service) ? missing : 'unknown';
  return {
    securityHub:
      worst(of('SecurityHub').map((p) => (p.findings_truncated === true ? 'truncated' : 'on'))) ??
      absent('securityhub', 'off'),
    guardDuty:
      worst(
        of('GuardDutyDetector').map((p) =>
          p.status === 'ENABLED' ? 'on' : p.status === 'MISSING' ? 'missing' : 'off'
        )
      ) ?? absent('guardduty', 'missing'),
    config:
      worst(of('ConfigRecorder').map((p) => (p.recording === true ? 'on' : 'off'))) ??
      absent('config', 'missing'),
    accessAnalyzer:
      worst(
        of('AccessAnalyzer').map((p) =>
          p.status === 'ACTIVE' ? 'on' : p.status === 'MISSING' ? 'missing' : 'off'
        )
      ) ?? absent('access-analyzer', 'missing'),
  };
}

export function buildAccountCoverage(
  accounts: Array<{ id: string; name: string }>,
  coverage: GraphVertex[],
  prodByAccount: Record<string, number>,
  detectionSources: GraphVertex[] = []
): AccountCoverage[] {
  const sourcesByAccount = new Map<string, GraphVertex[]>();
  for (const vertex of detectionSources) {
    const id = text(vertex.properties.account_id);
    if (id) sourcesByAccount.set(id, [...(sourcesByAccount.get(id) ?? []), vertex]);
  }
  const byAccount = new Map<string, GraphVertex[]>();
  for (const vertex of coverage) {
    const id = text(vertex.properties.account_id);
    if (id) byAccount.set(id, [...(byAccount.get(id) ?? []), vertex]);
  }
  const names = new Map(accounts.map((account) => [account.id, account.name]));
  const ids = [...new Set([...names.keys(), ...byAccount.keys()])];
  return ids
    .map((id) => {
      const records = (byAccount.get(id) ?? []).map(serviceCoverage);
      const summaries = records.filter((r) => r.service === SUMMARY_SERVICE);
      const services = records
        .filter((r) => r.service !== SUMMARY_SERVICE)
        .sort((a, b) => a.service.localeCompare(b.service) || a.region.localeCompare(b.region));
      const latest = summaries
        .map((r) => r.lastAttemptAt)
        .filter((at): at is string => at !== null)
        .sort()
        .pop();
      const resources = summaries.reduce<number | null>(
        (sum, r) => (r.nodes === null ? sum : (sum ?? 0) + r.nodes),
        null
      );
      return {
        id,
        name: names.get(id) ?? '',
        resources,
        prod: prodByAccount[id] ?? 0,
        collectedAt: latest ?? null,
        status: !records.length
          ? ('not-collected' as const)
          : services.some((s) => s.status === 'FAILED')
            ? ('failing' as const)
            : ('ok' as const),
        services,
        detection: detectionFor(sourcesByAccount.get(id) ?? [], records),
      };
    })
    .sort((a, b) => (a.name || a.id).localeCompare(b.name || b.id));
}

const plural = (n: number, word: string) =>
  `${n.toLocaleString('en-US')} ${word}${n === 1 ? '' : 's'}`;

async function readJobs(accounts: AccountCoverage[]): Promise<JobOutput[]> {
  const latestCollection = accounts
    .map((a) => a.collectedAt)
    .filter((at): at is string => at !== null)
    .sort()
    .pop();
  const [trend, cis, guardDuty, dspm, anomalies, permissions, leastPrivilege] = await Promise.all([
    trendStore.getLatest('openIssuesBySeverity'),
    reportStore.getLatestReport('CIS_AWS_FOUNDATIONS'),
    neptuneClient.latestOutput('GuardDutyFinding', 'source_updated_at'),
    neptuneClient.latestOutput('DataClassificationFinding', 'scanned_at'),
    neptuneClient.latestOutput('CloudTrailAnomaly', 'source_updated_at'),
    neptuneClient.latestOutput('EffectivePermission', 'evaluated_at'),
    leastPrivilegeStore.getSummary(),
  ]);
  return [
    {
      id: 'org-collector',
      name: 'Org collector',
      everyHours: 4,
      lastOutputAt: latestCollection ?? null,
      produced: plural(accounts.filter((a) => a.collectedAt).length, 'account'),
      quietWhenClean: false,
    },
    {
      id: 'rule-runner',
      name: 'Rule runner',
      everyHours: 4,
      lastOutputAt: trend?.recordedAt ?? null,
      produced: trend ? plural(trend.value, 'open issue') : '',
      quietWhenClean: false,
    },
    {
      id: 'compliance',
      name: 'Compliance',
      everyHours: 4,
      lastOutputAt: cis?.generatedAt ?? null,
      produced: cis
        ? `CIS: ${cis.summary.failed} of ${cis.summary.totalControls} controls failing`
        : '',
      quietWhenClean: false,
    },
    {
      id: 'guardduty-sweep',
      name: 'GuardDuty findings sweep',
      everyHours: 4,
      lastOutputAt: guardDuty.latest,
      produced: plural(guardDuty.count, 'finding'),
      quietWhenClean: true,
    },
    {
      id: 'dspm-scanner',
      name: 'DSPM scanner',
      everyHours: 24,
      lastOutputAt: dspm.latest,
      produced: plural(dspm.count, 'classified resource'),
      quietWhenClean: true,
    },
    {
      id: 'cloudtrail-analyzer',
      name: 'CloudTrail analyzer',
      everyHours: 24,
      lastOutputAt: anomalies.latest,
      produced: plural(anomalies.count, 'anomaly'),
      quietWhenClean: true,
    },
    {
      id: 'policy-evaluator',
      name: 'Policy evaluator',
      everyHours: 24,
      lastOutputAt: permissions.latest,
      produced: plural(permissions.count, 'principal'),
      quietWhenClean: false,
    },
    {
      id: 'least-privilege-sweep',
      name: 'Least-privilege sweep',
      everyHours: 24,
      lastOutputAt: leastPrivilege.lastSweptAt,
      produced: plural(leastPrivilege.principalsSwept, 'principal'),
      quietWhenClean: false,
    },
  ];
}

interface DataSources {
  accounts: AccountCoverage[];
  jobs: JobOutput[];
}

let cached: { at: number; read: Promise<DataSources> } | null = null;

export async function getDataSources(_req: Request, res: Response): Promise<void> {
  try {
    if (!cached || Date.now() - cached.at > CACHE_TTL_MS) {
      const read = Promise.all([
        neptuneClient.listAccounts(),
        neptuneClient.listCollectionCoverage(),
        neptuneClient.countByAccount('env', 'prod'),
        neptuneClient.listDetectionSources(),
      ]).then(async ([accounts, coverage, prod, sources]) => {
        const built = buildAccountCoverage(accounts, coverage, prod, sources);
        return { accounts: built, jobs: await readJobs(built) };
      });
      cached = { at: Date.now(), read };
      read.catch(() => {
        if (cached?.read === read) cached = null;
      });
    }
    res.json(await cached.read);
  } catch (error) {
    console.error('Error reading data sources:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to read data sources' });
  }
}
