import type { Request, Response } from 'express';
import {
  DynamoDBReconciliationStore,
  DynamoDBReportStore,
  MAPPED_FRAMEWORKS,
  citationsByFramework,
  getControlById,
  type ComplianceControlStatus,
  type MappedFramework,
  type ReconciliationRecord,
  type ReconciliationStore,
} from '@khalifa/risk-engine';

// The compliance CronJob reconciles every 4 hours. A record older than a day
// means reconciliation has stopped, and statuses that old must not be published.
export const MAX_RECORD_AGE_MS = 24 * 60 * 60 * 1000;

// Published so the trust center can state the staleness window the API
// actually enforces instead of duplicating it in site config.
export const MAX_RECORD_AGE_HOURS = MAX_RECORD_AGE_MS / (60 * 60 * 1000);

export interface PublishableRequirement {
  requirement: string;
  title: string;
  section: string;
  status: 'PASS' | 'FAIL';
}

// A mapped-framework requirement derives from canonical controls: it is
// publishable only while every mapped control is itself publishable (CIS, via
// reconciliation agreement and the allowlist) or assessed PASS/FAIL (Khalifa
// baseline, from the latest report). Manual or unevaluated controls keep it
// off the page.
export interface PublishableMappedRequirement extends PublishableRequirement {
  framework: MappedFramework;
}

export interface PublishableResponse {
  // OK only when the latest record is OK and fresh. Anything else lists nothing.
  status: 'OK' | 'STALE' | 'MISSING';
  generatedAt: string | null;
  requirements: PublishableRequirement[];
  mappedFrameworks: PublishableMappedRequirement[];
  /** Hours after which a record is STALE and nothing is published. */
  maxAgeHours: number;
}

export type BaselineStatuses = ReadonlyMap<string, ComplianceControlStatus>;

// The only fields that leave Khalifa for the public trust center: no accounts,
// regions, counts or disagreements, and only requirements that are both
// publishable (minAgreementDays of agreement with Security Hub) and allowlisted.
export function publishableFrom(
  record: ReconciliationRecord | null,
  now: Date,
  baselineStatuses?: BaselineStatuses
): PublishableResponse {
  if (!record) {
    return {
      status: 'MISSING',
      generatedAt: null,
      requirements: [],
      mappedFrameworks: [],
      maxAgeHours: MAX_RECORD_AGE_HOURS,
    };
  }
  const age = now.getTime() - Date.parse(record.generatedAt);
  if (record.status !== 'OK' || !(age >= 0 && age <= MAX_RECORD_AGE_MS)) {
    return {
      status: 'STALE',
      generatedAt: record.generatedAt,
      requirements: [],
      mappedFrameworks: [],
      maxAgeHours: MAX_RECORD_AGE_HOURS,
    };
  }
  const requirements: PublishableRequirement[] = [];
  const cisPublishable = new Map<string, 'PASS' | 'FAIL'>();
  for (const r of record.requirements) {
    if (!r.publishable || !r.allowlisted) continue;
    if (r.khalifaStatus !== 'PASS' && r.khalifaStatus !== 'FAIL') continue;
    const control = getControlById(r.requirement, 'CIS_AWS_FOUNDATIONS');
    if (!control) continue;
    cisPublishable.set(r.requirement, r.khalifaStatus);
    requirements.push({
      requirement: r.requirement,
      title: control.title,
      section: control.section,
      status: r.khalifaStatus,
    });
  }

  const mappedFrameworks = baselineStatuses
    ? deriveMappedPublishable(cisPublishable, baselineStatuses)
    : [];

  return {
    status: 'OK',
    generatedAt: record.generatedAt,
    requirements,
    mappedFrameworks,
    maxAgeHours: MAX_RECORD_AGE_HOURS,
  };
}

export function deriveMappedPublishable(
  cisPublishable: ReadonlyMap<string, 'PASS' | 'FAIL'>,
  baselineStatuses: BaselineStatuses
): PublishableMappedRequirement[] {
  const published: PublishableMappedRequirement[] = [];
  for (const framework of MAPPED_FRAMEWORKS) {
    for (const citation of citationsByFramework(framework)) {
      const statuses: Array<'PASS' | 'FAIL'> = [];
      let resolvable = true;
      for (const controlId of citation.controls) {
        const cis = cisPublishable.get(controlId);
        if (cis) {
          statuses.push(cis);
          continue;
        }
        const baseline = baselineStatuses.get(controlId);
        if (baseline === 'PASS' || baseline === 'FAIL') {
          statuses.push(baseline);
          continue;
        }
        resolvable = false;
        break;
      }
      if (!resolvable || statuses.length === 0) continue;
      published.push({
        framework,
        requirement: citation.requirement,
        title: citation.title,
        section: citation.section,
        status: statuses.includes('FAIL') ? 'FAIL' : 'PASS',
      });
    }
  }
  return published;
}

let store: ReconciliationStore | null = null;
function reconciliationStore(): ReconciliationStore {
  store ??= new DynamoDBReconciliationStore(process.env.REPORTS_TABLE || 'ComplianceReports');
  return store;
}

let reports: DynamoDBReportStore | null = null;
function complianceReportStore(): DynamoDBReportStore {
  reports ??= new DynamoDBReportStore(process.env.REPORTS_TABLE || 'ComplianceReports');
  return reports;
}

export function setReconciliationStoreForTests(s: ReconciliationStore | null): void {
  store = s;
}

export function setReportStoreForTests(s: DynamoDBReportStore | null): void {
  reports = s;
}

export async function getPublishableRequirements(_req: Request, res: Response): Promise<void> {
  try {
    const record = await reconciliationStore().getLatest();

    // The baseline report backs the mapped frameworks. An unreadable report
    // leaves them unpublished rather than failing the CIS response.
    let baselineStatuses: BaselineStatuses | undefined;
    try {
      const report = await complianceReportStore().getLatestReport('KHALIFA_BASELINE');
      baselineStatuses = new Map(
        (report?.controls ?? []).map(
          (result) => [result.control.id, result.status] as [string, ComplianceControlStatus]
        )
      );
    } catch (error) {
      console.error('Error reading the Khalifa baseline report:', error);
      baselineStatuses = undefined;
    }

    res.json(publishableFrom(record, new Date(), baselineStatuses));
  } catch (error) {
    console.error('Error reading the CIS reconciliation record:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to read the reconciliation record',
    });
  }
}
