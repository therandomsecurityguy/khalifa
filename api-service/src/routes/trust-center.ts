import type { Request, Response } from 'express';
import {
  DynamoDBReconciliationStore,
  getControlById,
  type ReconciliationRecord,
  type ReconciliationStore,
} from '@khalifa/risk-engine';

// The compliance CronJob reconciles every 4 hours. A record older than a day
// means reconciliation has stopped, and statuses that old must not be published.
export const MAX_RECORD_AGE_MS = 24 * 60 * 60 * 1000;

export interface PublishableRequirement {
  requirement: string;
  title: string;
  section: string;
  status: 'PASS' | 'FAIL';
}

export interface PublishableResponse {
  // OK only when the latest record is OK and fresh. Anything else lists nothing.
  status: 'OK' | 'STALE' | 'MISSING';
  generatedAt: string | null;
  requirements: PublishableRequirement[];
}

// The only fields that leave Khalifa for the public trust center: no accounts,
// regions, counts or disagreements, and only requirements that are both
// publishable (minAgreementDays of agreement with Security Hub) and allowlisted.
export function publishableFrom(
  record: ReconciliationRecord | null,
  now: Date
): PublishableResponse {
  if (!record) return { status: 'MISSING', generatedAt: null, requirements: [] };
  const age = now.getTime() - Date.parse(record.generatedAt);
  if (record.status !== 'OK' || !(age >= 0 && age <= MAX_RECORD_AGE_MS)) {
    return { status: 'STALE', generatedAt: record.generatedAt, requirements: [] };
  }
  const requirements: PublishableRequirement[] = [];
  for (const r of record.requirements) {
    if (!r.publishable || !r.allowlisted) continue;
    if (r.khalifaStatus !== 'PASS' && r.khalifaStatus !== 'FAIL') continue;
    const control = getControlById(r.requirement, 'CIS_AWS_FOUNDATIONS');
    if (!control) continue;
    requirements.push({
      requirement: r.requirement,
      title: control.title,
      section: control.section,
      status: r.khalifaStatus,
    });
  }
  return { status: 'OK', generatedAt: record.generatedAt, requirements };
}

let store: ReconciliationStore | null = null;
function reconciliationStore(): ReconciliationStore {
  store ??= new DynamoDBReconciliationStore(process.env.REPORTS_TABLE || 'ComplianceReports');
  return store;
}

export function setReconciliationStoreForTests(s: ReconciliationStore | null): void {
  store = s;
}

export async function getPublishableRequirements(_req: Request, res: Response): Promise<void> {
  try {
    res.json(publishableFrom(await reconciliationStore().getLatest(), new Date()));
  } catch (error) {
    console.error('Error reading the CIS reconciliation record:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to read the reconciliation record',
    });
  }
}
