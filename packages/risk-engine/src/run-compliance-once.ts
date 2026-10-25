import type { ComplianceReport } from './compliance-types';
import {
  ComplianceEngine,
  DynamoDBEvidenceStore,
  DynamoDBReportStore,
  type AssessmentRun,
} from './compliance-engine';
import { createNeptuneRuntimeClient, type NeptuneQueryClient } from './neptune-client';
import { DynamoDBIssueRepository } from './issue-repository';
import {
  DynamoDBReconciliationStore,
  readSecurityHubCisFindings,
  reconciliationSettingsFromEnv,
  runReconciliation,
  securityHubClientForRole,
} from './cis-reconciliation';

interface ComplianceRuntime {
  connect(): Promise<void>;
  runAllAssessments(): Promise<AssessmentRun>;
  close(): Promise<void>;
}

export interface ComplianceRunSummary {
  frameworksRun: number;
  controlsAssessed: number;
  failedControls: number;
  notEvaluatedControls: number;
  /** CIS reconciliation against Security Hub ; DISABLED when unconfigured. */
  reconciliation: 'OK' | 'STALE' | 'DISABLED';
}

/** Runs after the assessments; must not throw. */
export type Reconciler = (reports: ComplianceReport[]) => Promise<'OK' | 'STALE' | 'DISABLED'>;

export async function runComplianceOnce(
  neptuneEndpoint: string,
  createRuntime: (endpoint: string) => ComplianceRuntime = createDefaultRuntime,
  reconcile: Reconciler = reconcileFromEnv
): Promise<ComplianceRunSummary> {
  if (!neptuneEndpoint.trim()) throw new Error('NEPTUNE_ENDPOINT is required');

  const runtime = createRuntime(neptuneEndpoint);
  try {
    await runtime.connect();
    const { reports, failures } = await runtime.runAllAssessments();
    const totals = reports.reduce(
      (summary, report) => ({
        frameworksRun: summary.frameworksRun + 1,
        controlsAssessed: summary.controlsAssessed + report.summary.totalControls,
        failedControls: summary.failedControls + report.summary.failed,
        notEvaluatedControls: summary.notEvaluatedControls + report.summary.notEvaluated,
      }),
      { frameworksRun: 0, controlsAssessed: 0, failedControls: 0, notEvaluatedControls: 0 }
    );
    const reconciliation = await reconcile(reports);
    // After reconciliation, so one failed control does not also cost the
    // reconciliation record; the job still fails so the error is seen.
    if (failures.length > 0) {
      throw new Error(`Compliance assessment failed: ${failures.join('; ')}`);
    }
    return { ...totals, reconciliation };
  } finally {
    await runtime.close();
  }
}

export async function handler(): Promise<ComplianceRunSummary> {
  return runComplianceOnce(process.env.NEPTUNE_ENDPOINT || '');
}

async function reconcileFromEnv(reports: ComplianceReport[]): Promise<'OK' | 'STALE' | 'DISABLED'> {
  let settings;
  try {
    settings = reconciliationSettingsFromEnv();
  } catch (error) {
    console.error('CIS reconciliation misconfigured; skipped', { error: String(error) });
    return 'STALE';
  }
  if (!settings) return 'DISABLED';
  const { roleArn, region } = settings;
  const record = await runReconciliation(
    reports.find((r) => r.framework === 'CIS_AWS_FOUNDATIONS') ?? null,
    settings,
    {
      readFindings: async () =>
        readSecurityHubCisFindings(await securityHubClientForRole(roleArn, region)),
      store: new DynamoDBReconciliationStore(
        process.env.COMPLIANCE_REPORTS_TABLE || 'ComplianceReports'
      ),
    }
  );
  return record.status;
}

function createDefaultRuntime(endpoint: string): ComplianceRuntime {
  const client: NeptuneQueryClient = createNeptuneRuntimeClient(endpoint);
  const engine = new ComplianceEngine(
    client,
    new DynamoDBEvidenceStore(process.env.COMPLIANCE_EVIDENCE_TABLE || 'ComplianceEvidence'),
    new DynamoDBReportStore(process.env.COMPLIANCE_REPORTS_TABLE || 'ComplianceReports'),
    // Rule-backed controls (KH-DET-*, 1.7, ...) read their rules' open issues.
    // ISSUES_TABLE comes from the shared config map.
    new DynamoDBIssueRepository()
  );
  return {
    connect: () => client.connect(),
    runAllAssessments: () => engine.runAllAssessments(),
    close: () => client.close(),
  };
}
