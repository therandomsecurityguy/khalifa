import { ComplianceEngine, DynamoDBEvidenceStore, DynamoDBReportStore } from './compliance-engine';
import type { ComplianceReport } from './compliance-types';
import { createNeptuneRuntimeClient } from './neptune-client';

export interface ComplianceRunSummary {
  frameworksRun: number;
  controlsAssessed: number;
  failedControls: number;
  notEvaluatedControls: number;
}

export interface ComplianceRuntime {
  connect(): Promise<void>;
  runAllAssessments(): Promise<ComplianceReport[]>;
  close(): Promise<void>;
}

function createDefaultRuntime(endpoint: string): ComplianceRuntime {
  const client = createNeptuneRuntimeClient(endpoint);
  const engine = new ComplianceEngine(
    client,
    new DynamoDBEvidenceStore(process.env.COMPLIANCE_EVIDENCE_TABLE || 'ComplianceEvidence'),
    new DynamoDBReportStore(process.env.COMPLIANCE_REPORTS_TABLE || 'ComplianceReports')
  );
  return {
    connect: () => client.connect(),
    runAllAssessments: () => engine.runAllAssessments(),
    close: () => client.close(),
  };
}

export async function runComplianceOnce(
  neptuneEndpoint: string,
  createRuntime: (endpoint: string) => ComplianceRuntime = createDefaultRuntime
): Promise<ComplianceRunSummary> {
  if (!neptuneEndpoint.trim()) throw new Error('NEPTUNE_ENDPOINT is required');
  const runtime = createRuntime(neptuneEndpoint);
  try {
    await runtime.connect();
    const reports = await runtime.runAllAssessments();
    return reports.reduce(
      (summary, report) => ({
        frameworksRun: summary.frameworksRun + 1,
        controlsAssessed: summary.controlsAssessed + report.summary.totalControls,
        failedControls: summary.failedControls + report.summary.failed,
        notEvaluatedControls: summary.notEvaluatedControls + report.summary.notEvaluated,
      }),
      { frameworksRun: 0, controlsAssessed: 0, failedControls: 0, notEvaluatedControls: 0 }
    );
  } finally {
    await runtime.close();
  }
}
