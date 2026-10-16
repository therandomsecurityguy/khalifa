import {
  ComplianceEngine,
  DynamoDBEvidenceStore,
  DynamoDBReportStore,
  InMemoryReportStore,
  type GraphClient,
  type ComplianceFramework,
  type ComplianceReport,
  type ComplianceFrameworkSummary,
  type ComplianceControlResult,
  type ComplianceEvidence,
} from '@khalifa/risk-engine';
import { getApiNeptuneClient } from './api-dependencies';
import type { NeptuneClient } from './neptune-client';

export interface ComplianceServiceConfig {
  evidenceTableName?: string;
  reportsTableName?: string;
}

class GremlinGraphClient implements GraphClient {
  constructor(private readonly client: NeptuneClient) {}

  async executeQuery(query: string): Promise<any[]> {
    return this.client.executeStaticQuery(query);
  }
}

export class ComplianceService {
  private engine: ComplianceEngine;

  constructor(config: ComplianceServiceConfig) {
    const graphClient = new GremlinGraphClient(getApiNeptuneClient());
    const evidenceStore = new DynamoDBEvidenceStore(
      config.evidenceTableName || process.env.EVIDENCE_TABLE || 'ComplianceEvidence'
    );
    const reportStore = config.reportsTableName
      ? new DynamoDBReportStore(config.reportsTableName)
      : new InMemoryReportStore();
    this.engine = new ComplianceEngine(graphClient, evidenceStore, reportStore);
  }

  async listFrameworks(): Promise<ComplianceFrameworkSummary[]> {
    const frameworks: ComplianceFramework[] = ['CIS_AWS_FOUNDATIONS', 'KHALIFA_BASELINE'];
    const summaries: ComplianceFrameworkSummary[] = [];
    for (const f of frameworks) {
      summaries.push(await this.engine.getFrameworkSummary(f));
    }
    return summaries;
  }

  async getFrameworkSummary(framework: ComplianceFramework): Promise<ComplianceFrameworkSummary> {
    return this.engine.getFrameworkSummary(framework);
  }

  async getLatestReport(framework: ComplianceFramework): Promise<ComplianceReport | null> {
    return this.engine.getLatestReport(framework);
  }

  async getControlEvidence(
    controlId: string,
    framework: ComplianceFramework
  ): Promise<ComplianceEvidence[]> {
    return this.engine.getControlEvidence(controlId, framework);
  }

  async runAssessment(framework: ComplianceFramework): Promise<ComplianceReport> {
    return this.engine.runAssessment(framework);
  }

  async getControlResult(
    controlId: string,
    framework: ComplianceFramework
  ): Promise<ComplianceControlResult | null> {
    return this.engine.getControlResult(controlId, framework);
  }
}
