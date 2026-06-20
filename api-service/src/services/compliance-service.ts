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
import Gremlin from 'gremlin';

export interface ComplianceServiceConfig {
  neptuneEndpoint: string;
  evidenceTableName?: string;
  reportsTableName?: string;
}

class GremlinGraphClient implements GraphClient {
  private client: Gremlin.driver.Client;
  constructor(endpoint: string) {
    this.client = new Gremlin.driver.Client(`wss://${endpoint}:8182/gremlin`, {
      traversalSource: 'g',
      connectTimeout: 30000,
    });
  }
  async executeQuery(query: string): Promise<any[]> {
    const result = await this.client.submit(query);
    const items: any[] = [];
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const item = await result.next();
      if (!item) break;
      items.push(item);
    }
    return items;
  }
}

export class ComplianceService {
  private engine: ComplianceEngine;
  private neptuneEndpoint: string;

  constructor(config: ComplianceServiceConfig) {
    this.neptuneEndpoint = config.neptuneEndpoint;
    const graphClient = new GremlinGraphClient(config.neptuneEndpoint);
    const evidenceStore = new DynamoDBEvidenceStore(
      config.evidenceTableName || process.env.EVIDENCE_TABLE || 'ComplianceEvidence'
    );
    const reportStore = config.reportsTableName
      ? new DynamoDBReportStore(config.reportsTableName)
      : new InMemoryReportStore();
    this.engine = new ComplianceEngine(graphClient, evidenceStore, reportStore);
  }

  async listFrameworks(): Promise<ComplianceFrameworkSummary[]> {
    const frameworks: ComplianceFramework[] = ['CIS_AWS_FOUNDATIONS', 'SOC2', 'ISO27001'];
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
