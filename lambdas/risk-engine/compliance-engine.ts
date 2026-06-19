import { ComplianceFramework, ComplianceControl, ComplianceControlStatus, ComplianceEvidence, ComplianceReport, ComplianceControlResult, ComplianceFrameworkSummary } from './compliance-types';
import { CIS_AWS_FOUNDATIONS_V3_CONTROLS, SOC2_CONTROLS, ISO27001_CONTROLS, getControlsByFramework, getAllControls } from './compliance-types';
import { complianceRuleEvaluators } from './compliance-rules';

export interface GraphClient {
  executeQuery(query: string): Promise<any[]>;
}

export interface EvidenceStore {
  saveEvidence(evidence: ComplianceEvidence[]): Promise<void>;
  getEvidence(controlId: string): Promise<ComplianceEvidence[]>;
  getAllEvidence(): Promise<ComplianceEvidence[]>;
}

export class ComplianceEngine {
  private graphClient: GraphClient;
  private evidenceStore: EvidenceStore;

  constructor(graphClient: GraphClient, evidenceStore: EvidenceStore) {
    this.graphClient = graphClient;
    this.evidenceStore = evidenceStore;
  }

  async runAssessment(framework: ComplianceFramework): Promise<ComplianceReport> {
    const controls = getControlsByFramework(framework);
    const results: ComplianceControlResult[] = [];

    for (const control of controls) {
      if (!control.automated) {
        results.push({
          control,
          status: 'NOT_EVALUATED',
          evidence: [],
          issues: ['Manual assessment required'],
          lastEvaluated: new Date().toISOString()
        });
        continue;
      }

      const evaluator = complianceRuleEvaluators.find(e => e.controlId === control.id);
      if (!evaluator) {
        results.push({
          control,
          status: 'NOT_EVALUATED',
          evidence: [],
          issues: [`No automated evaluator for control ${control.id}`],
          lastEvaluated: new Date().toISOString()
        });
        continue;
      }

      try {
        const { status, evidence, issues } = await evaluator.evaluate(this.graphClient);
        
        await this.evidenceStore.saveEvidence(evidence);

        results.push({
          control,
          status,
          evidence,
          issues,
          lastEvaluated: new Date().toISOString()
        });
      } catch (error) {
        results.push({
          control,
          status: 'NOT_EVALUATED',
          evidence: [],
          issues: [`Evaluation error: ${error instanceof Error ? error.message : String(error)}`],
          lastEvaluated: new Date().toISOString()
        });
      }
    }

    const passed = results.filter(r => r.status === 'PASS').length;
    const failed = results.filter(r => r.status === 'FAIL').length;
    const manual = results.filter(r => r.status === 'MANUAL').length;
    const notApplicable = results.filter(r => r.status === 'NOT_APPLICABLE').length;
    const notEvaluated = results.filter(r => r.status === 'NOT_EVALUATED').length;
    const totalAutomated = controls.filter(c => c.automated).length;
    const evaluatedAutomated = results.filter(r => r.control.automated && r.status !== 'NOT_EVALUATED').length;
    const coveragePercent = totalAutomated > 0 ? Math.round((evaluatedAutomated / totalAutomated) * 100) : 0;

    return {
      framework,
      generatedAt: new Date().toISOString(),
      summary: {
        totalControls: controls.length,
        passed,
        failed,
        manual,
        notApplicable,
        notEvaluated,
        coveragePercent
      },
      controls: results
    };
  }

  async runAllAssessments(): Promise<ComplianceReport[]> {
    const frameworks: ComplianceFramework[] = ['CIS_AWS_FOUNDATIONS', 'SOC2', 'ISO27001'];
    const reports: ComplianceReport[] = [];

    for (const framework of frameworks) {
      const report = await this.runAssessment(framework);
      reports.push(report);
    }

    return reports;
  }

  async getFrameworkSummary(framework: ComplianceFramework): Promise<ComplianceFrameworkSummary> {
    const controls = getControlsByFramework(framework);
    const automatedControls = controls.filter(c => c.automated).length;
    const manualControls = controls.filter(c => !c.automated).length;

    const latestReport = await this.getLatestReport(framework);
    const coveragePercent = latestReport?.summary.coveragePercent ?? 0;
    const lastAssessment = latestReport?.generatedAt ?? '';

    return {
      framework,
      version: framework === 'CIS_AWS_FOUNDATIONS' ? '3.0.0' : '2022',
      totalControls: controls.length,
      automatedControls,
      manualControls,
      coveragePercent,
      lastAssessment
    };
  }

  async getControlEvidence(controlId: string, framework: ComplianceFramework): Promise<ComplianceEvidence[]> {
    return this.evidenceStore.getEvidence(controlId);
  }

  async getControlResult(controlId: string, framework: ComplianceFramework): Promise<ComplianceControlResult | null> {
    const report = await this.getLatestReport(framework);
    if (!report) return null;
    return report.controls.find(c => c.control.id === controlId) || null;
  }

  private async getLatestReport(framework: ComplianceFramework): Promise<ComplianceReport | null> {
    return null;
  }
}

export class DynamoDBEvidenceStore implements EvidenceStore {
  private tableName: string;
  private docClient: any;

  constructor(tableName: string = 'ComplianceEvidence') {
    this.tableName = tableName;
  }

  async saveEvidence(evidence: ComplianceEvidence[]): Promise<void> {
    // Implementation would use DynamoDB batch write
  }

  async getEvidence(controlId: string): Promise<ComplianceEvidence[]> {
    // Implementation would query by controlId GSI
    return [];
  }

  async getAllEvidence(): Promise<ComplianceEvidence[]> {
    // Implementation would scan table
    return [];
  }
}

export function createComplianceEngine(graphClient: GraphClient, evidenceStore: EvidenceStore): ComplianceEngine {
  return new ComplianceEngine(graphClient, evidenceStore);
}

export async function runScheduledComplianceAssessment(neptuneClient: GraphClient): Promise<void> {
  const store = new DynamoDBEvidenceStore();
  const engine = new ComplianceEngine(neptuneClient, store);
  await engine.runAllAssessments();
}