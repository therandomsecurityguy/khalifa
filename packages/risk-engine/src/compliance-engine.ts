import type {
  ComplianceFramework,
  ComplianceEvidence,
  ComplianceReport,
  ComplianceControlResult,
  ComplianceFrameworkSummary,
} from './compliance-types';
import { getControlsByFramework } from './compliance-types';
import { complianceRuleEvaluators } from './compliance-rules';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  QueryCommand,
  PutItemCommand,
  ScanCommand,
} from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';

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
  private reportStore: ReportStore;

  constructor(graphClient: GraphClient, evidenceStore: EvidenceStore, reportStore?: ReportStore) {
    this.graphClient = graphClient;
    this.evidenceStore = evidenceStore;
    this.reportStore = reportStore || new InMemoryReportStore();
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
          lastEvaluated: new Date().toISOString(),
        });
        continue;
      }

      const evaluator = complianceRuleEvaluators.find((e) => e.controlId === control.id);
      if (!evaluator) {
        results.push({
          control,
          status: 'NOT_EVALUATED',
          evidence: [],
          issues: [`No automated evaluator for control ${control.id}`],
          lastEvaluated: new Date().toISOString(),
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
          lastEvaluated: new Date().toISOString(),
        });
      } catch (error) {
        results.push({
          control,
          status: 'NOT_EVALUATED',
          evidence: [],
          issues: [`Evaluation error: ${error instanceof Error ? error.message : String(error)}`],
          lastEvaluated: new Date().toISOString(),
        });
      }
    }

    const passed = results.filter((r) => r.status === 'PASS').length;
    const failed = results.filter((r) => r.status === 'FAIL').length;
    const manual = results.filter((r) => r.status === 'MANUAL').length;
    const notApplicable = results.filter((r) => r.status === 'NOT_APPLICABLE').length;
    const notEvaluated = results.filter((r) => r.status === 'NOT_EVALUATED').length;
    const totalAutomated = controls.filter((c) => c.automated).length;
    const evaluatedAutomated = results.filter(
      (r) => r.control.automated && r.status !== 'NOT_EVALUATED'
    ).length;
    const coveragePercent =
      totalAutomated > 0 ? Math.round((evaluatedAutomated / totalAutomated) * 100) : 0;

    const report: ComplianceReport = {
      framework,
      generatedAt: new Date().toISOString(),
      summary: {
        totalControls: controls.length,
        passed,
        failed,
        manual,
        notApplicable,
        notEvaluated,
        coveragePercent,
      },
      controls: results,
    };

    await this.reportStore.saveReport(report);

    return report;
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
    const automatedControls = controls.filter((c) => c.automated).length;
    const manualControls = controls.filter((c) => !c.automated).length;

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
      lastAssessment,
    };
  }

  async getControlEvidence(
    controlId: string,
    _framework: ComplianceFramework
  ): Promise<ComplianceEvidence[]> {
    return this.evidenceStore.getEvidence(controlId);
  }

  async getControlResult(
    controlId: string,
    framework: ComplianceFramework
  ): Promise<ComplianceControlResult | null> {
    const report = await this.getLatestReport(framework);
    if (!report) return null;
    return report.controls.find((c: ComplianceControlResult) => c.control.id === controlId) || null;
  }

  async getLatestReport(framework: ComplianceFramework): Promise<ComplianceReport | null> {
    return this.reportStore.getLatestReport(framework);
  }
}

export interface ReportStore {
  saveReport(report: ComplianceReport): Promise<void>;
  getLatestReport(framework: ComplianceFramework): Promise<ComplianceReport | null>;
  listReports(framework: ComplianceFramework, limit?: number): Promise<ComplianceReport[]>;
}

export class InMemoryReportStore implements ReportStore {
  private reports = new Map<ComplianceFramework, ComplianceReport[]>();

  async saveReport(report: ComplianceReport): Promise<void> {
    const existing = this.reports.get(report.framework) || [];
    existing.push(report);
    this.reports.set(report.framework, existing);
  }

  async getLatestReport(framework: ComplianceFramework): Promise<ComplianceReport | null> {
    const list = this.reports.get(framework) || [];
    if (list.length === 0) return null;
    return list[list.length - 1];
  }

  async listReports(framework: ComplianceFramework, limit?: number): Promise<ComplianceReport[]> {
    const list = this.reports.get(framework) || [];
    return limit ? list.slice(-limit) : list;
  }
}

export class DynamoDBEvidenceStore implements EvidenceStore {
  private tableName: string;
  private docClient: DynamoDBDocumentClient;

  constructor(tableName: string = 'ComplianceEvidence') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.tableName = tableName;
    this.docClient = DynamoDBDocumentClient.from(client);
  }

  async saveEvidence(evidence: ComplianceEvidence[]): Promise<void> {
    if (evidence.length === 0) return;
    const items = evidence.map((e) => ({
      PutRequest: {
        Item: marshall({
          ...e,
          pk: `${e.controlId}#${e.resourceId}#${e.collectedAt}`,
        }),
      },
    }));

    for (let i = 0; i < items.length; i += 25) {
      await this.docClient.send(
        new BatchWriteItemCommand({
          RequestItems: {
            [this.tableName]: items.slice(i, i + 25),
          },
        })
      );
    }
  }

  async getEvidence(controlId: string): Promise<ComplianceEvidence[]> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: 'controlId = :controlId',
        ExpressionAttributeValues: {
          ':controlId': { S: controlId },
        },
      })
    );
    if (!result.Items) return [];
    return result.Items.map((item) => unmarshall(item) as ComplianceEvidence);
  }

  async getAllEvidence(): Promise<ComplianceEvidence[]> {
    const result = await this.docClient.send(new ScanCommand({ TableName: this.tableName }));
    if (!result.Items) return [];
    return result.Items.map((item) => unmarshall(item) as ComplianceEvidence);
  }
}

export class DynamoDBReportStore implements ReportStore {
  private tableName: string;
  private docClient: DynamoDBDocumentClient;

  constructor(tableName: string = 'ComplianceReports') {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.tableName = tableName;
    this.docClient = DynamoDBDocumentClient.from(client);
  }

  async saveReport(report: ComplianceReport): Promise<void> {
    await this.docClient.send(
      new PutItemCommand({
        TableName: this.tableName,
        Item: marshall({
          framework: report.framework,
          generatedAt: report.generatedAt,
          report,
        }),
      })
    );
  }

  async getLatestReport(framework: ComplianceFramework): Promise<ComplianceReport | null> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: 'framework = :framework',
        ExpressionAttributeValues: {
          ':framework': { S: framework },
        },
        ScanIndexForward: false,
        Limit: 1,
      })
    );
    if (!result.Items || result.Items.length === 0) return null;
    const item = unmarshall(result.Items[0]);
    return item.report as ComplianceReport;
  }

  async listReports(framework: ComplianceFramework, limit?: number): Promise<ComplianceReport[]> {
    const result = await this.docClient.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: 'framework = :framework',
        ExpressionAttributeValues: {
          ':framework': { S: framework },
        },
        ScanIndexForward: false,
        Limit: limit || 50,
      })
    );
    if (!result.Items) return [];
    return result.Items.map((item) => unmarshall(item).report as ComplianceReport);
  }
}

export function createComplianceEngine(
  graphClient: GraphClient,
  evidenceStore: EvidenceStore,
  reportStore?: ReportStore
): ComplianceEngine {
  return new ComplianceEngine(graphClient, evidenceStore, reportStore);
}

export async function runScheduledComplianceAssessment(neptuneClient: GraphClient): Promise<void> {
  const evidenceStore = new DynamoDBEvidenceStore();
  const reportStore = new DynamoDBReportStore();
  const engine = new ComplianceEngine(neptuneClient, evidenceStore, reportStore);
  await engine.runAllAssessments();
}
