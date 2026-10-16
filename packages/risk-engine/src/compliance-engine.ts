import type {
  ComplianceControl,
  ComplianceFramework,
  ComplianceEvidence,
  ComplianceReport,
  ComplianceControlResult,
  ComplianceFrameworkSummary,
} from './compliance-types';
import { getControlsByFramework, REGIONAL_CONTROL_IDS } from './compliance-types';
import { complianceRuleEvaluators } from './compliance-rules';
import { getRuleById } from './rules';
import {
  DynamoDBClient,
  BatchWriteItemCommand,
  QueryCommand,
  PutItemCommand,
  ScanCommand,
} from '@aws-sdk/client-dynamodb';
import type { WriteRequest } from '@aws-sdk/client-dynamodb';
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

// The issues store, as a rule-backed control reads it.
export interface OpenIssueReader {
  getOpenIssuesByRule(ruleId: string): Promise<{ id: string; status?: string }[]>;
}

const SAMPLE_ISSUE_IDS = 10;

export class ComplianceEngine {
  private graphClient: GraphClient;
  private evidenceStore: EvidenceStore;
  private reportStore: ReportStore;
  private issueReader?: OpenIssueReader;

  constructor(
    graphClient: GraphClient,
    evidenceStore: EvidenceStore,
    reportStore?: ReportStore,
    issueReader?: OpenIssueReader
  ) {
    this.graphClient = graphClient;
    this.evidenceStore = evidenceStore;
    this.reportStore = reportStore || new InMemoryReportStore();
    this.issueReader = issueReader;
  }

  // A control defined as the outcome its risk rules measure (KH-DET-2 is
  // "no canary credential has been used", RULE-023 detects one). It has no
  // evaluator of its own, so it was reported "No automated evaluator" forever,
  // whatever the rules found. FAIL on any open issue of a related rule; PASS
  // when none is open and every related rule is enabled. Suppressed and
  // resolved issues do not count. A disabled rule, or an issue store that
  // cannot be read, is NOT_EVALUATED rather than a failed assessment.
  private async evaluateFromRules(
    control: ComplianceControl
  ): Promise<Omit<ComplianceControlResult, 'control' | 'lastEvaluated'>> {
    const reader = this.issueReader!;
    const inactive = control.relatedRules.filter((id) => getRuleById(id)?.enabled !== true);
    if (inactive.length > 0) {
      return {
        status: 'NOT_EVALUATED',
        evidence: [],
        issues: [`Related rule disabled or unknown: ${inactive.join(', ')}`],
      };
    }
    let byRule: [string, { id: string; status?: string }[]][];
    try {
      byRule = await Promise.all(
        control.relatedRules.map(
          async (id) =>
            [id, await reader.getOpenIssuesByRule(id)] as [
              string,
              { id: string; status?: string }[],
            ]
        )
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        status: 'NOT_EVALUATED',
        evidence: [],
        issues: [`Issue store unreadable: ${message}`],
      };
    }
    const open = byRule.map(
      ([id, list]) => [id, list.filter((i) => (i.status ?? 'open') === 'open')] as const
    );
    const total = open.reduce((n, [, list]) => n + list.length, 0);
    const status = total === 0 ? 'PASS' : 'FAIL';
    return {
      status,
      evidence: [
        {
          controlId: control.id,
          resourceId: control.relatedRules.join(','),
          resourceType: 'RiskRule',
          status,
          details: {
            openIssuesByRule: Object.fromEntries(open.map(([id, list]) => [id, list.length])),
            sampleIssueIds: open
              .flatMap(([, list]) => list.map((i) => i.id))
              .slice(0, SAMPLE_ISSUE_IDS),
          },
          collectedAt: new Date().toISOString(),
          collectedBy: 'compliance-engine',
        },
      ],
      issues: open
        .filter(([, list]) => list.length > 0)
        .map(([id, list]) => `${list.length} open ${id} issue${list.length === 1 ? '' : 's'}`),
    };
  }

  // The regions collection actually ran in, read from the per-account
  // resource-inventory coverage vertices. Undefined if the read fails: the
  // label is then missing, which is better than failing the assessment.
  private async collectedRegions(): Promise<string[] | undefined> {
    try {
      const regions = await this.graphClient.executeQuery(
        `g.V().hasLabel('CollectionCoverage').has('service', 'resource-inventory').values('region').dedup()`
      );
      return [...new Set(regions.map(String))].sort();
    } catch {
      return undefined;
    }
  }

  async runAssessment(framework: ComplianceFramework): Promise<ComplianceReport> {
    const controls = getControlsByFramework(framework);
    const results: ComplianceControlResult[] = [];
    const failures: string[] = [];
    const regions = controls.some((c) => REGIONAL_CONTROL_IDS.has(c.id))
      ? await this.collectedRegions()
      : undefined;

    for (const control of controls) {
      if (!control.automated) {
        results.push({
          control,
          status: 'MANUAL',
          evidence: [],
          issues: ['Manual assessment required'],
          lastEvaluated: new Date().toISOString(),
        });
        continue;
      }

      const evaluator = complianceRuleEvaluators.find((e) => e.controlId === control.id);
      if (!evaluator && control.relatedRules.length > 0 && this.issueReader) {
        const result = await this.evaluateFromRules(control);
        await this.evidenceStore.saveEvidence(result.evidence);
        results.push({ control, ...result, lastEvaluated: new Date().toISOString() });
        continue;
      }
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
          ...(REGIONAL_CONTROL_IDS.has(control.id) && regions ? { regionsEvaluated: regions } : {}),
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        failures.push(`${control.id}: ${message}`);
        results.push({
          control,
          status: 'NOT_EVALUATED',
          evidence: [],
          issues: [`Evaluation error: ${message}`],
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

    if (failures.length > 0) {
      throw new Error(`Compliance assessment failed for ${framework}: ${failures.join('; ')}`);
    }

    return report;
  }

  async runAllAssessments(): Promise<ComplianceReport[]> {
    const frameworks: ComplianceFramework[] = ['CIS_AWS_FOUNDATIONS', 'KHALIFA_BASELINE'];
    const reports: ComplianceReport[] = [];

    for (const framework of frameworks) {
      reports.push(await this.runAssessment(framework));
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
      summary: latestReport?.summary ?? {
        totalControls: controls.length,
        passed: 0,
        failed: 0,
        manual: manualControls,
        notApplicable: 0,
        notEvaluated: automatedControls,
        coveragePercent,
      },
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
  private sleep: (ms: number) => Promise<void>;
  private maxAttempts: number;

  constructor(
    tableName: string = 'ComplianceEvidence',
    options: {
      client?: DynamoDBDocumentClient;
      sleep?: (ms: number) => Promise<void>;
      maxAttempts?: number;
    } = {}
  ) {
    const client = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    this.tableName = tableName;
    this.docClient = options.client || DynamoDBDocumentClient.from(client);
    this.sleep = options.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.maxAttempts = options.maxAttempts || 5;
  }

  async saveEvidence(evidence: ComplianceEvidence[]): Promise<void> {
    if (evidence.length === 0) return;
    const items: WriteRequest[] = evidence.map((e) => ({
      PutRequest: {
        Item: marshall({
          ...e,
        }),
      },
    }));

    for (let i = 0; i < items.length; i += 25) {
      let pending = items.slice(i, i + 25);

      for (let attempt = 0; pending.length > 0 && attempt < this.maxAttempts; attempt++) {
        const result = await this.docClient.send(
          new BatchWriteItemCommand({
            RequestItems: {
              [this.tableName]: pending,
            },
          })
        );
        pending = result.UnprocessedItems?.[this.tableName] || [];

        if (pending.length > 0 && attempt + 1 < this.maxAttempts) {
          const maxDelay = Math.min(100 * 2 ** attempt, 2000);
          await this.sleep(Math.floor(Math.random() * maxDelay));
        }
      }

      if (pending.length > 0) {
        throw new Error(
          `Failed to persist ${pending.length} compliance evidence items after ${this.maxAttempts} attempts`
        );
      }
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
