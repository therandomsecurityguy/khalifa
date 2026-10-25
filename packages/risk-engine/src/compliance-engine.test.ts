import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import type {
  ComplianceControl,
  ComplianceEvidence,
  ComplianceFramework,
} from './compliance-types';

jest.mock('./compliance-types', () => ({
  getControlsByFramework: jest.fn((framework: ComplianceFramework) => [
    {
      id: `${framework}-1`,
      framework,
      section: 'test',
      title: 'Test control',
      description: 'Test control',
      severity: 'high',
      automated: true,
      relatedRules: [],
      evidenceRequirements: [],
      remediationGuidance: 'Fix it',
    } satisfies ComplianceControl,
  ]),
  // Mutable so a test can mark the control regional.
  REGIONAL_CONTROL_IDS: new Set<string>(),
}));

jest.mock('./compliance-rules', () => ({
  complianceRuleEvaluators: [],
}));

import { complianceRuleEvaluators } from './compliance-rules';
import { REGIONAL_CONTROL_IDS } from './compliance-types';
import { ComplianceEngine, DynamoDBEvidenceStore, InMemoryReportStore } from './compliance-engine';

const evidence: ComplianceEvidence = {
  controlId: 'CIS_AWS_FOUNDATIONS-1',
  resourceId: 'arn:aws:s3:::example',
  resourceType: 'S3Bucket',
  status: 'PASS',
  details: {},
  collectedAt: '2026-09-10T00:00:00.000Z',
  collectedBy: 'test',
};

describe('ComplianceEngine failure visibility', () => {
  beforeEach(() => {
    complianceRuleEvaluators.splice(0);
  });

  it('persists a report and rejects when evaluation fails', async () => {
    complianceRuleEvaluators.push({
      controlId: 'CIS_AWS_FOUNDATIONS-1',
      evaluate: jest.fn().mockRejectedValue(new Error('Neptune unavailable')),
    });
    const reports = new InMemoryReportStore();
    const engine = new ComplianceEngine(
      { executeQuery: jest.fn() },
      { saveEvidence: jest.fn(), getEvidence: jest.fn(), getAllEvidence: jest.fn() },
      reports
    );

    const error = await engine.runAssessment('CIS_AWS_FOUNDATIONS').catch((caught) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(error.message).toContain('Neptune unavailable');
    await expect(reports.getLatestReport('CIS_AWS_FOUNDATIONS')).resolves.toMatchObject({
      summary: { notEvaluated: 1 },
    });
  });

  it('runs every framework when one control fails, and reports the failure', async () => {
    complianceRuleEvaluators.push({
      controlId: 'CIS_AWS_FOUNDATIONS-1',
      evaluate: jest.fn().mockRejectedValue(new Error('Neptune query timeout')),
    });
    const reports = new InMemoryReportStore();
    const engine = new ComplianceEngine(
      { executeQuery: jest.fn() },
      { saveEvidence: jest.fn(), getEvidence: jest.fn(), getAllEvidence: jest.fn() },
      reports
    );

    const run = await engine.runAllAssessments();

    expect(run.reports.map((r) => r.framework)).toEqual([
      'CIS_AWS_FOUNDATIONS',
      'KHALIFA_BASELINE',
      'SOC2',
      'ISO27001',
      'PCI_DSS',
      'NIST_800_53',
    ]);
    expect(run.failures).toEqual([
      'CIS_AWS_FOUNDATIONS CIS_AWS_FOUNDATIONS-1: Neptune query timeout',
    ]);
    await expect(reports.getLatestReport('KHALIFA_BASELINE')).resolves.not.toBeNull();
  });

  it('rejects after persisting a report when evidence persistence fails', async () => {
    complianceRuleEvaluators.push({
      controlId: 'CIS_AWS_FOUNDATIONS-1',
      evaluate: jest.fn().mockResolvedValue({ status: 'PASS', evidence: [evidence], issues: [] }),
    });
    const reports = new InMemoryReportStore();
    const engine = new ComplianceEngine(
      { executeQuery: jest.fn() },
      {
        saveEvidence: jest.fn().mockRejectedValue(new Error('DynamoDB throttled')),
        getEvidence: jest.fn(),
        getAllEvidence: jest.fn(),
      },
      reports
    );

    await expect(engine.runAssessment('CIS_AWS_FOUNDATIONS')).rejects.toThrow('DynamoDB throttled');
    await expect(reports.getLatestReport('CIS_AWS_FOUNDATIONS')).resolves.not.toBeNull();
  });
});

describe('ComplianceEngine.getFrameworkSummary', () => {
  it('returns assessment counts even when no report exists', async () => {
    const engine = new ComplianceEngine(
      { executeQuery: jest.fn() },
      { saveEvidence: jest.fn(), getEvidence: jest.fn(), getAllEvidence: jest.fn() },
      new InMemoryReportStore()
    );

    await expect(engine.getFrameworkSummary('CIS_AWS_FOUNDATIONS')).resolves.toMatchObject({
      totalControls: 1,
      automatedControls: 1,
      manualControls: 0,
      coveragePercent: 0,
      lastAssessment: '',
      summary: {
        totalControls: 1,
        passed: 0,
        failed: 0,
        manual: 0,
        notApplicable: 0,
        notEvaluated: 1,
        coveragePercent: 0,
      },
    });
  });
});

describe('DynamoDBEvidenceStore', () => {
  it('retries only unprocessed items', async () => {
    const unprocessed = [{ PutRequest: { Item: { controlId: { S: 'control' } } } }];
    const send = jest
      .fn()
      .mockResolvedValueOnce({ UnprocessedItems: { Evidence: unprocessed } })
      .mockResolvedValueOnce({ UnprocessedItems: {} });
    const sleep = jest.fn().mockResolvedValue(undefined);
    const store = new DynamoDBEvidenceStore('Evidence', {
      client: { send } as unknown as DynamoDBDocumentClient,
      sleep,
      maxAttempts: 3,
    });

    await store.saveEvidence([evidence]);

    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1][0].input.RequestItems.Evidence).toEqual(unprocessed);
    expect(sleep).toHaveBeenCalledTimes(1);
  });

  it('rejects when unprocessed items remain after the retry limit', async () => {
    const unprocessed = [{ PutRequest: { Item: { controlId: { S: 'control' } } } }];
    const send = jest.fn().mockResolvedValue({ UnprocessedItems: { Evidence: unprocessed } });
    const store = new DynamoDBEvidenceStore('Evidence', {
      client: { send } as unknown as DynamoDBDocumentClient,
      sleep: jest.fn().mockResolvedValue(undefined),
      maxAttempts: 2,
    });

    await expect(store.saveEvidence([evidence])).rejects.toThrow(
      'Failed to persist 1 compliance evidence items after 2 attempts'
    );
    expect(send).toHaveBeenCalledTimes(2);
  });
});

// A regional control's PASS only covers the regions that were collected; the
// result says which, so it cannot read as a PASS everywhere.
describe('ComplianceEngine region scope', () => {
  const regional = REGIONAL_CONTROL_IDS as Set<string>;
  const pass = { status: 'PASS' as const, evidence: [evidence], issues: [] };
  const stores = () => ({
    evidence: { saveEvidence: jest.fn(), getEvidence: jest.fn(), getAllEvidence: jest.fn() },
    reports: new InMemoryReportStore(),
  });

  beforeEach(() => {
    complianceRuleEvaluators.splice(0);
    complianceRuleEvaluators.push({
      controlId: 'CIS_AWS_FOUNDATIONS-1',
      evaluate: jest.fn().mockResolvedValue(pass),
    });
    regional.clear();
  });

  it('records the collected regions on a regional control, sorted and de-duplicated', async () => {
    regional.add('CIS_AWS_FOUNDATIONS-1');
    const executeQuery = jest.fn().mockResolvedValue(['us-west-2', 'eu-west-2', 'us-west-2']);
    const { evidence: e, reports } = stores();

    const report = await new ComplianceEngine({ executeQuery }, e, reports).runAssessment(
      'CIS_AWS_FOUNDATIONS'
    );

    expect(report.controls[0].status).toBe('PASS');
    expect(report.controls[0].regionsEvaluated).toEqual(['eu-west-2', 'us-west-2']);
    expect(executeQuery.mock.calls[0][0]).toContain("has('service', 'resource-inventory')");
  });

  it('leaves global controls unlabelled and does not query regions for them', async () => {
    const executeQuery = jest.fn();
    const { evidence: e, reports } = stores();

    const report = await new ComplianceEngine({ executeQuery }, e, reports).runAssessment(
      'CIS_AWS_FOUNDATIONS'
    );

    expect(report.controls[0].regionsEvaluated).toBeUndefined();
    expect(executeQuery).not.toHaveBeenCalled();
  });

  it('still assesses, unlabelled, when the region read fails', async () => {
    regional.add('CIS_AWS_FOUNDATIONS-1');
    const executeQuery = jest.fn().mockRejectedValue(new Error('Neptune unavailable'));
    const { evidence: e, reports } = stores();

    const report = await new ComplianceEngine({ executeQuery }, e, reports).runAssessment(
      'CIS_AWS_FOUNDATIONS'
    );

    expect(report.controls[0].status).toBe('PASS');
    expect(report.controls[0].regionsEvaluated).toBeUndefined();
  });
});
