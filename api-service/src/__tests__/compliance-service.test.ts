import { ComplianceService } from '../services/compliance-service';

describe('ComplianceService', () => {
  it('lists the supported frameworks', async () => {
    const service = new ComplianceService({
      reportsTableName: undefined,
    });
    const summaries = await service.listFrameworks();
    expect(summaries.map((s) => s.framework)).toEqual(['CIS_AWS_FOUNDATIONS', 'KHALIFA_BASELINE']);
  });

  it('returns framework summary with control counts', async () => {
    const service = new ComplianceService({});
    const summary = await service.getFrameworkSummary('CIS_AWS_FOUNDATIONS');
    expect(summary.framework).toBe('CIS_AWS_FOUNDATIONS');
    expect(summary.totalControls).toBeGreaterThan(0);
    expect(summary.automatedControls).toBeGreaterThan(0);
    expect(summary.version).toBe('3.0.0');
    expect(summary.summary).toEqual({
      totalControls: summary.totalControls,
      passed: 0,
      failed: 0,
      manual: summary.manualControls,
      notApplicable: 0,
      notEvaluated: summary.automatedControls,
      coveragePercent: 0,
    });
  });
});
