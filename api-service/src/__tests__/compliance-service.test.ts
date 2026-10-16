import { ComplianceService } from '../services/compliance-service';

describe('ComplianceService', () => {
  it('lists the supported frameworks, canonical first', async () => {
    const service = new ComplianceService({
      reportsTableName: undefined,
    });
    const summaries = await service.listFrameworks();
    expect(summaries.map((s) => s.framework)).toEqual([
      'CIS_AWS_FOUNDATIONS',
      'KHALIFA_BASELINE',
      'SOC2',
      'ISO27001',
    ]);
    // Mapped frameworks report their requirement counts, not canonical controls.
    const soc2 = summaries.find((s) => s.framework === 'SOC2');
    expect(soc2?.totalControls).toBe(9);
    expect(soc2?.version).toBe('2017');
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
