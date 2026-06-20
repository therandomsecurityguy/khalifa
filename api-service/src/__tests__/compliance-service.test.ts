import { ComplianceService } from '../services/compliance-service';

describe('ComplianceService', () => {
  it('lists all three frameworks', async () => {
    const service = new ComplianceService({
      neptuneEndpoint: 'fake:8182',
      reportsTableName: undefined,
    });
    const summaries = await service.listFrameworks();
    expect(summaries.length).toBe(3);
    expect(summaries.map((s) => s.framework).sort()).toEqual([
      'CIS_AWS_FOUNDATIONS',
      'ISO27001',
      'SOC2',
    ]);
  });

  it('returns framework summary with control counts', async () => {
    const service = new ComplianceService({
      neptuneEndpoint: 'fake:8182',
    });
    const summary = await service.getFrameworkSummary('CIS_AWS_FOUNDATIONS');
    expect(summary.framework).toBe('CIS_AWS_FOUNDATIONS');
    expect(summary.totalControls).toBeGreaterThan(0);
    expect(summary.automatedControls).toBeGreaterThan(0);
    expect(summary.version).toBe('3.0.0');
  });
});
