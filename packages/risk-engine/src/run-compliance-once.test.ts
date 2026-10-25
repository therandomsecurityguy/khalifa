import type { ComplianceReport } from './compliance-types';
import { runComplianceOnce } from './run-compliance-once';

const report = {
  summary: { totalControls: 3, passed: 1, failed: 1, notEvaluated: 1 },
} as ComplianceReport;

function runtime(runAllAssessments: jest.Mock) {
  return {
    connect: jest.fn().mockResolvedValue(undefined),
    runAllAssessments,
    close: jest.fn().mockResolvedValue(undefined),
  };
}

describe('runComplianceOnce', () => {
  it('summarizes a run and always closes its client', async () => {
    const instance = runtime(jest.fn().mockResolvedValue({ reports: [report], failures: [] }));

    await expect(runComplianceOnce('neptune:8182', () => instance)).resolves.toEqual({
      frameworksRun: 1,
      controlsAssessed: 3,
      failedControls: 1,
      notEvaluatedControls: 1,
      // RECONCILIATION_SECURITY_HUB_ROLE_ARN is unset in tests.
      reconciliation: 'DISABLED',
    });
    expect(instance.close).toHaveBeenCalledTimes(1);
  });

  it('hands the reports from the run to CIS reconciliation and reports its status', async () => {
    const instance = runtime(jest.fn().mockResolvedValue({ reports: [report], failures: [] }));
    const reconcile = jest.fn().mockResolvedValue('STALE');

    const summary = await runComplianceOnce('neptune:8182', () => instance, reconcile);

    expect(reconcile).toHaveBeenCalledWith([report]);
    expect(summary.reconciliation).toBe('STALE');
    expect(instance.close).toHaveBeenCalledTimes(1);
  });

  // 2026-10-14: CIS 3.4 timed out, the run threw before reconciliation, and no
  // reconciliation record was written for that run or its retry.
  it('reconciles the saved reports before failing on control errors', async () => {
    const instance = runtime(
      jest.fn().mockResolvedValue({
        reports: [report],
        failures: ['CIS_AWS_FOUNDATIONS 3.4: Neptune query timeout after 30000ms'],
      })
    );
    const reconcile = jest.fn().mockResolvedValue('OK');

    await expect(runComplianceOnce('neptune:8182', () => instance, reconcile)).rejects.toThrow(
      'CIS_AWS_FOUNDATIONS 3.4: Neptune query timeout'
    );
    expect(reconcile).toHaveBeenCalledWith([report]);
    expect(instance.close).toHaveBeenCalledTimes(1);
  });

  it('propagates failures and still closes its client', async () => {
    const instance = runtime(jest.fn().mockRejectedValue(new Error('persistence failed')));

    await expect(runComplianceOnce('neptune:8182', () => instance)).rejects.toThrow(
      'persistence failed'
    );
    expect(instance.close).toHaveBeenCalledTimes(1);
  });

  it('rejects a missing endpoint before creating a client', async () => {
    const factory = jest.fn();
    await expect(runComplianceOnce(' ', factory)).rejects.toThrow('NEPTUNE_ENDPOINT is required');
    expect(factory).not.toHaveBeenCalled();
  });
});
