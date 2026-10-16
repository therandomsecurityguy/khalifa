import type { ComplianceReport } from './compliance-types';
import { runComplianceOnce, type ComplianceRuntime } from './run-compliance-once';

function report(
  framework: ComplianceReport['framework'],
  failed: number,
  notEvaluated: number
): ComplianceReport {
  const totalControls = failed + notEvaluated + 1;
  return {
    framework,
    generatedAt: '2026-10-15T00:00:00.000Z',
    summary: {
      totalControls,
      passed: 1,
      failed,
      manual: 0,
      notApplicable: 0,
      notEvaluated,
      coveragePercent: 100 * (1 / totalControls),
    },
    controls: [],
  };
}

function fakeRuntime(runAllAssessments: jest.Mock): ComplianceRuntime & {
  connect: jest.Mock;
  close: jest.Mock;
} {
  return {
    connect: jest.fn(async () => undefined),
    runAllAssessments,
    close: jest.fn(async () => undefined),
  };
}

describe('runComplianceOnce', () => {
  it('rejects an empty endpoint', async () => {
    await expect(runComplianceOnce('')).rejects.toThrow('NEPTUNE_ENDPOINT is required');
  });

  it('aggregates the assessment summaries', async () => {
    const reports = [report('CIS_AWS_FOUNDATIONS', 2, 1), report('SOC2', 1, 3)];
    const runtime = fakeRuntime(jest.fn(async () => reports));

    await expect(runComplianceOnce('wss://cluster/gremlin', () => runtime)).resolves.toEqual({
      frameworksRun: 2,
      controlsAssessed: 4 + 5,
      failedControls: 3,
      notEvaluatedControls: 4,
    });
    expect(runtime.connect).toHaveBeenCalledTimes(1);
    expect(runtime.close).toHaveBeenCalledTimes(1);
  });

  it('closes the runtime when the assessment fails', async () => {
    const runtime = fakeRuntime(jest.fn(async () => Promise.reject(new Error('neptune down'))));

    await expect(runComplianceOnce('wss://cluster/gremlin', () => runtime)).rejects.toThrow(
      'neptune down'
    );
    expect(runtime.close).toHaveBeenCalledTimes(1);
  });
});
