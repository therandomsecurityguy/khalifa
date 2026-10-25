import {
  ComplianceEngine,
  InMemoryReportStore,
  deriveMappedReport,
  type ComplianceControlResult,
  type ComplianceEvidence,
  type ComplianceReport,
} from './index';
import type { ComplianceControl, ComplianceFramework } from './compliance-types';

function canonicalResult(
  framework: ComplianceFramework,
  id: string,
  status: ComplianceControlResult['status'],
  evidence: ComplianceEvidence[] = []
): ComplianceControlResult {
  const control: ComplianceControl = {
    id,
    framework,
    section: 'x',
    title: id,
    description: id,
    severity: 'high',
    automated: true,
    relatedRules: [],
    evidenceRequirements: [],
    remediationGuidance: '',
  };
  return { control, status, evidence, issues: [], lastEvaluated: '2026-10-16T00:00:00.000Z' };
}

function canonicalReports(results: ComplianceControlResult[]): ComplianceReport[] {
  const cis = results.filter((r) => r.control.framework === 'CIS_AWS_FOUNDATIONS');
  const baseline = results.filter((r) => r.control.framework === 'KHALIFA_BASELINE');
  return [cis, baseline].map((controls) => ({
    framework: controls[0]?.control.framework ?? 'CIS_AWS_FOUNDATIONS',
    generatedAt: '2026-10-16T00:00:00.000Z',
    summary: {
      totalControls: controls.length,
      passed: 0,
      failed: 0,
      manual: 0,
      notApplicable: 0,
      notEvaluated: 0,
      coveragePercent: 100,
    },
    controls,
  }));
}

// CC9.1 cites KH-2.5 (replication), KH-2.8 (RDS backups), KH-2.10 (deletion protection).
function cc9Results(overrides: Partial<Record<string, ComplianceControlResult['status']>> = {}) {
  const ids: [string, ComplianceControlResult['status']][] = [
    ['KH-2.5', 'PASS'],
    ['KH-2.8', 'PASS'],
    ['KH-2.10', 'PASS'],
  ];
  return canonicalReports(
    ids.map(([id, status]) => canonicalResult('KHALIFA_BASELINE', id, overrides[id] ?? status))
  );
}

describe('deriveMappedReport', () => {
  it('aggregates a requirement from its mapped controls', () => {
    const report = deriveMappedReport('SOC2', cc9Results(), '2026-10-16T12:00:00.000Z');
    const cc91 = report.controls.find((r) => r.control.id === 'CC9.1')!;
    expect(cc91.status).toBe('PASS');
    expect(cc91.mappedControls?.map((m) => m.controlId)).toEqual(['KH-2.5', 'KH-2.8', 'KH-2.10']);
    expect(cc91.mappedControls?.every((m) => m.framework === 'KHALIFA_BASELINE')).toBe(true);
    expect(report.derivedFrom).toEqual(['CIS_AWS_FOUNDATIONS', 'KHALIFA_BASELINE']);
    expect(report.framework).toBe('SOC2');
  });

  it('fails the requirement when any mapped control fails', () => {
    const report = deriveMappedReport('SOC2', cc9Results({ 'KH-2.8': 'FAIL' }), 'x');
    expect(report.controls.find((r) => r.control.id === 'CC9.1')!.status).toBe('FAIL');
  });

  it('keeps manual controls from producing a pass', () => {
    const report = deriveMappedReport('ISO27001', cc9Results({ 'KH-2.5': 'MANUAL' }), 'x');
    expect(report.controls.find((r) => r.control.id === 'A.8.13')!.status).toBe('NOT_EVALUATED');
  });

  it('marks requirements with unassessed controls as not evaluated', () => {
    const report = deriveMappedReport('SOC2', cc9Results(), 'x');
    const cc61 = report.controls.find((r) => r.control.id === 'CC6.1')!;
    expect(cc61.status).toBe('NOT_EVALUATED');
    expect(cc61.issues.join(' ')).toContain('Mapped control not evaluated');
    expect(cc61.mappedControls).toEqual([]);
  });

  it('writes no evidence on the requirement itself', () => {
    const report = deriveMappedReport('SOC2', cc9Results(), 'x');
    for (const result of report.controls) {
      expect(result.evidence).toEqual([]);
    }
  });

  it('summarizes requirements rather than canonical controls', () => {
    const report = deriveMappedReport('SOC2', cc9Results(), 'x');
    expect(report.summary.totalControls).toBe(9);
    expect(report.summary.passed).toBe(1); // CC9.1
  });
});

describe('ComplianceEngine mapped frameworks', () => {
  function rawEngine() {
    const saved: ComplianceEvidence[][] = [];
    const store = new InMemoryReportStore();
    const engine = new ComplianceEngine(
      {
        executeQuery: async () => [],
      },
      {
        saveEvidence: async (evidence) => {
          saved.push(evidence);
        },
        getEvidence: async () => [],
        getAllEvidence: async () => [],
      },
      store
    );
    return { engine, store, saved };
  }

  function buildEngine() {
    const { engine, store, saved } = rawEngine();
    // The canonical assessments are covered by their own suites; here the
    // subject is how runAllAssessments derives and stores mapped reports.
    const canonical = canonicalReports([
      canonicalResult('CIS_AWS_FOUNDATIONS', '1.5', 'PASS'),
      canonicalResult('KHALIFA_BASELINE', 'KH-2.8', 'PASS'),
    ]);
    jest
      .spyOn(
        engine as unknown as { assess: (f: ComplianceFramework) => Promise<unknown> },
        'assess'
      )
      .mockImplementation(async (framework: ComplianceFramework) => {
        const report = canonical.find((r) => r.framework === framework);
        if (!report) throw new Error(`unexpected framework: ${framework}`);
        return { report, failures: [] };
      });
    return { engine, store, saved };
  }

  it('stores derived reports alongside the canonical ones', async () => {
    const { engine, store } = buildEngine();
    const { reports } = await engine.runAllAssessments();
    expect(reports.map((r) => r.framework)).toEqual([
      'CIS_AWS_FOUNDATIONS',
      'KHALIFA_BASELINE',
      'SOC2',
      'ISO27001',
      'PCI_DSS',
      'NIST_800_53',
    ]);
    const soc2 = await store.getLatestReport('SOC2');
    expect(soc2?.controls.length).toBe(9);
    expect(soc2?.derivedFrom).toEqual(['CIS_AWS_FOUNDATIONS', 'KHALIFA_BASELINE']);
  });

  it('writes no evidence while deriving mapped reports', async () => {
    const { engine, saved } = buildEngine();
    const { reports } = await engine.runAllAssessments();
    const mappedIds = new Set(
      reports
        .filter((r) => r.framework === 'SOC2' || r.framework === 'ISO27001')
        .flatMap((r) => r.controls.map((c) => c.control.id))
    );
    expect(mappedIds.size).toBeGreaterThan(0);
    expect(saved).toEqual([]);
  });

  it('refuses to run a mapped framework as a standalone assessment', async () => {
    const { engine } = rawEngine();
    await expect(engine.runAssessment('SOC2')).rejects.toThrow('mapped framework');
  });

  it('serves mapped framework summaries from the citations', async () => {
    const { engine } = buildEngine();
    const { reports } = await engine.runAllAssessments();
    const soc2 = await engine.getFrameworkSummary('SOC2');
    expect(soc2.totalControls).toBe(9);
    expect(soc2.version).toBe('2017');
    expect(soc2.lastAssessment).toBe(reports.find((r) => r.framework === 'SOC2')?.generatedAt);
    expect(soc2.summary.totalControls).toBe(9);
    const iso = await engine.getFrameworkSummary('ISO27001');
    expect(iso.totalControls).toBe(17);
    const pci = await engine.getFrameworkSummary('PCI_DSS');
    expect(pci.totalControls).toBe(11);
    expect(pci.version).toBe('4.0');
    const nist = await engine.getFrameworkSummary('NIST_800_53');
    expect(nist.totalControls).toBe(15);
  });

  it('aggregates evidence for a mapped requirement from the canonical reports', async () => {
    const { engine, store } = buildEngine();
    const evidence: ComplianceEvidence = {
      controlId: 'KH-2.8',
      resourceId: 'db-1',
      resourceType: 'RdsInstance',
      status: 'PASS',
      details: {},
      collectedAt: '2026-10-16T00:00:00.000Z',
      collectedBy: 'compliance-engine',
    };
    await store.saveReport({
      framework: 'KHALIFA_BASELINE',
      generatedAt: '2026-10-16T00:00:00.000Z',
      summary: {
        totalControls: 1,
        passed: 1,
        failed: 0,
        manual: 0,
        notApplicable: 0,
        notEvaluated: 0,
        coveragePercent: 100,
      },
      controls: [canonicalResult('KHALIFA_BASELINE', 'KH-2.8', 'PASS', [evidence])],
    });
    const merged = await engine.getControlEvidence('CC9.1', 'SOC2');
    expect(merged).toEqual([evidence]);
    expect(await engine.getControlEvidence('CC6.1', 'SOC2')).toEqual([]);
  });
});
