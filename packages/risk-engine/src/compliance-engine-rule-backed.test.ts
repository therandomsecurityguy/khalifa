import type { ComplianceControl } from './compliance-types';

// Rule-backed controls: no evaluator of their own, judged from their
// related rules' open issues. Rule enablement comes from the real catalogue.
const controls: ComplianceControl[] = [];
jest.mock('./compliance-types', () => ({
  getControlsByFramework: jest.fn(() => controls),
  REGIONAL_CONTROL_IDS: new Set<string>(),
}));
const evaluators: { controlId: string; evaluate: jest.Mock }[] = [];
jest.mock('./compliance-rules', () => ({ complianceRuleEvaluators: evaluators }));

import { ComplianceEngine, InMemoryReportStore, type OpenIssueReader } from './compliance-engine';

const control = (id: string, relatedRules: string[]): ComplianceControl => ({
  id,
  framework: 'KHALIFA_BASELINE',
  section: 'Detection',
  title: id,
  description: id,
  severity: 'critical',
  automated: true,
  relatedRules,
  evidenceRequirements: [],
  remediationGuidance: '',
});

function engine(reader?: OpenIssueReader) {
  const saveEvidence = jest.fn();
  return {
    saveEvidence,
    engine: new ComplianceEngine(
      { executeQuery: jest.fn() },
      { saveEvidence, getEvidence: jest.fn(), getAllEvidence: jest.fn() },
      new InMemoryReportStore(),
      reader
    ),
  };
}

const reader = (byRule: Record<string, { id: string; status?: string }[]>): OpenIssueReader => ({
  getOpenIssuesByRule: jest.fn(async (id: string) => byRule[id] ?? []),
});

async function assess(c: ComplianceControl, r?: OpenIssueReader) {
  controls.splice(0, controls.length, c);
  const { engine: e, saveEvidence } = engine(r);
  const report = await e.runAssessment('KHALIFA_BASELINE');
  return { result: report.controls[0], saveEvidence };
}

beforeEach(() => evaluators.splice(0));

describe('rule-backed controls', () => {
  it('fails on an open issue of a related rule', async () => {
    const { result, saveEvidence } = await assess(
      control('KH-DET-2', ['RULE-023']),
      reader({ 'RULE-023': [{ id: 'RULE-023-v2-abc', status: 'open' }] })
    );

    expect(result.status).toBe('FAIL');
    expect(result.issues).toEqual(['1 open RULE-023 issue']);
    expect(result.evidence[0].details).toEqual({
      openIssuesByRule: { 'RULE-023': 1 },
      sampleIssueIds: ['RULE-023-v2-abc'],
    });
    expect(saveEvidence).toHaveBeenCalledWith(result.evidence);
  });

  it('passes when no related rule has an open issue', async () => {
    const { result } = await assess(control('KH-DET-2', ['RULE-023']), reader({}));

    expect(result.status).toBe('PASS');
  });

  it('ignores suppressed and resolved issues', async () => {
    const { result } = await assess(
      control('KH-DET-2', ['RULE-023']),
      reader({
        'RULE-023': [
          { id: 'a', status: 'suppressed' },
          { id: 'b', status: 'resolved' },
        ],
      })
    );

    expect(result.status).toBe('PASS');
  });

  it('fails a two-rule control if either rule has an open issue', async () => {
    const { result } = await assess(
      control('KH-DET-1', ['RULE-021', 'RULE-022']),
      reader({ 'RULE-022': [{ id: 'c', status: 'open' }] })
    );

    expect(result.status).toBe('FAIL');
    expect(result.evidence[0].details.openIssuesByRule).toEqual({ 'RULE-021': 0, 'RULE-022': 1 });
  });

  // RULE-003 is disabled in the catalogue, so KH-VULN-1 has no live signal.
  it('is NOT_EVALUATED while a related rule is disabled', async () => {
    const r = reader({});
    const { result } = await assess(control('KH-VULN-1', ['RULE-003']), r);

    expect(result.status).toBe('NOT_EVALUATED');
    expect(result.issues[0]).toContain('RULE-003');
    expect(r.getOpenIssuesByRule).not.toHaveBeenCalled();
  });

  // Before the compliance role can read the issues table the read is denied;
  // that must not fail the whole assessment.
  it('is NOT_EVALUATED, without failing the assessment, when the issue store is unreadable', async () => {
    const denied: OpenIssueReader = {
      getOpenIssuesByRule: jest.fn(async () => {
        throw Object.assign(new Error('not authorized to perform: dynamodb:Query'), {
          name: 'AccessDeniedException',
        });
      }),
    };
    const { result } = await assess(control('KH-DET-2', ['RULE-023']), denied);

    expect(result.status).toBe('NOT_EVALUATED');
    expect(result.issues[0]).toContain('Issue store unreadable');
  });

  it('leaves a control with its own evaluator to that evaluator', async () => {
    const evaluate = jest.fn().mockResolvedValue({ status: 'PASS', evidence: [], issues: [] });
    evaluators.push({ controlId: '2.1.4', evaluate });
    const r = reader({ 'RULE-007': [{ id: 'd', status: 'open' }] });

    const { result } = await assess(control('2.1.4', ['RULE-007']), r);

    expect(evaluate).toHaveBeenCalledTimes(1);
    expect(result.status).toBe('PASS');
    expect(r.getOpenIssuesByRule).not.toHaveBeenCalled();
  });

  it('keeps the old behaviour when no issue reader is configured', async () => {
    const { result } = await assess(control('KH-DET-2', ['RULE-023']));

    expect(result.status).toBe('NOT_EVALUATED');
    expect(result.issues[0]).toContain('No automated evaluator');
  });
});
