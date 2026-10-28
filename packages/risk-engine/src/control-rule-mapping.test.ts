import { complianceRuleEvaluators } from './compliance-rules';
import { getAllControls } from './compliance-types';
import { riskRules } from './rules';

/**
 * Guards the control <-> rule mapping in both directions.
 *
 * `relatedRules` on a control is the only link between the two catalogues;
 * `RiskRule` has no pointer back. Without these assertions a rule added
 * without a mapping is invisible until someone audits it by hand, which is
 * how RULE-011 through RULE-024 all shipped unlinked.
 */
describe('control to rule mapping', () => {
  const controls = getAllControls();
  const ruleIds = new Set(riskRules.map((rule) => rule.id));
  const referenced = new Set(controls.flatMap((control) => control.relatedRules));

  it('every risk rule is referenced by at least one control', () => {
    const orphaned = riskRules.map((rule) => rule.id).filter((id) => !referenced.has(id));

    expect(orphaned).toEqual([]);
  });

  it('every relatedRules entry resolves to a rule that exists', () => {
    const dangling = controls.flatMap((control) =>
      control.relatedRules.filter((id) => !ruleIds.has(id)).map((id) => `${control.id} -> ${id}`)
    );

    expect(dangling).toEqual([]);
  });

  it('every evaluator targets a control that exists', () => {
    const controlIds = new Set(controls.map((control) => control.id));
    const unknown = complianceRuleEvaluators
      .map((evaluator) => evaluator.controlId)
      .filter((id) => !controlIds.has(id));

    expect(unknown).toEqual([]);
  });

  it('control ids are unique', () => {
    const seen = new Set<string>();
    const duplicates = controls.map((c) => c.id).filter((id) => !seen.add(id) && true);

    expect(duplicates).toEqual([]);
  });
});

/**
 * The reviewed mapping, pinned.
 *
 * The tests above check the mapping's shape: every rule mapped somewhere, every
 * reference resolving. Nothing checked that a mapping is right, and it drifted
 * badly: an audit on 2026-09-28 found 24 of 45 mappings wrong -- RULE-004 alone
 * sat on nine unrelated controls -- and every earlier fix had applied a
 * different, unwritten standard.
 *
 * THE CRITERION: a rule maps to a control when every finding the rule raises is
 * a violation of that control. Catching only a narrower slice is fine -- IMDSv1
 * on role-holding instances is still an IMDSv1 violation. Detecting something
 * merely adjacent is not: root activity is not evidence that a root-activity
 * alarm is missing, and a Security Hub finding proves Security Hub is enabled.
 *
 * Changing a control's relatedRules fails this test until the entry below is
 * updated, with its reason, so the change is made against the criterion and
 * reviewed rather than slipped in.
 */
const REVIEWED_MAPPING: Record<string, { controls: string[]; why: string }> = {
  'RULE-001': { controls: ['KH-EXP-1'], why: 'exposed EC2 whose role reaches restricted S3' },
  'RULE-002': {
    controls: ['5.2', '5.3'],
    why: 'SG open to 0.0.0.0/0 (5.2) or ::/0 (5.3) on 22/3389',
  },
  'RULE-003': { controls: ['KH-VULN-1'], why: 'critical CVEs, on exposed workloads only' },
  'RULE-004': { controls: ['KH-IAM-1'], why: 'admin role on an internet-reachable workload' },
  'RULE-005': { controls: ['KH-PATH-1'], why: 'Internet to crown jewel within four hops' },
  'RULE-006': { controls: ['KH-IAM-1'], why: 'trusted role with a wildcard-resource Allow' },
  'RULE-007': { controls: ['2.1.4'], why: 'public S3 bucket, sensitive ones only' },
  'RULE-008': { controls: ['2.3.3'], why: 'public RDS instance, sensitive ones only' },
  'RULE-009': {
    controls: ['KH-EXP-1'],
    why: 'internet-exposed Lambda whose role reaches classified data',
  },
  'RULE-010': {
    controls: ['KH-SEC-1'],
    why: 'secret resource policy allowing an outside account or anyone',
  },
  'RULE-011': { controls: ['2.1.4'], why: 'public S3 bucket holding PII' },
  'RULE-012': { controls: ['KH-SEC-2'], why: 'secrets found in S3 objects or Lambda environments' },
  'RULE-013': { controls: ['1.14'], why: 'active access key older than 90 days' },
  'RULE-014': { controls: ['1.12'], why: 'key unused 90+ days, so also past 1.12 threshold' },
  'RULE-015': { controls: ['1.10'], why: 'console password with no MFA' },
  'RULE-016': { controls: ['KH-SEC-1'], why: 'wildcard secret-read grant to a principal' },
  'RULE-017': { controls: ['KH-4.1'], why: 'GuardDuty disabled or missing' },
  'RULE-018': {
    controls: ['KH-SH-1'],
    why: 'active critical/high Security Hub finding on an exposed resource',
  },
  'RULE-019': { controls: ['KH-EKS-1'], why: 'EKS endpoint public and open to the world' },
  'RULE-020': {
    controls: ['1.7'],
    why: 'root activity violates "eliminate root use"; not 4.3, which asks for an alarm',
  },
  'RULE-021': { controls: ['KH-DET-1'], why: 'unresolved secret read from a new source IP' },
  'RULE-022': {
    controls: ['KH-DET-1'],
    why: 'unresolved AccessDenied spike; not 4.1, which asks for an alarm',
  },
  'RULE-023': { controls: ['KH-DET-2'], why: 'a canary credential has been used' },
  'RULE-035': {
    controls: ['KH-DET-1'],
    why: 'unresolved first-use API activity; a lead, so auto-ticketing stays off',
  },
  'RULE-036': {
    controls: ['KH-DET-1'],
    why: 'unresolved unusual-hour activity; informational, never auto-ticketed',
  },
  'RULE-024': { controls: ['5.6'], why: 'IMDSv1 instances, those holding a role' },
  'RULE-025': { controls: ['1.20'], why: 'Access Analyzer not ACTIVE, including missing' },
  'RULE-026': { controls: ['3.6'], why: 'customer CMK without rotation' },
  'RULE-027': { controls: ['3.7'], why: 'VPC without flow logs' },
  'RULE-028': { controls: ['3.3'], why: 'Config recorder not recording' },
  'RULE-029': {
    controls: ['KH-DET-3'],
    why: 'an active GuardDuty attack finding on an internet-exposed resource',
  },
  'RULE-031': { controls: ['KH-IAM-3'], why: 'admin IAM user with an active access key' },
  'RULE-032': { controls: ['KH-SEC-1'], why: 'prod secret readable from a non-prod account' },
  'RULE-033': { controls: ['KH-SEC-1'], why: 'secret shared with another collected account' },
  'RULE-030': {
    controls: ['KH-IAM-2'],
    why: 'principal that can assume its way to an admin or escalation role',
  },
  'RULE-034': {
    controls: ['KH-IAM-2'],
    why: 'principal that can pass an admin role to compute it creates',
  },
};

// Mapping is per rule, so every finding a rule raises lands on every control it
// maps to. A rule starting from several resource types can therefore only map to
// controls that cover all of them: RULE-011 matched S3 buckets and RDS
// instances, and each of 2.1.4 (S3) and 2.3.3 (RDS) showed the other's findings.
// Every CIS control is about one resource type.
describe('rules mapped to CIS controls start from one resource type', () => {
  const cisRules = new Set(
    getAllControls()
      .filter((control) => control.framework === 'CIS_AWS_FOUNDATIONS')
      .flatMap((control) => control.relatedRules)
  );

  it.each(riskRules.filter((rule) => cisRules.has(rule.id)).map((rule) => [rule.id, rule]))(
    '%s',
    (_id, rule) => {
      expect(rule.gremlinQueryTemplate).not.toMatch(/g\.V\(\)\s*\.hasLabel\(\s*within\(/);
    }
  );
});

describe('reviewed control to rule mapping', () => {
  const actual: Record<string, string[]> = {};
  for (const control of getAllControls()) {
    for (const rule of control.relatedRules) (actual[rule] ??= []).push(control.id);
  }

  it('covers every risk rule', () => {
    expect(Object.keys(REVIEWED_MAPPING).sort()).toEqual(riskRules.map((r) => r.id).sort());
  });

  it.each(Object.entries(REVIEWED_MAPPING))(
    '%s maps to exactly its reviewed controls',
    (rule, reviewed) => {
      expect((actual[rule] ?? []).sort()).toEqual([...reviewed.controls].sort());
    }
  );
});

// Automated controls with related rules but no evaluator are judged
// from those rules' open issues. Pinned so a new evaluator or rule changes the
// set deliberately.
describe('rule-backed controls', () => {
  it('are exactly the controls defined as a rule outcome', () => {
    const evaluated = new Set(complianceRuleEvaluators.map((e) => e.controlId));
    const ruleBacked = getAllControls()
      .filter((c) => c.automated && !evaluated.has(c.id) && c.relatedRules.length > 0)
      .map((c) => c.id)
      .sort();
    expect(ruleBacked).toEqual(
      [
        '1.7',
        'KH-DET-1',
        'KH-DET-2',
        'KH-DET-3',
        'KH-EXP-1',
        'KH-IAM-1',
        'KH-IAM-2',
        'KH-IAM-3',
        'KH-SH-1',
        'KH-VULN-1',
      ].sort()
    );
  });
});
