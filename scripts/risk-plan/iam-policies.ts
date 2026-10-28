import {
  isActionMatched,
  parsePolicyDocument,
  type PolicyDocument,
} from '../../lambdas/policy-evaluator/policy-parser';
import type { ParsedStatement } from '../../lambdas/policy-evaluator/types';
import type { RawFinding } from './analyzers';
import type { PlannedResource } from './plan';

// Shift-left for IAM policies: a policy document in a plan (aws_iam_policy /
// aws_iam_role_policy) or a standalone before/after pair is parsed with the
// same policy parser the CIEM evaluator runs, and grants that the catalogue's
// rules would eventually fire on are reported before they deploy. With a
// before document the check is a diff: a grant that already existed is not
// newly introduced. Conditions (iam:PassedToService, org boundaries, SCPs)
// are NOT evaluated — findings say so.

export class PolicyParseError extends Error {}

const PASS_ROLE = 'iam:PassRole';

function safeParse(documentJson: string): PolicyDocument | undefined {
  try {
    return parsePolicyDocument(documentJson);
  } catch {
    return undefined;
  }
}

function allowsAction(statement: ParsedStatement, action: string): boolean {
  return (
    statement.effect === 'Allow' &&
    statement.actions.some((pattern) => isActionMatched(pattern, action))
  );
}

function allowsOnAllResources(statement: ParsedStatement, action: string): boolean {
  return allowsAction(statement, action) && statement.resources.includes('*');
}

function grantDetail(statement: ParsedStatement, base: string): string {
  const conditions = statement.conditions && Object.keys(statement.conditions).length > 0;
  return conditions ? `${base} (statement conditions are not evaluated by plan analysis)` : base;
}

function wildcardActionStatement(document: PolicyDocument): ParsedStatement | undefined {
  return document.Statement.find(
    (statement) => statement.effect === 'Allow' && statement.actions.includes('*')
  );
}

// The analyzer core, shared by plan-embedded documents and standalone files.
export function policyDocumentFindings(
  afterJson: string,
  beforeJson: string | undefined,
  address: string
): RawFinding[] {
  const after = safeParse(afterJson);
  if (!after) return [];
  const before = beforeJson ? safeParse(beforeJson) : undefined;
  const findings: RawFinding[] = [];

  const passRole = after.Statement.find((statement) => allowsOnAllResources(statement, PASS_ROLE));
  const passRoleBefore = before?.Statement.some((statement) =>
    allowsOnAllResources(statement, PASS_ROLE)
  );
  if (passRole && !passRoleBefore) {
    findings.push({
      ruleId: null,
      fallbackName: 'IAM Policy Grants iam:PassRole on All Resources',
      fallbackSeverity: 'critical',
      address,
      detail: grantDetail(
        passRole,
        'allows iam:PassRole on Resource "*" — whoever can use this policy can hand any role, admin ones included, to compute they launch (RULE-034 fires once an admin role is in the reachable path)'
      ),
      predictedPath: 'Identity → iam:PassRole(*) → compute it launches → role',
    });
  }

  const wildcard = wildcardActionStatement(after);
  const wildcardBefore = before ? wildcardActionStatement(before) !== undefined : false;
  if (wildcard && !wildcardBefore) {
    findings.push({
      ruleId: null,
      fallbackName: 'IAM Policy Grants Wildcard Actions',
      fallbackSeverity: 'high',
      address,
      detail: grantDetail(wildcard, 'grants Action "*": every API at once, including IAM changes'),
      predictedPath: 'Identity → * actions → any collected resource',
    });
  }

  return findings;
}

// Plan-embedded policies: `after.policy` is a JSON string on aws_iam_policy
// and aws_iam_role_policy; before gives true diff semantics on updates.
export function policyFindingsForResource(resource: PlannedResource): RawFinding[] {
  const after = resource.after.policy;
  if (typeof after !== 'string') return [];
  const before = typeof resource.before.policy === 'string' ? resource.before.policy : undefined;
  return policyDocumentFindings(after, before, resource.address);
}

// Standalone files (for flows outside Terraform, e.g. a diff of
// `aws iam get-policy-version` before and after). A malformed document is the
// operator's error, not a silent skip.
export function standalonePolicyFindings(afterText: string, beforeText?: string): RawFinding[] {
  if (safeParse(afterText) === undefined) {
    throw new PolicyParseError('--policy must be a valid IAM policy document (JSON)');
  }
  if (beforeText !== undefined && safeParse(beforeText) === undefined) {
    throw new PolicyParseError('--policy-before must be a valid IAM policy document (JSON)');
  }
  return policyDocumentFindings(afterText, beforeText, 'policy');
}
