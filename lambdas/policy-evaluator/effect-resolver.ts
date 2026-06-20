import type { ParsedStatement, EffectivePermission, ConditionalGrant, IamConditionBlock } from './types';
import { parsePolicyDocument, isActionMatched, isResourceMatched } from './policy-parser';
import { evaluateConditionBlock } from './condition-evaluator';
import type { ConditionEvaluationContext } from './types';

interface PolicyAttachment {
  policyDocumentJson: string;
  policyArn: string;
}

export interface PermissionBoundary {
  policyDocumentJson: string;
  policyArn: string;
}

export interface ResolveInput {
  principalArn: string;
  identityPolicies: PolicyAttachment[];
  resourcePolicies?: PolicyAttachment[];
  permissionBoundary?: PermissionBoundary;
  serviceControlPolicies?: PolicyAttachment[];
  sessionPolicies?: PolicyAttachment[];
}

export function resolveEffectivePermissions(input: ResolveInput): EffectivePermission {
  const allowedActions = new Set<string>();
  const deniedActions = new Set<string>();
  const conditionalGrants: ConditionalGrant[] = [];
  const policiesEvaluated: string[] = [];

  const allStatements: { statement: ParsedStatement; source: string }[] = [];

  for (const policy of input.identityPolicies) {
    try {
      const doc = parsePolicyDocument(policy.policyDocumentJson);
      for (const stmt of doc.Statement) {
        allStatements.push({ statement: stmt, source: policy.policyArn });
      }
      policiesEvaluated.push(policy.policyArn);
    } catch (e) {}
  }

  for (const policy of input.sessionPolicies || []) {
    try {
      const doc = parsePolicyDocument(policy.policyDocumentJson);
      for (const stmt of doc.Statement) {
        allStatements.push({ statement: stmt, source: policy.policyArn });
      }
      policiesEvaluated.push(policy.policyArn);
    } catch (e) {}
  }

  for (const policy of input.resourcePolicies || []) {
    try {
      const doc = parsePolicyDocument(policy.policyDocumentJson);
      for (const stmt of doc.Statement) {
        allStatements.push({ statement: stmt, source: policy.policyArn });
      }
      policiesEvaluated.push(policy.policyArn);
    } catch (e) {}
  }

  const explicitDenies = allStatements.filter((s) => s.statement.effect === 'Deny');
  const explicitAllows = allStatements.filter((s) => s.statement.effect === 'Allow');

  for (const { statement } of explicitDenies) {
    for (const action of statement.actions) {
      deniedActions.add(action);
      allowedActions.delete(action);
    }
  }

  for (const { statement } of explicitAllows) {
    if (statement.conditions && Object.keys(statement.conditions).length > 0) {
      const conditionResult = evaluateConditionBlock(statement.conditions, {});
      if (conditionResult === 'conditional' || conditionResult === true) {
        for (const action of statement.actions) {
          if (!deniedActions.has(action)) {
            conditionalGrants.push({
              action,
              resource: statement.resources.join(','),
              conditions: statement.conditions,
            });
          }
        }
      }
      continue;
    }

    const hasWildcard = statement.actions.some((a) => a === '*' || a === '*:*');

    if (hasWildcard && (input.permissionBoundary || (input.serviceControlPolicies && input.serviceControlPolicies.length > 0))) {
      if (input.permissionBoundary) {
        try {
          const boundaryDoc = parsePolicyDocument(input.permissionBoundary.policyDocumentJson);
          for (const bs of boundaryDoc.Statement) {
            if (bs.effect === 'Allow') {
              for (const ba of bs.actions) {
                if (ba === '*' || ba === '*:*') {
                  allowedActions.add('*');
                } else if (!deniedActions.has(ba) && isActionMatchedByStatement(statement, ba)) {
                  allowedActions.add(ba);
                }
              }
            }
          }
        } catch (e) {}
      } else {
        allowedActions.add('*');
      }

      if (input.serviceControlPolicies) {
        for (const scp of input.serviceControlPolicies) {
          try {
            const scpDoc = parsePolicyDocument(scp.policyDocumentJson);
            const scpAllowedActions = new Set<string>();
            for (const ss of scpDoc.Statement) {
              if (ss.effect === 'Allow') {
                for (const sa of ss.actions) {
                  scpAllowedActions.add(sa);
                }
              }
            }
            if (!scpAllowedActions.has('*') && !scpAllowedActions.has('*:*')) {
              for (const aa of [...allowedActions]) {
                if (aa !== '*' && aa !== '*:*' && !scpAllowedActions.has(aa) && ![...scpAllowedActions].some((sa) => isActionMatched(sa, aa))) {
                  allowedActions.delete(aa);
                  deniedActions.add(aa);
                }
              }
            }
          } catch (e) {}
        }
      }
    } else {
      for (const action of statement.actions) {
        if (!deniedActions.has(action)) {
          let blockedByBoundary = false;

          if (input.permissionBoundary) {
            try {
              const boundaryDoc = parsePolicyDocument(input.permissionBoundary.policyDocumentJson);
              const boundaryAllowsAction = boundaryDoc.Statement.some(
                (bs) => bs.effect === 'Allow' && bs.actions.some((ba) => isActionMatched(ba, action))
              );
              if (!boundaryAllowsAction) blockedByBoundary = true;
            } catch (e) {}
          }

          if (!blockedByBoundary) {
            for (const scp of input.serviceControlPolicies || []) {
              try {
                const scpDoc = parsePolicyDocument(scp.policyDocumentJson);
                const scpAllows = scpDoc.Statement.some(
                  (ss) => ss.effect === 'Allow' && ss.actions.some((sa) => isActionMatched(sa, action))
                );
                if (!scpAllows) blockedByBoundary = true;
              } catch (e) {}
            }
          }

          if (!blockedByBoundary) {
            allowedActions.add(action);
          } else {
            deniedActions.add(action);
          }
        }
      }
    }
  }

  const allowedArray = [...allowedActions];
  const deniedArray = [...deniedActions];
  const isAdmin = allowedActions.has('*') || allowedActions.has('*:*') || allowedActions.has('iam:*') || allowedActions.has('AdministratorAccess');

  return {
    id: `eff-perm:${input.principalArn}`,
    principalArn: input.principalArn,
    allowedActions: allowedArray,
    deniedActions: deniedArray,
    conditionalGrants,
    policiesEvaluated,
    evaluatedAt: new Date().toISOString(),
    isAdmin,
    blastRadius: allowedArray.length,
  };
}

export function checkActionAllowed(
  effectivePerm: EffectivePermission,
  action: string,
  resource?: string,
  context?: ConditionEvaluationContext
): { allowed: boolean; reason: string } {
  if (effectivePerm.deniedActions.some((da) => isActionMatched(da, action))) {
    return { allowed: false, reason: 'Explicit deny' };
  }

  if (effectivePerm.allowedActions.some((aa) => isActionMatched(aa, action))) {
    if (resource) {
      const hasMatchingAllow = effectivePerm.allowedActions.some((aa) => isActionMatched(aa, action));
      if (!hasMatchingAllow) {
        return { allowed: false, reason: 'Resource not in allowed list' };
      }
    }
    return { allowed: true, reason: 'Explicit allow' };
  }

  for (const grant of effectivePerm.conditionalGrants) {
    if (isActionMatched(grant.action, action)) {
      if (context) {
        const conditionResult = evaluateConditionBlock(grant.conditions, context);
        if (conditionResult === true) return { allowed: true, reason: 'Conditional allow (conditions met)' };
        if (conditionResult === false) return { allowed: false, reason: 'Conditional deny (conditions not met)' };
      }
      return { allowed: false, reason: 'Conditional (no context provided)' };
    }
  }

  return { allowed: false, reason: 'Implicit deny' };
}

function isActionMatchedByStatement(statement: ParsedStatement, action: string): boolean {
  if (statement.notActions && statement.notActions.length > 0) {
    return !statement.notActions.some((na) => isActionMatched(na, action));
  }
  return statement.actions.some((a) => isActionMatched(a, action));
}