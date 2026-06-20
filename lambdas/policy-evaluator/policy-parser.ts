import type { ParsedStatement, IamConditionBlock } from './types';

export interface PolicyDocument {
  Version: string;
  Statement: ParsedStatement[];
}

export function parsePolicyDocument(documentJson: string): PolicyDocument {
  const doc = JSON.parse(documentJson);
  const version = doc.Version || '2012-10-17';
  const rawStatements = Array.isArray(doc.Statement)
    ? doc.Statement
    : doc.Statement
      ? [doc.Statement]
      : [];

  const statements: ParsedStatement[] = rawStatements.map((stmt: any, index: number) => ({
    sid: stmt.Sid || `stmt-${index}`,
    effect: stmt.Effect === 'Allow' ? ('Allow' as const) : ('Deny' as const),
    actions: normalizeList(stmt.Action),
    resources: normalizeList(stmt.Resource),
    conditions: stmt.Condition ? normalizeConditions(stmt.Condition) : undefined,
    notActions: stmt.NotAction ? normalizeList(stmt.NotAction) : undefined,
    notResources: stmt.NotResource ? normalizeList(stmt.NotResource) : undefined,
  }));

  return { Version: version, Statement: statements };
}

export function parseTrustPolicyDocument(
  documentJson: string
): { principalType: string; principalValue: string; conditions?: IamConditionBlock }[] {
  const doc = JSON.parse(documentJson);
  const rawStatements = Array.isArray(doc.Statement)
    ? doc.Statement
    : doc.Statement
      ? [doc.Statement]
      : [];
  const results: {
    principalType: string;
    principalValue: string;
    conditions?: IamConditionBlock;
  }[] = [];

  for (const stmt of rawStatements) {
    if (stmt.Effect !== 'Allow') continue;
    const principals = stmt.Principal || {};
    const conditions = stmt.Condition ? normalizeConditions(stmt.Condition) : undefined;

    for (const [principalType, principalValues] of Object.entries(principals)) {
      const values = normalizeList(principalValues as any);
      for (const v of values) {
        results.push({ principalType, principalValue: v, conditions });
      }
    }
  }

  return results;
}

function normalizeList(value: any): string[] {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
}

function normalizeConditions(conditions: any): IamConditionBlock {
  const result: IamConditionBlock = {};
  for (const [operator, keys] of Object.entries(conditions)) {
    result[operator] = {};
    for (const [key, val] of Object.entries(keys as Record<string, any>)) {
      result[operator][key] = Array.isArray(val) ? val.map(String) : [String(val)];
    }
  }
  return result;
}

export function isActionMatched(actionPattern: string, action: string): boolean {
  if (actionPattern === '*' || actionPattern === '*:*') return true;
  const patternLower = actionPattern.toLowerCase();
  const actionLower = action.toLowerCase();
  return wildcardMatch(patternLower, actionLower);
}

export function isResourceMatched(resourcePattern: string, resource: string): boolean {
  if (resourcePattern === '*') return true;
  return wildcardMatch(resourcePattern, resource);
}

function wildcardMatch(pattern: string, text: string): boolean {
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  const regex = new RegExp(`^${regexStr}$`, 'i');
  return regex.test(text);
}

export function expandActionPattern(pattern: string, knownServices?: Set<string>): string[] {
  if (pattern === '*' || pattern === '*:*') return ['*:*'];
  if (!pattern.includes('*') && !pattern.includes('?')) return [pattern];

  if (knownServices && pattern.endsWith(':*')) {
    const service = pattern.split(':')[0].toLowerCase();
    if (knownServices.has(service)) {
      return [pattern];
    }
  }

  return [pattern];
}

export function isActionInList(action: string, actionList: string[]): boolean {
  return actionList.some((pattern) => isActionMatched(pattern, action));
}

export function isResourceInList(resource: string, resourceList: string[]): boolean {
  return resourceList.some((pattern) => isResourceMatched(pattern, resource));
}
