import { globMatch } from '../../shared/glob';

// Verbs that return secret values. ListSecrets returns names only and cannot be
// scoped to a resource, so counting it flagged every read-only and audit role.
const SECRET_READ_VERBS = ['getsecretvalue', 'batchgetsecretvalue'];

export type SecretGrantScope = 'wildcard' | 'scoped' | 'not_resource' | 'none';

export function actionGrantsSecretRead(action: string): boolean {
  const normalized = action.toLowerCase();
  if (normalized === '*' || normalized === '*:*') return true;

  const separator = normalized.indexOf(':');
  if (separator === -1) return false;
  const service = normalized.slice(0, separator);
  const verb = normalized.slice(separator + 1);

  if (service !== 'secretsmanager' && service !== '*') return false;
  if (verb === '*' || verb.startsWith('*')) return true;
  return SECRET_READ_VERBS.some((candidate) => globMatch(verb, candidate));
}

export function statementGrantsSecretRead(actions: unknown): boolean {
  const list = Array.isArray(actions) ? actions : actions ? [actions] : [];
  return list.some((action) => typeof action === 'string' && actionGrantsSecretRead(action));
}

export function isWildcardSecretResource(resource: string): boolean {
  if (resource === '*') return true;
  if (!/^arn:aws(?:-us-gov|-cn)?:secretsmanager:/.test(resource)) return false;
  return resource.includes('*');
}

function awsPrincipals(stmt: any): unknown[] {
  const principal = stmt?.Principal;
  if (principal === '*') return ['*'];
  if (!principal || typeof principal !== 'object') return [];
  const aws = (principal as Record<string, unknown>).AWS;
  if (aws === undefined) return [];
  return Array.isArray(aws) ? aws : [aws];
}

export function principalIsAnyone(stmt: any): boolean {
  return awsPrincipals(stmt).includes('*');
}

// Accounts other than the policy's own that a principal names, as an ARN or a
// bare account ID.
export function principalAccountIds(stmt: any, accountId: string): string[] {
  const ids = new Set<string>();
  for (const value of awsPrincipals(stmt)) {
    if (typeof value !== 'string') continue;
    const match = /^(?:arn:aws(?:-us-gov|-cn)?:iam::)?(\d{12})(?::|$)/.exec(value);
    if (match && match[1] !== accountId) ids.add(match[1]);
  }
  return [...ids].sort();
}

export function hasCrossAccountPrincipal(stmt: any, accountId: string): boolean {
  return principalIsAnyone(stmt) || principalAccountIds(stmt, accountId).length > 0;
}

// Operators that require the key to be present and match. IfExists, negated
// and ForAllValues forms pass for a principal outside any organization.
const ORG_CONDITION_OPERATORS = new Set([
  'stringequals',
  'stringequalsignorecase',
  'stringlike',
  'foranyvalue:stringequals',
  'foranyvalue:stringlike',
]);
const ORG_CONDITION_KEYS = new Set(['aws:principalorgid', 'aws:principalorgpaths']);
// A literal organization ID, optionally followed by an OU path.
const LITERAL_ORG_VALUE = /^o-[a-z0-9]{10,32}(?:\/|$)/;

// True when a condition limits the principal to a named organization.
export function isOrgRestricted(stmt: any): boolean {
  const condition = stmt?.Condition;
  if (!condition || typeof condition !== 'object') return false;
  return Object.entries(condition as Record<string, unknown>).some(([operator, keys]) => {
    if (!ORG_CONDITION_OPERATORS.has(operator.toLowerCase())) return false;
    if (!keys || typeof keys !== 'object') return false;
    return Object.entries(keys as Record<string, unknown>).some(([key, value]) => {
      if (!ORG_CONDITION_KEYS.has(key.toLowerCase())) return false;
      const values = Array.isArray(value) ? value : [value];
      return (
        values.length > 0 && values.every((v) => typeof v === 'string' && LITERAL_ORG_VALUE.test(v))
      );
    });
  });
}

export function deriveSecretGrantScope(stmt: any): SecretGrantScope {
  const notResources = Array.isArray(stmt?.NotResource)
    ? stmt.NotResource
    : stmt?.NotResource
      ? [stmt.NotResource]
      : [];
  if (notResources.length > 0) return 'not_resource';

  const resources = Array.isArray(stmt?.Resource)
    ? stmt.Resource
    : stmt?.Resource
      ? [stmt.Resource]
      : [];
  if (resources.length === 0) return 'none';
  if (
    resources.some(
      (resource: unknown) => typeof resource === 'string' && isWildcardSecretResource(resource)
    )
  ) {
    return 'wildcard';
  }
  return 'scoped';
}

export function deriveStatementSecretProperties(
  stmt: any,
  accountId: string
): {
  grants_secret_read: boolean;
  secret_grant_scope: SecretGrantScope;
  has_cross_account_principal: boolean;
} {
  return {
    grants_secret_read: stmt?.Effect === 'Allow' && statementGrantsSecretRead(stmt?.Action),
    secret_grant_scope: deriveSecretGrantScope(stmt),
    has_cross_account_principal: hasCrossAccountPrincipal(stmt, accountId),
  };
}

// Who a resource policy statement shares with. Identity policy statements have
// no Principal and get none of these.
export function deriveStatementPrincipalProperties(
  stmt: any,
  accountId: string
):
  | {
      principal_is_anyone: boolean;
      principal_org_restricted: boolean;
      principal_account_ids: string[];
      principal_account_count: number;
    }
  | Record<string, never> {
  if (stmt?.Principal === undefined) return {};
  const accountIds = principalAccountIds(stmt, accountId);
  return {
    principal_is_anyone: principalIsAnyone(stmt),
    principal_org_restricted: isOrgRestricted(stmt),
    principal_account_ids: accountIds,
    principal_account_count: accountIds.length,
  };
}

// Object ARNs (bucket/*, bucket/prefix/*) have no vertex; grants on them reach
// the bucket. Wildcard bucket names stay as written and match nothing.
const S3_OBJECT_ARN = /^(arn:[a-z-]+:s3:::)([^/*?]+)\/.*$/;

export function grantTarget(resource: string): string {
  const match = S3_OBJECT_ARN.exec(resource);
  return match ? `${match[1]}${match[2]}` : resource;
}
