// Verbs that return secret values. ListSecrets returns names only and cannot be
// scoped to a resource, so counting it flagged every read-only and audit role.
const SECRET_READ_VERBS = ['getsecretvalue', 'batchgetsecretvalue'];

export type SecretGrantScope = 'wildcard' | 'scoped' | 'not_resource' | 'none';

function escapeRegex(text: string): string {
  return text.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
}

function matchesPattern(pattern: string, value: string): boolean {
  return new RegExp(`^${escapeRegex(pattern).replace(/\*/g, '.*')}$`).test(value);
}

export function actionGrantsSecretRead(action: string): boolean {
  const normalized = action.toLowerCase();
  if (normalized === '*' || normalized === '*:*') return true;

  const separator = normalized.indexOf(':');
  if (separator === -1) return false;
  const service = normalized.slice(0, separator);
  const verb = normalized.slice(separator + 1);

  if (service !== 'secretsmanager' && service !== '*') return false;
  if (verb === '*' || verb.startsWith('*')) return true;
  return SECRET_READ_VERBS.some((candidate) => matchesPattern(verb, candidate));
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

export function hasCrossAccountPrincipal(stmt: any, accountId: string): boolean {
  const principal = stmt?.Principal;
  if (!principal) return false;
  if (principal === '*') return true;
  if (typeof principal !== 'object') return false;

  const aws = (principal as Record<string, unknown>).AWS;
  if (aws === undefined) return false;
  const values = Array.isArray(aws) ? aws : [aws];

  return values.some((value) => {
    if (value === '*') return true;
    const match =
      typeof value === 'string' ? value.match(/^arn:aws(?:-us-gov|-cn)?:iam::(\d+)/) : null;
    if (!match) return false;
    return match[1] !== accountId;
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

// Object ARNs (bucket/*, bucket/prefix/*) have no vertex; grants on them reach
// the bucket. Wildcard bucket names stay as written and match nothing.
const S3_OBJECT_ARN = /^(arn:[a-z-]+:s3:::)([^/*?]+)\/.*$/;

export function grantTarget(resource: string): string {
  const match = S3_OBJECT_ARN.exec(resource);
  return match ? `${match[1]}${match[2]}` : resource;
}
