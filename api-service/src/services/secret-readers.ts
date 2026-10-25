import { globMatch } from '@khalifa/risk-engine';

const READ_ACTION = 'secretsmanager:GetSecretValue';

export interface ReaderRow {
  principal: { id: string; label: string; name: string; admin: boolean };
  policy: { type: string; arn: string; name: string };
  statement: {
    id: string;
    effect: string;
    actions: string | null;
    notActions: string | null;
    resources: string | null;
    notResources: string | null;
    conditional: boolean;
  };
}

// How widely a statement reaches the secret: by its own ARN, a pattern, every
// resource, or every resource except some (NotResource).
export type ReaderScope = 'secret' | 'pattern' | 'all' | 'not-resource';

export interface ReaderGrant {
  policyName: string;
  policyKind: 'inline' | 'managed' | 'aws-managed';
  scope: ReaderScope;
  // Allowed through NotAction: every action except the ones it lists.
  notAction: boolean;
  conditional: boolean;
}

export interface SecretReader {
  id: string;
  name: string;
  type: 'role' | 'user' | 'group';
  admin: boolean;
  // A Deny with conditions also matches, so the read may be refused.
  mayBeDenied: boolean;
  grants: ReaderGrant[];
}

interface Principal {
  id: string;
  name: string;
  type: SecretReader['type'];
  admin: boolean;
}

interface PreparedStatement {
  effect: 'Allow' | 'Deny';
  conditional: boolean;
  notAction: boolean;
  resources: string[] | null;
  notResources: string[] | null;
  attachments: Array<{
    principal: Principal;
    policyName: string;
    policyKind: ReaderGrant['policyKind'];
  }>;
}

// An account's statements that bear on reading any secret, parsed once and
// shared by every principal they are attached to.
export type PreparedStatements = PreparedStatement[];

const TYPES: Record<string, SecretReader['type']> = {
  IamRole: 'role',
  IamUser: 'user',
  IamGroup: 'group',
};
const SCOPE_RANK: Record<ReaderScope, number> = {
  all: 0,
  'not-resource': 1,
  pattern: 2,
  secret: 3,
};

// The writer stores arrays as JSON text; anything else is treated as absent.
function list(json: string | null): string[] | null {
  if (!json) return null;
  try {
    const value: unknown = JSON.parse(json);
    return Array.isArray(value)
      ? value.filter((item): item is string => typeof item === 'string')
      : null;
  } catch {
    return null;
  }
}

function coversRead(actions: string[] | null, notActions: string[] | null): boolean {
  if (actions) return actions.some((action) => globMatch(action, READ_ACTION));
  return notActions !== null && !notActions.some((action) => globMatch(action, READ_ACTION));
}

// A resource whose service field cannot be Secrets Manager matches no secret.
function couldNameSecret(resource: string): boolean {
  if (resource === '*') return true;
  const service = resource.split(':')[2];
  return service === undefined || globMatch(service, 'secretsmanager');
}

function scopeFor(statement: PreparedStatement, arn: string): ReaderScope | null {
  if (statement.resources) {
    const matching = statement.resources.filter((resource) => globMatch(resource, arn));
    if (matching.length === 0) return null;
    if (matching.includes('*')) return 'all';
    return matching.some((resource) => !/[*?]/.test(resource)) ? 'secret' : 'pattern';
  }
  if (statement.notResources) {
    return statement.notResources.some((resource) => globMatch(resource, arn))
      ? null
      : 'not-resource';
  }
  return null;
}

function policyKind(type: string): ReaderGrant['policyKind'] {
  return type === 'inline' || type === 'aws-managed' ? type : 'managed';
}

function policyName(policy: ReaderRow['policy']): string {
  if (policy.type === 'inline') return policy.name;
  const tail = policy.arn.split(':policy/').pop();
  return tail || policy.name;
}

export function prepareStatements(rows: ReaderRow[]): PreparedStatements {
  // A statement that cannot grant or deny a secret read is remembered as null.
  const byId = new Map<string, PreparedStatement | null>();
  for (const { principal, policy, statement } of rows) {
    const type = TYPES[principal.label];
    const effect = statement.effect;
    if (!type || (effect !== 'Allow' && effect !== 'Deny')) continue;
    // Grouped within its policy, so statements of different policies never
    // merge whatever form their ids take; a missing id falls back to content.
    const key = JSON.stringify([
      policy.arn,
      policy.name,
      statement.id || [
        effect,
        statement.actions,
        statement.notActions,
        statement.resources,
        statement.notResources,
        statement.conditional,
      ],
    ]);
    let prepared = byId.get(key);
    if (prepared === null) continue;
    if (prepared === undefined) {
      const actions = list(statement.actions);
      const notActions = list(statement.notActions);
      const resources = list(statement.resources)?.filter(couldNameSecret) ?? null;
      const notResources = resources === null ? list(statement.notResources) : null;
      if (
        !coversRead(actions, notActions) ||
        (resources !== null && resources.length === 0) ||
        (resources === null && notResources === null)
      ) {
        byId.set(key, null);
        continue;
      }
      prepared = {
        effect,
        conditional: statement.conditional,
        notAction: actions === null,
        resources,
        notResources,
        attachments: [],
      };
      byId.set(key, prepared);
    }
    prepared.attachments.push({
      principal: {
        id: principal.id,
        name: principal.name || principal.id.split('/').pop() || principal.id,
        type,
        admin: principal.admin,
      },
      policyName: policyName(policy),
      policyKind: policyKind(policy.type),
    });
  }
  return [...byId.values()].filter(
    (statement): statement is PreparedStatement => statement !== null
  );
}

// Principals whose identity policies allow reading the secret. An
// unconditional matching Deny removes the principal; a conditional one leaves
// it flagged. Conditions, permission boundaries, SCPs and key policies are not
// evaluated. Broadest grants first.
export function readersFor(statements: PreparedStatements, arn: string): SecretReader[] {
  const byPrincipal = new Map<string, SecretReader & { denied: boolean }>();
  for (const statement of statements) {
    const scope = scopeFor(statement, arn);
    if (!scope) continue;
    for (const { principal, policyName: name, policyKind: kind } of statement.attachments) {
      const reader = byPrincipal.get(principal.id) ?? {
        ...principal,
        mayBeDenied: false,
        denied: false,
        grants: [],
      };
      if (statement.effect === 'Deny') {
        if (statement.conditional) reader.mayBeDenied = true;
        else reader.denied = true;
      } else {
        reader.grants.push({
          policyName: name,
          policyKind: kind,
          scope,
          notAction: statement.notAction,
          conditional: statement.conditional,
        });
      }
      byPrincipal.set(principal.id, reader);
    }
  }
  return [...byPrincipal.values()]
    .filter((reader) => !reader.denied && reader.grants.length > 0)
    .map(({ denied: _denied, ...reader }) => ({
      ...reader,
      grants: reader.grants.sort((a, b) => SCOPE_RANK[a.scope] - SCOPE_RANK[b.scope]),
    }))
    .sort(
      (a, b) =>
        SCOPE_RANK[a.grants[0].scope] - SCOPE_RANK[b.grants[0].scope] ||
        Number(b.admin) - Number(a.admin) ||
        a.name.localeCompare(b.name)
    );
}

// Broad: reaches the secret without naming it.
export function isBroadReader(reader: SecretReader): boolean {
  return reader.grants.some((grant) => isBroadGrant(grant.scope, grant.notAction));
}

function isBroadGrant(scope: ReaderScope, notAction: boolean): boolean {
  return scope === 'all' || scope === 'not-resource' || notAction;
}

// The same answer as readersFor, as counts only: no reader objects or sorting,
// so it stays cheap across every secret in an account.
export function countReaders(
  statements: PreparedStatements,
  arn: string
): { total: number; broad: number } {
  const allowed = new Map<string, boolean>();
  const denied = new Set<string>();
  for (const statement of statements) {
    const scope = scopeFor(statement, arn);
    if (!scope) continue;
    for (const { principal } of statement.attachments) {
      if (statement.effect === 'Deny') {
        if (!statement.conditional) denied.add(principal.id);
      } else {
        const broad = isBroadGrant(scope, statement.notAction);
        allowed.set(principal.id, (allowed.get(principal.id) ?? false) || broad);
      }
    }
  }
  let total = 0;
  let broad = 0;
  for (const [id, isBroad] of allowed) {
    if (denied.has(id)) continue;
    total += 1;
    if (isBroad) broad += 1;
  }
  return { total, broad };
}

export function secretReaders(
  rows: ReaderRow[],
  arn: string,
  cap: number
): { readers: SecretReader[]; truncated: boolean } {
  const readers = readersFor(prepareStatements(rows), arn);
  return { readers: readers.slice(0, cap), truncated: readers.length > cap };
}
