import type { EscalationPath } from './types';
import { ADMIN_ACTIONS, PRIVILEGE_ESCALATION_ACTIONS } from './types';
import { isActionMatched } from './policy-parser';

export interface TrustEdge {
  from: string;
  to: string;
  principalType: string;
  isCrossAccount: boolean;
  conditionsJson?: string;
}

export interface RoleWithPermissions {
  arn: string;
  allowedActions: string[];
  isAdmin: boolean;
}

export function detectEscalationPaths(
  trustEdges: TrustEdge[],
  rolesWithPermissions: RoleWithPermissions[],
  sourceAccount?: string,
  maxHops: number = 3
): EscalationPath[] {
  const paths: EscalationPath[] = [];
  const rolesByArn = new Map(rolesWithPermissions.map((r) => [r.arn, r]));

  const adjacency = new Map<string, TrustEdge[]>();
  for (const edge of trustEdges) {
    const list = adjacency.get(edge.from) || [];
    list.push(edge);
    adjacency.set(edge.from, list);
  }

  const adminRoles = rolesWithPermissions.filter((r) => r.isAdmin);
  for (const adminRole of adminRoles) {
    const reachableFrom = findPrincipalsThatCanReachRole(trustEdges, adminRole.arn, maxHops);
    for (const { source, pathEdges } of reachableFrom) {
      if (sourceAccount && !isSameAccount(source, sourceAccount)) continue;

      paths.push({
        id: `esc-path:${source}:${adminRole.arn}`,
        sourceArn: source,
        targetArn: adminRole.arn,
        path: pathEdges.map((e) => ({ from: e.from, to: e.to, edgeType: 'TRUSTS' })),
        pathLength: pathEdges.length,
        riskLevel: 'critical',
        escalationType: 'admin',
        conditions: pathEdges[0]?.conditionsJson ? JSON.parse(pathEdges[0].conditionsJson) : {},
        detectedAt: new Date().toISOString(),
      });
    }
  }

  for (const role of rolesWithPermissions) {
    if (role.isAdmin) continue;
    const hasEscalationActions = role.allowedActions.some((action) =>
      PRIVILEGE_ESCALATION_ACTIONS.some((pa) => isActionMatched(pa, action))
    );
    if (!hasEscalationActions) continue;

    const reachableFrom = findPrincipalsThatCanReachRole(trustEdges, role.arn, maxHops);
    for (const { source, pathEdges } of reachableFrom) {
      if (sourceAccount && !isSameAccount(source, sourceAccount)) continue;

      paths.push({
        id: `esc-path:${source}:${role.arn}`,
        sourceArn: source,
        targetArn: role.arn,
        path: pathEdges.map((e) => ({ from: e.from, to: e.to, edgeType: 'TRUSTS' })),
        pathLength: pathEdges.length,
        riskLevel: 'high',
        escalationType: 'privilege_escalation',
        conditions: pathEdges[0]?.conditionsJson ? JSON.parse(pathEdges[0].conditionsJson) : {},
        detectedAt: new Date().toISOString(),
      });
    }
  }

  return deduplicatePaths(paths);
}

function findPrincipalsThatCanReachRole(
  trustEdges: TrustEdge[],
  targetRoleArn: string,
  maxHops: number
): { source: string; pathEdges: TrustEdge[] }[] {
  const results: { source: string; pathEdges: TrustEdge[] }[] = [];
  const visited = new Set<string>();

  function dfs(current: string, path: TrustEdge[], depth: number) {
    if (depth > maxHops) return;
    if (visited.has(current)) return;
    visited.add(current);

    const edgesLeadingTo = trustEdges.filter((e) => e.to === current);
    for (const edge of edgesLeadingTo) {
      results.push({ source: edge.from, pathEdges: [...path, edge] });
      dfs(edge.from, [...path, edge], depth + 1);
    }
  }

  dfs(targetRoleArn, [], 1);
  return results;
}

function isSameAccount(arn: string, accountId: string): boolean {
  const match = arn.match(/^arn:aws:iam::(\d+)/);
  if (match) return match[1] === accountId;
  return true;
}

function deduplicatePaths(paths: EscalationPath[]): EscalationPath[] {
  const seen = new Set<string>();
  return paths.filter((p) => {
    const key = `${p.sourceArn}:${p.targetArn}:${p.escalationType}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function detectLateralMovement(
  trustEdges: TrustEdge[],
  rolesWithPermissions: RoleWithPermissions[],
  maxHops: number = 3
): EscalationPath[] {
  const paths: EscalationPath[] = [];
  const crossAccountTrusts = trustEdges.filter((e) => e.isCrossAccount);

  for (const trustEdge of crossAccountTrusts) {
    const targetRole = rolesWithPermissions.find((r) => r.arn === trustEdge.to);
    if (!targetRole) continue;

    const dataActions = targetRole.allowedActions.filter(
      (a) =>
        a.startsWith('s3:') ||
        a.startsWith('dynamodb:') ||
        a.startsWith('rds:') ||
        a.startsWith('kms:')
    );
    if (dataActions.length === 0) continue;

    paths.push({
      id: `esc-path:${trustEdge.from}:${trustEdge.to}:lateral`,
      sourceArn: trustEdge.from,
      targetArn: trustEdge.to,
      path: [{ from: trustEdge.from, to: trustEdge.to, edgeType: 'TRUSTS' }],
      pathLength: 1,
      riskLevel: 'medium',
      escalationType: 'lateral_movement',
      conditions: trustEdge.conditionsJson ? JSON.parse(trustEdge.conditionsJson) : {},
      detectedAt: new Date().toISOString(),
    });
  }

  return deduplicatePaths(paths);
}
