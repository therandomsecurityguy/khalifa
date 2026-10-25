import { IAMClient, ListInstanceProfilesCommand } from '@aws-sdk/client-iam';
import { collectPaginated } from '../../shared/pagination';
import type { GraphEdge } from '../../shared/types';
import { roleVertexId } from './iam-ids';

export type InstanceProfileRoles = Map<string, string[]>;

// Undefined only on AccessDenied (member stack not yet redeployed). Other errors
// fail the stage so reconcile keeps the previous run's edges.
export async function listInstanceProfileRoles(
  client: IAMClient
): Promise<InstanceProfileRoles | undefined> {
  try {
    const profiles = await collectPaginated(
      (marker) => client.send(new ListInstanceProfilesCommand({ Marker: marker })),
      (page) => page.InstanceProfiles,
      (page) => (page.IsTruncated ? page.Marker : undefined)
    );
    const roles: InstanceProfileRoles = new Map();
    for (const profile of profiles) {
      if (!profile.Arn) continue;
      roles.set(
        profile.Arn,
        (profile.Roles || []).map((role) => role.RoleName).filter((name): name is string => !!name)
      );
    }
    return roles;
  } catch (error) {
    if (error instanceof Error && /^AccessDenied/.test(error.name)) return undefined;
    throw error;
  }
}

// Role vertex ids are role/<RoleName> without the path (roleVertexId).
export function instanceRoleEdges(
  instanceArn: string,
  profileArn: string,
  profileRoles: InstanceProfileRoles,
  accountId: string
): GraphEdge[] {
  return (profileRoles.get(profileArn) || []).map((roleName) => ({
    from: instanceArn,
    to: roleVertexId(accountId, roleName),
    label: 'HAS_IAM_ROLE',
  }));
}
