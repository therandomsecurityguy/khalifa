import {
  IAMClient,
  ListRolesCommand,
  GetRolePolicyCommand,
  ListRolePoliciesCommand,
  ListAttachedRolePoliciesCommand,
} from '@aws-sdk/client-iam';
import type { GraphNode, GraphEdge } from '../../shared/types';
import type { TagMap } from './tags';
import { extractCommonProperties } from './tags';

const EXTERNAL_ACCOUNT_NODE_PREFIX = 'arn:aws:khalifa:external-account:';

function isCrossAccountPrincipal(principal: unknown): string | null {
  if (!principal || typeof principal !== 'object') return null;
  const obj = principal as Record<string, unknown>;
  const aws = obj.AWS;
  if (!aws) return null;

  const values = Array.isArray(aws) ? aws : [aws];
  for (const v of values) {
    if (typeof v !== 'string') continue;
    const match = v.match(/^arn:aws:iam::(\d{12}):/);
    if (match && match[1]) {
      return match[1];
    }
  }
  return null;
}

function extractTrustAccountIds(trustPolicy: string | undefined): string[] {
  if (!trustPolicy) return [];
  try {
    const parsed = JSON.parse(trustPolicy);
    const statements = Array.isArray(parsed.Statement) ? parsed.Statement : [parsed.Statement];
    const accountIds = new Set<string>();
    for (const stmt of statements || []) {
      if (!stmt || stmt.Effect !== 'Allow') continue;
      const principal = stmt.Principal;
      if (!principal) continue;
      const id = isCrossAccountPrincipal(principal);
      if (id) accountIds.add(id);
    }
    return Array.from(accountIds);
  } catch {
    return [];
  }
}

export async function collectCrossAccountTrust(
  client: IAMClient,
  accountId: string,
  tagsByArn: Map<string, TagMap>
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seenAccounts = new Set<string>();

  const rolesResponse = await client.send(new ListRolesCommand({ MaxItems: 1000 }));

  for (const role of rolesResponse.Roles || []) {
    if (!role.RoleName || !role.Arn) continue;
    const trustAccountIds = extractTrustAccountIds(role.AssumeRolePolicyDocument);

    const isAdminRole = await checkIsAdminRole(client, role.RoleName);

    for (const trustedAccount of trustAccountIds) {
      if (seenAccounts.has(trustedAccount)) continue;
      seenAccounts.add(trustedAccount);

      const externalArn = `${EXTERNAL_ACCOUNT_NODE_PREFIX}${trustedAccount}`;
      nodes.push({
        id: externalArn,
        label: 'ExternalAccount',
        properties: {
          id: trustedAccount,
          arn: externalArn,
          account_id: trustedAccount,
          name: `Account ${trustedAccount}`,
        },
      });
    }

    if (trustAccountIds.length > 0) {
      const tags = tagsByArn.get(role.Arn);
      const tagProps = extractCommonProperties(tags);

      nodes.push({
        id: role.Arn,
        label: 'IamRole',
        properties: {
          id: role.RoleName,
          arn: role.Arn,
          account_id: accountId,
          path: role.Path,
          create_date: role.CreateDate?.toISOString(),
          has_cross_account_trust: true,
          is_admin_role: isAdminRole,
          ...tagProps,
        },
      });

      for (const trustedAccount of trustAccountIds) {
        const externalArn = `${EXTERNAL_ACCOUNT_NODE_PREFIX}${trustedAccount}`;
        edges.push({ from: role.Arn, to: externalArn, label: 'TRUSTS' });
      }
    }
  }

  return { nodes, edges };
}

async function checkIsAdminRole(client: IAMClient, roleName: string): Promise<boolean> {
  try {
    const policies = await client.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName }));

    for (const policy of policies.AttachedPolicies || []) {
      if (!policy.PolicyArn) continue;
      if (policy.PolicyArn.includes('AdministratorAccess')) return true;
      if (policy.PolicyName?.toLowerCase().includes('admin')) return true;
    }

    const inlinePolicies = await client.send(new ListRolePoliciesCommand({ RoleName: roleName }));
    for (const name of inlinePolicies.PolicyNames || []) {
      try {
        const policy = await client.send(
          new GetRolePolicyCommand({ RoleName: roleName, PolicyName: name })
        );
        if (
          policy.PolicyDocument?.includes('"Action": "*"') ||
          policy.PolicyDocument?.includes('"Action":"*"')
        ) {
          return true;
        }
      } catch (e) {}
    }
  } catch (e) {}

  return false;
}
