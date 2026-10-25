import {
  IAMClient,
  ListRolesCommand,
  GetRolePolicyCommand,
  ListRolePoliciesCommand,
  ListAttachedRolePoliciesCommand,
} from '@aws-sdk/client-iam';
import type { GraphNode, GraphEdge } from '../../shared/types';
import { collectPaginated } from '../../shared/pagination';
import type { TagMap } from './tags';
import { extractCommonProperties } from './tags';
import { roleVertexId } from './iam-ids';

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

function parsePolicyDocument(policyDocument: string): Record<string, unknown> {
  const document = policyDocument.trim().startsWith('{')
    ? policyDocument
    : decodeURIComponent(policyDocument);
  return JSON.parse(document) as Record<string, unknown>;
}

export function extractTrustAccountIds(trustPolicy: string | undefined): string[] {
  if (!trustPolicy) return [];
  const parsed = parsePolicyDocument(trustPolicy);
  const statements = Array.isArray(parsed.Statement) ? parsed.Statement : [parsed.Statement];
  const accountIds = new Set<string>();
  for (const statement of statements || []) {
    if (!statement || typeof statement !== 'object') continue;
    const item = statement as Record<string, unknown>;
    if (item.Effect !== 'Allow' || !item.Principal) continue;
    const id = isCrossAccountPrincipal(item.Principal);
    if (id) accountIds.add(id);
  }
  return [...accountIds];
}

export async function collectCrossAccountTrust(
  client: IAMClient,
  accountId: string,
  tagsByArn: Map<string, TagMap>
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seenAccounts = new Set<string>();

  const roles = await collectPaginated(
    (marker) => client.send(new ListRolesCommand({ MaxItems: 1000, Marker: marker })),
    (page) => page.Roles,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );
  for (const role of roles) {
    if (!role.RoleName || !role.Arn) continue;
    const trustAccountIds = extractTrustAccountIds(role.AssumeRolePolicyDocument);

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
          external_account_id: trustedAccount,
          name: `Account ${trustedAccount}`,
        },
      });
    }

    if (trustAccountIds.length > 0) {
      // Only roles with a cross-account trust get the (expensive) admin check;
      // it reads attached and inline policies and is only reported for roles
      // that carry a TRUSTS edge.
      const isAdminRole = await checkIsAdminRole(client, role.RoleName);
      const tags = tagsByArn.get(role.Arn);
      const tagProps = extractCommonProperties(tags);
      // The same vertex collectIam writes, so these properties merge onto it
      // instead of creating a second IamRole at the ARN with its path.
      const roleId = roleVertexId(accountId, role.Arn);

      nodes.push({
        id: roleId,
        label: 'IamRole',
        properties: {
          id: role.RoleName,
          arn: roleId,
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
        edges.push({ from: roleId, to: externalArn, label: 'TRUSTS' });
      }
    }
  }

  return { nodes, edges };
}

async function checkIsAdminRole(client: IAMClient, roleName: string): Promise<boolean> {
  const attachedPolicies = await collectPaginated(
    (marker) =>
      client.send(new ListAttachedRolePoliciesCommand({ RoleName: roleName, Marker: marker })),
    (page) => page.AttachedPolicies,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );
  for (const policy of attachedPolicies) {
    if (!policy.PolicyArn) continue;
    if (policy.PolicyArn.includes('AdministratorAccess')) return true;
    if (policy.PolicyName?.toLowerCase().includes('admin')) return true;
  }

  const inlinePolicies = await collectPaginated(
    (marker) => client.send(new ListRolePoliciesCommand({ RoleName: roleName, Marker: marker })),
    (page) => page.PolicyNames,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );
  for (const name of inlinePolicies) {
    const policy = await client.send(
      new GetRolePolicyCommand({ RoleName: roleName, PolicyName: name })
    );
    if (policy.PolicyDocument && grantsAllActions(parsePolicyDocument(policy.PolicyDocument))) {
      return true;
    }
  }

  return false;
}

function grantsAllActions(policy: Record<string, unknown>): boolean {
  const statements = Array.isArray(policy.Statement) ? policy.Statement : [policy.Statement];
  return statements.some((statement) => {
    if (!statement || typeof statement !== 'object') return false;
    const item = statement as Record<string, unknown>;
    const actions = Array.isArray(item.Action) ? item.Action : [item.Action];
    return item.Effect === 'Allow' && actions.includes('*');
  });
}
