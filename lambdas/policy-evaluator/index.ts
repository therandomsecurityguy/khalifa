import Gremlin from 'gremlin';
import type { GraphNode, GraphEdge } from '../shared/types';
import { Logger } from '../shared/types';
import { getSecret } from '../shared/secrets-client';
import { parsePolicyDocument } from './policy-parser';
import { resolveEffectivePermissions } from './effect-resolver';
import type { EffectivePermission, EscalationPath } from './types';
import { detectEscalationPaths, detectLateralMovement } from './escalation-detector';
import type { TrustEdge, RoleWithPermissions } from './escalation-detector';

const logger = new Logger('policy-evaluator');
let client: Gremlin.driver.Client | null = null;

async function getClient(): Promise<Gremlin.driver.Client> {
  if (!client) {
    const endpoint = process.env.NEPTUNE_ENDPOINT || '';
    const secretArn = process.env.NEPTUNE_AUTH_SECRET_ARN || '';
    let credentials = {};
    if (secretArn) {
      const secret = await getSecret(secretArn);
      credentials = { username: secret.username, password: secret.password };
    }
    client = new Gremlin.driver.Client(`wss://${endpoint}:8182/gremlin`, {
      traversalSource: 'g',
      connectTimeout: 30000,
      messageMaxChunkSize: 65536,
      ...credentials,
    });
  }
  return client;
}

interface EvaluatorEvent {
  accountIds?: string[];
  maxEscalationHops?: number;
}

export const handler = async (
  event: EvaluatorEvent = {}
): Promise<{ permissionsEvaluated: number; escalationPaths: number }> => {
  logger.info('Starting policy evaluation');
  const maxHops = event.maxEscalationHops || 3;
  let permissionsEvaluated = 0;
  let escalationPaths = 0;

  try {
    const gremlinClient = await getClient();

    const principals = await fetchPrincipals(gremlinClient);
    logger.info(`Found ${principals.length} principals`);

    for (const principal of principals) {
      const policies = await fetchPoliciesForPrincipal(gremlinClient, principal.arn);
      const effectivePerm = resolveEffectivePermissions({
        principalArn: principal.arn,
        identityPolicies: policies.map((p) => ({
          policyDocumentJson: p.documentJson,
          policyArn: p.policyArn,
        })),
      });

      await writeEffectivePermission(gremlinClient, effectivePerm);
      permissionsEvaluated++;
    }

    const trustEdges = await fetchTrustEdges(gremlinClient);
    const rolesWithPerms = await fetchRolesWithPermissions(gremlinClient);

    const adminEscPaths = detectEscalationPaths(trustEdges, rolesWithPerms, undefined, maxHops);
    const lateralPaths = detectLateralMovement(trustEdges, rolesWithPerms, maxHops);
    const allPaths = [...adminEscPaths, ...lateralPaths];

    for (const path of allPaths) {
      await writeEscalationPath(gremlinClient, path);
      escalationPaths++;
    }

    logger.info(
      `Policy evaluation complete: ${permissionsEvaluated} principals, ${escalationPaths} escalation paths`
    );
    return { permissionsEvaluated, escalationPaths };
  } catch (error) {
    logger.error(`Policy evaluation failed: ${error}`);
    throw error;
  }
};

async function fetchPrincipals(gremlinClient: Gremlin.driver.Client): Promise<{ arn: string }[]> {
  const query = `g.V().hasLabel(within('IamUser', 'IamRole')).values('arn')`;
  const results = await gremlinClient.submit(query);
  return results.toArray().map((arn: string) => ({ arn }));
}

async function fetchPoliciesForPrincipal(
  gremlinClient: Gremlin.driver.Client,
  principalArn: string
): Promise<{ policyArn: string; documentJson: string }[]> {
  const query = `
    g.V().has('arn', principalArn)
      .out('ATTACHED_TO').hasLabel('IamPolicyDocument')
      .project('policyArn', 'documentJson')
        .by('policy_arn')
        .by('document_json')
  `;
  const results = await gremlinClient.submit(query, { principalArn });
  return results.toArray().map((item: any) => ({
    policyArn: item.get('policyArn') || '',
    documentJson: item.get('documentJson') || '{}',
  }));
}

async function fetchTrustEdges(gremlinClient: Gremlin.driver.Client): Promise<TrustEdge[]> {
  const query = `
    g.E().hasLabel('TRUSTS')
      .project('from', 'to', 'principalType', 'isCrossAccount', 'conditionsJson')
        .by('from_label')
        .by('to_label')
        .by('principal_type')
        .by('is_cross_account')
        .by('conditions_json')
  `;
  try {
    const results = await gremlinClient.submit(query);
    return results.toArray().map((item: any) => ({
      from: item.get('from') || '',
      to: item.get('to') || '',
      principalType: item.get('principalType') || 'AWS',
      isCrossAccount: item.get('isCrossAccount') === true,
      conditionsJson: item.get('conditionsJson') || undefined,
    }));
  } catch (e) {
    return [];
  }
}

async function fetchRolesWithPermissions(
  gremlinClient: Gremlin.driver.Client
): Promise<RoleWithPermissions[]> {
  const query = `
    g.V().hasLabel('EffectivePermission')
      .project('arn', 'allowedActions', 'isAdmin')
        .by('principal_arn')
        .by('allowed_actions')
        .by('is_admin')
  `;
  try {
    const results = await gremlinClient.submit(query);
    return results.toArray().map((item: any) => ({
      arn: item.get('arn') || '',
      allowedActions: item.get('allowedActions') || [],
      isAdmin: item.get('isAdmin') === true,
    }));
  } catch (e) {
    return [];
  }
}

async function writeEffectivePermission(
  gremlinClient: Gremlin.driver.Client,
  perm: EffectivePermission
): Promise<void> {
  const actionsJson = JSON.stringify(perm.allowedActions);
  const deniedJson = JSON.stringify(perm.deniedActions);
  const policiesJson = JSON.stringify(perm.policiesEvaluated);

  const bindings = {
    id: perm.id,
    arn: perm.id,
    principal_arn: perm.principalArn,
    allowed_actions: actionsJson,
    denied_actions: deniedJson,
    is_admin: perm.isAdmin,
    blast_radius: perm.blastRadius,
    evaluated_at: perm.evaluatedAt,
    policies_evaluated: policiesJson,
  };

  const query =
    "g.V().has('EffectivePermission', 'principal_arn', principal_arn).fold()" +
    '.coalesce(unfold()' +
    ".property('allowed_actions', allowed_actions)" +
    ".property('denied_actions', denied_actions)" +
    ".property('is_admin', is_admin)" +
    ".property('blast_radius', blast_radius)" +
    ".property('evaluated_at', evaluated_at)" +
    ".property('policies_evaluated', policies_evaluated)" +
    ", addV('EffectivePermission')" +
    ".property('id', id)" +
    ".property('arn', arn)" +
    ".property('principal_arn', principal_arn)" +
    ".property('allowed_actions', allowed_actions)" +
    ".property('denied_actions', denied_actions)" +
    ".property('is_admin', is_admin)" +
    ".property('blast_radius', blast_radius)" +
    ".property('evaluated_at', evaluated_at)" +
    ".property('policies_evaluated', policies_evaluated)).next()";

  await gremlinClient.submit(query, bindings);
}

async function writeEscalationPath(
  gremlinClient: Gremlin.driver.Client,
  path: EscalationPath
): Promise<void> {
  const conditionsJson = JSON.stringify(path.conditions);

  const bindings = {
    id: path.id,
    arn: path.id,
    source_arn: path.sourceArn,
    target_arn: path.targetArn,
    path_length: path.pathLength,
    risk_level: path.riskLevel,
    escalation_type: path.escalationType,
    conditions_json: conditionsJson,
    detected_at: path.detectedAt,
  };

  const query =
    "g.V().has('EscalationPath', 'id', id).fold()" +
    '.coalesce(unfold()' +
    ".property('source_arn', source_arn)" +
    ".property('target_arn', target_arn)" +
    ".property('path_length', path_length)" +
    ".property('risk_level', risk_level)" +
    ".property('escalation_type', escalation_type)" +
    ".property('conditions_json', conditions_json)" +
    ".property('detected_at', detected_at)" +
    ", addV('EscalationPath')" +
    ".property('id', id)" +
    ".property('arn', arn)" +
    ".property('source_arn', source_arn)" +
    ".property('target_arn', target_arn)" +
    ".property('path_length', path_length)" +
    ".property('risk_level', risk_level)" +
    ".property('escalation_type', escalation_type)" +
    ".property('conditions_json', conditions_json)" +
    ".property('detected_at', detected_at)).next()";

  await gremlinClient.submit(query, bindings);
}
