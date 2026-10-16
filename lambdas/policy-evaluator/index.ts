import Gremlin from 'gremlin';
import { effectivePermissionId, NeptuneRuntimeClient } from '@khalifa/risk-engine';
import { Logger } from '../shared/types';
import { parseJsonArray } from '../shared/arrays';
import { enumerateGraph, toArray, type GraphSubmitter } from '../shared/graph-scan';
import { resolveEffectivePermissions } from './effect-resolver';
import type { EffectivePermission, EscalationPath } from './types';
import { detectEscalationPaths, detectLateralMovement } from './escalation-detector';
import type { TrustEdge, RoleWithPermissions } from './escalation-detector';

const { single } = Gremlin.process.cardinality;
const { t, P } = Gremlin.process;
const __ = Gremlin.process.statics;

// A traversal source is only used to accumulate Bytecode; it is never
// connected to a graph. Amazon Neptune rejects Gremlin script bindings, so
// every CIEM query is submitted as bytecode rather than a parameterized script.
let bytecodeSource: Gremlin.process.GraphTraversalSource | null = null;
function graph(): Gremlin.process.GraphTraversalSource {
  bytecodeSource ??= new Gremlin.process.GraphTraversalSource(
    new Gremlin.structure.Graph(),
    new Gremlin.process.TraversalStrategies(),
    new Gremlin.process.Bytecode()
  );
  return bytecodeSource;
}

const logger = new Logger('policy-evaluator');
let client: NeptuneRuntimeClient | null = null;
// Injectable so the runtime command can pass its environment; the Lambda path
// leaves this as process.env.
let runtimeEnvironment: NodeJS.ProcessEnv = process.env;

// SigV4, matching graph-writer and the rest of the graph access layer. The
// function previously used static password credentials from Secrets Manager,
// so it needed a secret read for every evaluation; the execution role now
// carries neptune-db permissions instead.
async function getClient(): Promise<GraphSubmitter> {
  if (!client) {
    client = new NeptuneRuntimeClient({
      endpoint: runtimeEnvironment.NEPTUNE_ENDPOINT || '',
      region: runtimeEnvironment.AWS_REGION,
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
  const runStartedAt = new Date().toISOString();
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
      if (path.escalationType !== 'lateral_movement') {
        await writeEscalationEdge(gremlinClient, path);
      }
      escalationPaths++;
    }
    await dropStaleEscalations(gremlinClient, runStartedAt);

    logger.info(
      `Policy evaluation complete: ${permissionsEvaluated} principals, ${escalationPaths} escalation paths`
    );
    return { permissionsEvaluated, escalationPaths };
  } catch (error) {
    logger.error(`Policy evaluation failed: ${error}`);
    throw error;
  }
};

export async function fetchPrincipals(gremlinClient: GraphSubmitter): Promise<{ arn: string }[]> {
  // Bounded pages instead of one unbounded submit: a large organization
  // materialized every principal at once, which OOMs the evaluator.
  const arns = await enumerateGraph(
    gremlinClient,
    (start, end) =>
      `g.V().hasLabel(within('IamUser', 'IamRole')).values('arn').range(${start}, ${end})`,
    { label: 'principals' }
  );
  return arns.map((arn) => ({ arn: String(arn) }));
}

export async function fetchPoliciesForPrincipal(
  gremlinClient: GraphSubmitter,
  principalArn: string
): Promise<{ policyArn: string; documentJson: string }[]> {
  const results = await gremlinClient.submit(
    graph()
      .V(principalArn)
      .out('ATTACHED_TO')
      // Managed policies sit one hop further: principal -> IamPolicy -> document.
      .optional(__.out('CONTAINS').hasLabel('IamPolicyDocument'))
      .hasLabel('IamPolicyDocument')
      .project('policyArn', 'documentJson')
      .by('policy_arn')
      .by('document_json')
      .getBytecode()
  );
  return toArray(results).map((item: any) => ({
    policyArn: item.get('policyArn') || '',
    documentJson: item.get('documentJson') || '{}',
  }));
}

export async function fetchTrustEdges(gremlinClient: GraphSubmitter): Promise<TrustEdge[]> {
  // Endpoints come from the edge itself. The previous `by('from_label')` /
  // `by('to_label')` read properties no writer ever sets, so every trust edge
  // arrived with empty endpoints and escalation detection could never match.
  const rows = await enumerateGraph(
    gremlinClient,
    (start, end) => `
      g.E().hasLabel('TRUSTS')
        .project('from', 'to', 'principalType', 'isCrossAccount', 'conditionsJson')
          .by(outV().id())
          .by(inV().id())
          .by('principal_type')
          .by('is_cross_account')
          .by('conditions_json')
        .range(${start}, ${end})
    `,
    { label: 'trust-edges' }
  );
  // No error swallowing: an empty trust-edge list previously reported as
  // "no escalation paths", which is indistinguishable from a healthy graph.
  // A failed read now fails the run so the schedule and alarms see it.
  return rows.map((row) => {
    const item = row as { get(key: string): unknown };
    return {
      from: String(item.get('from') || ''),
      to: String(item.get('to') || ''),
      principalType: String(item.get('principalType') || 'AWS'),
      isCrossAccount: item.get('isCrossAccount') === true,
      conditionsJson: (item.get('conditionsJson') as string) || undefined,
    };
  });
}

export async function fetchRolesWithPermissions(
  gremlinClient: GraphSubmitter
): Promise<RoleWithPermissions[]> {
  // `allowed_actions` is a serialized JSON array per principal; materializing
  // every row in one response is the other OOM path.
  const rows = await enumerateGraph(
    gremlinClient,
    (start, end) => `
      g.V().hasLabel('EffectivePermission')
        .project('arn', 'allowedActions', 'isAdmin')
          .by('principal_arn')
          .by('allowed_actions')
          .by('is_admin')
        .range(${start}, ${end})
    `,
    { label: 'effective-permissions' }
  );
  // Swallowing this read as an empty list silently disabled escalation
  // detection; propagate so a partial evaluation fails loudly.
  return rows.map((row) => {
    const item = row as { get(key: string): unknown };
    return {
      arn: String(item.get('arn') || ''),
      // `allowed_actions` comes back as the serialized JSON string the writer
      // stored; escalation detection calls `.some`/`.filter` on it, so a raw
      // string would throw.
      allowedActions: parseJsonArray(item.get('allowedActions')),
      isAdmin: item.get('isAdmin') === true,
    };
  });
}

export async function writeEffectivePermission(
  gremlinClient: GraphSubmitter,
  perm: EffectivePermission
): Promise<void> {
  const actionsJson = JSON.stringify(perm.allowedActions);
  const deniedJson = JSON.stringify(perm.deniedActions);
  const policiesJson = JSON.stringify(perm.policiesEvaluated);
  const conditionalJson = JSON.stringify(perm.conditionalGrants);
  const id = effectivePermissionId(perm.principalArn);

  const refresh = __.unfold()
    .property(single, 'allowed_actions', actionsJson)
    .property(single, 'denied_actions', deniedJson)
    .property(single, 'conditional_grants', conditionalJson)
    .property(single, 'is_admin', perm.isAdmin)
    .property(single, 'blast_radius', perm.blastRadius)
    .property(single, 'evaluated_at', perm.evaluatedAt)
    .property(single, 'policies_evaluated', policiesJson);

  // T.id, not a plain `id` property: the element id is what the next run
  // looks up, so the create branch must pin it or the principal is added again.
  const create = __.addV('EffectivePermission')
    .property(t.id, id)
    .property(single, 'id', id)
    .property(single, 'arn', perm.id)
    .property(single, 'principal_arn', perm.principalArn)
    .property(single, 'allowed_actions', actionsJson)
    .property(single, 'denied_actions', deniedJson)
    .property(single, 'conditional_grants', conditionalJson)
    .property(single, 'is_admin', perm.isAdmin)
    .property(single, 'blast_radius', perm.blastRadius)
    .property(single, 'evaluated_at', perm.evaluatedAt)
    .property(single, 'policies_evaluated', policiesJson);

  // The principal carries is_admin too, so rules, scoring and the attack-path
  // admin target can read it from the role or user itself.
  await gremlinClient.submit(
    graph()
      .V(id)
      .fold()
      .coalesce(refresh, create)
      .V(perm.principalArn)
      .property(single, 'is_admin', perm.isAdmin)
      .getBytecode()
  );
}

export async function writeEscalationPath(
  gremlinClient: GraphSubmitter,
  path: EscalationPath
): Promise<void> {
  const conditionsJson = JSON.stringify(path.conditions);

  const refresh = __.unfold()
    .property(single, 'source_arn', path.sourceArn)
    .property(single, 'target_arn', path.targetArn)
    .property(single, 'path_length', path.pathLength)
    .property(single, 'risk_level', path.riskLevel)
    .property(single, 'escalation_type', path.escalationType)
    .property(single, 'conditions_json', conditionsJson)
    .property(single, 'detected_at', path.detectedAt);

  // Id step, not a label scan: the create branch pins T.id, so a re-run
  // refreshes the vertex instead of adding a second one.
  const create = __.addV('EscalationPath')
    .property(t.id, path.id)
    .property(single, 'id', path.id)
    .property(single, 'arn', path.id)
    .property(single, 'source_arn', path.sourceArn)
    .property(single, 'target_arn', path.targetArn)
    .property(single, 'path_length', path.pathLength)
    .property(single, 'risk_level', path.riskLevel)
    .property(single, 'escalation_type', path.escalationType)
    .property(single, 'conditions_json', conditionsJson)
    .property(single, 'detected_at', path.detectedAt);

  await gremlinClient.submit(graph().V(path.id).fold().coalesce(refresh, create).getBytecode());
}

// Links the source principal to the role it can reach so rules can match the
// path. Lateral movement stays on the EscalationPath vertex only.
export async function writeEscalationEdge(
  gremlinClient: GraphSubmitter,
  path: EscalationPath
): Promise<void> {
  const id = `can-escalate:${path.sourceArn}:${path.targetArn}`;
  const props = (traversal: Gremlin.process.GraphTraversal) =>
    traversal
      .property('risk_level', path.riskLevel)
      .property('escalation_type', path.escalationType)
      .property('path_length', path.pathLength)
      .property('detected_at', path.detectedAt);

  await gremlinClient.submit(
    graph()
      .E(id)
      .fold()
      .coalesce(
        props(__.unfold()),
        props(
          __.V(path.sourceArn)
            .as('source')
            .V(path.targetArn)
            .addE('CAN_ESCALATE_TO')
            .from_('source')
            .property(t.id, id)
        )
      )
      .getBytecode()
  );
}

// Removes paths and links this run did not re-detect, so their issues resolve.
// Only called after a complete run; a failed run throws before reaching it.
export async function dropStaleEscalations(
  gremlinClient: GraphSubmitter,
  runStartedAt: string
): Promise<void> {
  // not(gte) rather than lt, so an element missing detected_at is stale too.
  const fresh = () => __.has('detected_at', P.gte(runStartedAt));
  await gremlinClient.submit(
    graph().V().hasLabel('EscalationPath').not(fresh()).drop().getBytecode()
  );
  await gremlinClient.submit(
    graph().E().hasLabel('CAN_ESCALATE_TO').not(fresh()).drop().getBytecode()
  );
}

/** EKS-runtime entrypoint. Shares the Lambda handler so both paths run one
 *  implementation, with the environment injected rather than read at load. */
export async function runPolicyEvaluation(
  event: EvaluatorEvent = {},
  environment: NodeJS.ProcessEnv = process.env
): Promise<{ permissionsEvaluated: number; escalationPaths: number }> {
  runtimeEnvironment = environment;
  try {
    return await handler(event);
  } finally {
    // The EKS runtime is one-shot: the SigV4 WebSocket is the handle keeping
    // the process alive, so close it or the CronJob pod never exits. The Lambda
    // path calls `handler` directly, where the connection is deliberately reused.
    const open = client;
    client = null;
    if (open) await open.close();
  }
}
