import Gremlin from 'gremlin';
import { effectivePermissionId, NeptuneRuntimeClient } from '@khalifa/risk-engine';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { Logger } from '../shared/types';
import { parseJsonArray } from '../shared/arrays';
import { generateRightsizingRecommendation, type UsedActionEntry } from '../shared/rightsizer';
import { enumerateGraph, toArray, type GraphSubmitter } from '../shared/graph-scan';
import { extractAccountId, extractPrincipalType, isServiceLinkedRole } from './arn';

const logger = new Logger('least-privilege-sweep');

// A traversal source used only to accumulate Bytecode; Amazon Neptune rejects
// Gremlin script bindings, so the reads are submitted as bytecode.
let bytecodeSource: Gremlin.process.GraphTraversalSource | null = null;
function graph(): Gremlin.process.GraphTraversalSource {
  bytecodeSource ??= new Gremlin.process.GraphTraversalSource(
    new Gremlin.structure.Graph(),
    new Gremlin.process.TraversalStrategies(),
    new Gremlin.process.Bytecode()
  );
  return bytecodeSource;
}

// Environment-dependent knobs are rebindable so the EKS runtime can pass the
// environment it was handed, instead of the module reading process.env at load
// time (which ignores an injected environment and looks wired while using the
// wrong table). The Lambda path relies on the module-load defaults below.
let findingsTable = process.env.LEAST_PRIVILEGE_TABLE || 'LeastPrivilegeFindings';
let accessAnalyzerTable = process.env.ACCESS_ANALYZER_TABLE || 'AccessAnalyzerCache';
let defaultSafetyMarginDays = parseInt(process.env.SAFETY_MARGIN_DAYS || '7', 10);

/** Rebinds the environment-dependent knobs. Table names and the margin only: the
 *  DynamoDB client is process-scoped and takes its region from the pod, as every
 *  other workload does. */
export function configure(environment: NodeJS.ProcessEnv = process.env): void {
  findingsTable = environment.LEAST_PRIVILEGE_TABLE || 'LeastPrivilegeFindings';
  accessAnalyzerTable = environment.ACCESS_ANALYZER_TABLE || 'AccessAnalyzerCache';
  defaultSafetyMarginDays = parseInt(environment.SAFETY_MARGIN_DAYS || '7', 10);
}

let gremlinClient: NeptuneRuntimeClient | null = null;

// SigV4, matching graph-writer and the rest of the graph access layer. The
// sweep previously used static password credentials from Secrets Manager; the
// execution role now carries neptune-db read permissions instead.
async function getGremlinClient(): Promise<GraphSubmitter> {
  if (!gremlinClient) {
    gremlinClient = new NeptuneRuntimeClient({
      endpoint: process.env.NEPTUNE_ENDPOINT || '',
      region: process.env.AWS_REGION,
    });
  }
  return gremlinClient;
}

const dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
const docClient = DynamoDBDocumentClient.from(dynamoClient);

interface SweepEvent {
  accountIds?: string[];
  safetyMarginDays?: number;
}

interface Principal {
  arn: string;
}

interface PolicyRef {
  policyArn: string;
  documentJson: string;
  policyType: string;
}

interface EffectivePermission {
  allowedActions: string[];
  isAdmin: boolean;
  blastRadius: number;
}

export interface SweepResult {
  principalsSwept: number;
  findingsWritten: number;
  highRiskCount: number;
  /** Principals skipped because their CloudTrail usage data was unavailable. */
  usageUnavailable: number;
}

export const handler = async (event: SweepEvent = {}): Promise<SweepResult> => {
  logger.info('Starting least-privilege sweep');
  const safetyMarginDays = event.safetyMarginDays || defaultSafetyMarginDays;

  let principalsSwept = 0;
  let findingsWritten = 0;
  let highRiskCount = 0;
  let usageUnavailable = 0;

  try {
    const client = await getGremlinClient();
    const principals = await fetchPrincipals(client);
    logger.info(`Found ${principals.length} principals`);

    for (const principal of principals) {
      if (isServiceLinkedRole(principal.arn)) continue;

      const accountId = extractAccountId(principal.arn);
      const principalType = extractPrincipalType(principal.arn);
      if (!accountId || principalType === 'unknown') continue;

      const policies = await fetchPoliciesForPrincipal(client, principal.arn);
      const rightsizablePolicies = policies.filter((p) => p.policyType !== 'aws-managed');
      if (rightsizablePolicies.length === 0) continue;

      const effectivePerm = await fetchEffectivePermission(client, principal.arn);
      if (!effectivePerm || effectivePerm.allowedActions.length === 0) continue;

      let usedActions: UsedActionEntry[];
      try {
        usedActions = await fetchUsedActions(principal.arn);
      } catch (error) {
        // Usage data is half of a rightsizing decision. Treating an
        // unavailable read as "no usage" recommended removing every action,
        // so skip the principal and surface the gap instead.
        usageUnavailable++;
        logger.warn(`Skipping ${principal.arn}: usage data unavailable`, {
          error: error instanceof Error ? error.message : String(error),
        });
        continue;
      }

      const recommendation = generateRightsizingRecommendation(
        principal.arn,
        effectivePerm.allowedActions,
        usedActions,
        rightsizablePolicies.map((p) => p.documentJson),
        { safetyMarginDays, includeReadonlySafe: true }
      );

      await writeFinding({
        accountId,
        principalArn: principal.arn,
        principalType,
        allowedActionCount: effectivePerm.allowedActions.length,
        removedActionCount: recommendation.removedActions.length,
        keptActionCount: recommendation.keptActions.length,
        removedActions: recommendation.removedActions,
        keptActions: recommendation.keptActions,
        recommendedPolicyJson: JSON.stringify(recommendation.recommendedPolicy),
        riskLevel: recommendation.riskLevel,
        confidence: recommendation.confidence,
        isAdmin: effectivePerm.isAdmin,
        blastRadius: effectivePerm.blastRadius,
      });

      principalsSwept++;
      findingsWritten++;
      if (recommendation.riskLevel === 'high') highRiskCount++;
    }

    if (usageUnavailable > 0) {
      logger.error(
        `Sweep completed with ${usageUnavailable} principal(s) skipped for unavailable usage data`,
        { principalsSwept, findingsWritten, highRiskCount, usageUnavailable }
      );
    } else {
      logger.info(
        `Sweep complete: ${principalsSwept} principals, ${findingsWritten} findings, ${highRiskCount} high-risk`
      );
    }
    return { principalsSwept, findingsWritten, highRiskCount, usageUnavailable };
  } catch (error) {
    logger.error(`Sweep failed: ${error}`);
    throw error;
  }
};

export async function fetchPrincipals(client: GraphSubmitter): Promise<Principal[]> {
  const arns = await enumerateGraph(
    client,
    (start, end) =>
      `g.V().hasLabel(within('IamUser', 'IamRole')).values('arn').range(${start}, ${end})`,
    { label: 'principals' }
  );
  return arns.map((arn) => ({ arn: String(arn) }));
}

export async function fetchPoliciesForPrincipal(
  client: GraphSubmitter,
  principalArn: string
): Promise<PolicyRef[]> {
  const results = await client.submit(
    graph()
      .V(principalArn)
      .out('ATTACHED_TO')
      .hasLabel('IamPolicyDocument')
      .project('policyArn', 'documentJson', 'policyType')
      .by('policy_arn')
      .by('document_json')
      .by('policy_type')
      .getBytecode()
  );
  return toArray(results).map((item: any) => ({
    policyArn: item.get('policyArn') || '',
    documentJson: item.get('documentJson') || '{}',
    policyType: item.get('policyType') || 'inline',
  }));
}

export async function fetchEffectivePermission(
  client: GraphSubmitter,
  principalArn: string
): Promise<EffectivePermission | null> {
  // Id step, not a property filter: the previous
  // `g.V().hasLabel('EffectivePermission').has('principal_arn', …)` scanned the
  // whole label once per principal.
  const results = await client.submit(
    graph()
      .V(effectivePermissionId(principalArn))
      .project('allowedActions', 'isAdmin', 'blastRadius')
      .by('allowed_actions')
      .by('is_admin')
      .by('blast_radius')
      .getBytecode()
  );
  const arr = toArray(results);
  if (arr.length === 0) return null;

  const item = arr[0] as { get(key: string): unknown };
  const allowedActionsRaw = item.get('allowedActions');
  const allowedActions = parseJsonArray(allowedActionsRaw);

  const blastRadius = item.get('blastRadius');
  return {
    allowedActions,
    isAdmin: item.get('isAdmin') === true,
    blastRadius: typeof blastRadius === 'number' ? blastRadius : 0,
  };
}

interface UsedActionSender {
  send(command: QueryCommand): Promise<{ Items?: Array<Record<string, unknown>> }>;
}

export async function fetchUsedActions(
  principalArn: string,
  sender: UsedActionSender = docClient
): Promise<UsedActionEntry[]> {
  // Errors propagate: the caller distinguishes "no usage recorded" (a valid
  // empty list) from "usage could not be read" (skip the principal).
  const result = await sender.send(
    new QueryCommand({
      TableName: accessAnalyzerTable,
      KeyConditionExpression: 'principalArn = :arn',
      ExpressionAttributeValues: {
        ':arn': { S: principalArn },
      },
    })
  );

  return (result.Items || []).map((item) => {
    const data = unmarshall(item as Record<string, never>) as {
      eventSource?: string;
      eventName?: string;
      lastUsed?: string;
      eventCount?: number;
    };
    return {
      principalArn,
      eventSource: data.eventSource || '',
      eventName: data.eventName || '',
      lastUsed: data.lastUsed || '',
      eventCount: data.eventCount || 0,
    };
  });
}

interface Finding {
  accountId: string;
  principalArn: string;
  principalType: string;
  allowedActionCount: number;
  removedActionCount: number;
  keptActionCount: number;
  removedActions: string[];
  keptActions: string[];
  recommendedPolicyJson: string;
  riskLevel: string;
  confidence: number;
  isAdmin: boolean;
  blastRadius: number;
}

async function writeFinding(finding: Finding): Promise<void> {
  const item = {
    accountId: finding.accountId,
    principalArn: finding.principalArn,
    principalType: finding.principalType,
    allowedActionCount: finding.allowedActionCount,
    removedActionCount: finding.removedActionCount,
    keptActionCount: finding.keptActionCount,
    removedActions: finding.removedActions,
    keptActions: finding.keptActions,
    recommendedPolicyJson: finding.recommendedPolicyJson,
    riskLevel: finding.riskLevel,
    confidence: finding.confidence,
    isAdmin: finding.isAdmin,
    blastRadius: finding.blastRadius,
    lastSweptAt: new Date().toISOString(),
  };

  await docClient.send(
    new PutCommand({
      TableName: findingsTable,
      Item: item,
    })
  );
}

/** EKS-runtime entrypoint. Shares the Lambda handler so both paths run one
 *  implementation, with the environment injected rather than read at load. */
export async function runLeastPrivilegeSweep(
  event: SweepEvent = {},
  environment: NodeJS.ProcessEnv = process.env
): Promise<SweepResult> {
  configure(environment);
  try {
    return await handler(event);
  } finally {
    // The EKS runtime is one-shot: close the SigV4 WebSocket or the CronJob pod
    // never exits. The Lambda path calls `handler` directly and reuses it.
    const open = gremlinClient;
    gremlinClient = null;
    if (open) await open.close();
  }
}
