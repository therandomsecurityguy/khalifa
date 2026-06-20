import type { Request, Response } from 'express';
import { NeptuneClient } from '../services/neptune-client';
import type { NeptuneRawVertex } from '../services/neptune-client';
import {
  DynamoDBClient,
  QueryCommand,
} from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import type {
  EffectivePermissionsResponse,
  EscalationPathsResponse,
  UnusedPermissionsResponse,
  RightsizingResponse,
  TrustGraphResponse,
  EscalationPath,
  ConditionalGrant,
  ServiceActions,
  IamPolicyStatement,
  IamConditionBlock,
} from '../types';

const neptuneEndpoint = process.env.NEPTUNE_ENDPOINT || '';
const neptuneClient = new NeptuneClient({ endpoint: neptuneEndpoint });
const dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const accessAnalyzerTable = process.env.ACCESS_ANALYZER_TABLE || 'AccessAnalyzerCache';

export async function getEffectivePermissions(req: Request, res: Response): Promise<void> {
  try {
    const { principal } = req.params;
    if (!principal) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'principal is required' });
      return;
    }

    await neptuneClient.connect();
    const perm = await neptuneClient.getEffectivePermissions(principal);

    if (!perm) {
      res.status(404).json({ code: 'NOT_FOUND', message: `No effective permissions found for: ${principal}` });
      return;
    }

    const response: EffectivePermissionsResponse = {
      principal: perm.principal_arn as string || principal,
      allowedActions: parseJsonArray(perm.allowed_actions as string),
      deniedActions: parseJsonArray(perm.denied_actions as string),
      conditionalGrants: parseConditionalGrants(perm.conditional_grants as string),
      policiesEvaluated: parseJsonArray(perm.policies_evaluated as string),
      isAdmin: perm.is_admin as boolean || false,
      blastRadius: perm.blast_radius as number || 0,
      evaluatedAt: perm.evaluated_at as string || '',
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting effective permissions:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get effective permissions' });
  }
}

export async function getEscalationPaths(req: Request, res: Response): Promise<void> {
  try {
    const { sourceAccount, targetRole, escalationType, riskLevel } = req.query;

    await neptuneClient.connect();
    const paths = await neptuneClient.getEscalationPaths({
      sourceAccount: sourceAccount as string | undefined,
      targetRole: targetRole as string | undefined,
      escalationType: escalationType as string | undefined,
      riskLevel: riskLevel as string | undefined,
    });

    const escalationPaths: EscalationPath[] = paths.map((p, index) => ({
      id: p.id as string || `esc-${index}`,
      sourceArn: p.source_arn as string || '',
      targetArn: p.target_arn as string || '',
      path: [],
      pathLength: p.path_length as number || 0,
      riskLevel: p.risk_level as 'critical' | 'high' | 'medium' | 'low' || 'medium',
      escalationType: p.escalation_type as 'admin' | 'privilege_escalation' | 'lateral_movement' || 'privilege_escalation',
      conditions: parseConditionBlock(p.conditions_json as string),
      detectedAt: p.detected_at as string || '',
    }));

    const response: EscalationPathsResponse = {
      paths: escalationPaths,
      total: escalationPaths.length,
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting escalation paths:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get escalation paths' });
  }
}

export async function getUnusedPermissions(req: Request, res: Response): Promise<void> {
  try {
    const { principal } = req.query;
    const days = parseInt(req.query.days as string || '90', 10);

    if (!principal) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'principal query parameter is required' });
      return;
    }

    await neptuneClient.connect();
    const perm = await neptuneClient.getEffectivePermissions(principal as string);

    const usedActions = await fetchUsedActionsFromDynamo(principal as string);

    const allowedActions = perm ? parseJsonArray(perm.allowed_actions as string) : [];
    const unusedByService = groupActionsByService(allowedActions, usedActions);

    const usedByService = groupUsedActionsByService(usedActions);

    const response: UnusedPermissionsResponse = {
      principalArn: principal as string,
      unusedActions: unusedByService,
      usedActions: usedByService,
      lastAnalyzed: perm?.evaluated_at as string || new Date().toISOString(),
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting unused permissions:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get unused permissions' });
  }
}

export async function getRightsizingRecommendation(req: Request, res: Response): Promise<void> {
  try {
    const { principal } = req.params;

    if (!principal) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'principal is required' });
      return;
    }

    await neptuneClient.connect();
    const perm = await neptuneClient.getEffectivePermissions(principal);

    if (!perm) {
      res.status(404).json({ code: 'NOT_FOUND', message: `No effective permissions found for: ${principal}` });
      return;
    }

    const allowedActions = parseJsonArray(perm.allowed_actions as string);
    const usedActions = await fetchUsedActionsFromDynamo(principal);

    const usedActionEntries = usedActions.map((a) => ({
      principalArn: principal,
      eventSource: a.service,
      eventName: a.eventName,
      lastUsed: new Date().toISOString(),
      eventCount: 1,
    }));

    const currentPolicy: IamPolicyStatement[] = [{
      sid: 'current',
      effect: 'Allow',
      actions: allowedActions,
      resources: ['*'],
    }];

    const keptActions = computeKeptActions(allowedActions, usedActions);
    const removedActions = allowedActions.filter((a) => !keptActions.includes(a));

    const removalRatio = allowedActions.length > 0 ? removedActions.length / allowedActions.length : 0;

    const response: RightsizingResponse = {
      principalArn: principal,
      currentPolicy,
      recommendedPolicy: [{
        sid: 'rightsized',
        effect: 'Allow',
        actions: keptActions.length > 0 ? keptActions : ['*'],
        resources: ['*'],
      }],
      removedActions,
      keptActions,
      riskLevel: removalRatio > 0.5 ? 'high' : removalRatio > 0.2 ? 'medium' : 'low',
      confidence: usedActions.length > 0 ? Math.min(1, usedActions.length / 50) : 0,
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting rightsizing recommendation:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get rightsizing recommendation' });
  }
}

export async function getTrustGraph(req: Request, res: Response): Promise<void> {
  try {
    const { account } = req.query;

    await neptuneClient.connect();
    const result = await neptuneClient.getTrustGraph(account as string | undefined);

    const response: TrustGraphResponse = {
      nodes: result.nodes,
      edges: result.edges,
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting trust graph:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get trust graph' });
  }
}

function parseJsonArray(jsonStr: string | undefined): string[] {
  if (!jsonStr) return [];
  if (Array.isArray(jsonStr)) return jsonStr;
  try {
    return JSON.parse(jsonStr);
  } catch {
    return [];
  }
}

function parseConditionalGrants(jsonStr: string | undefined): ConditionalGrant[] {
  if (!jsonStr) return [];
  try {
    return JSON.parse(jsonStr);
  } catch {
    return [];
  }
}

function parseConditionBlock(jsonStr: string | undefined): IamConditionBlock {
  if (!jsonStr) return {};
  try {
    return JSON.parse(jsonStr);
  } catch {
    return {};
  }
}

interface UsedAction {
  service: string;
  eventName: string;
  lastUsed: string;
}

async function fetchUsedActionsFromDynamo(principalArn: string): Promise<UsedAction[]> {
  try {
    const result = await docClient.send(
      new QueryCommand({
        TableName: accessAnalyzerTable,
        KeyConditionExpression: 'principalArn = :arn',
        ExpressionAttributeValues: {
          ':arn': { S: principalArn },
        },
      })
    );

    return (result.Items || []).map((item) => ({
      service: (unmarshall(item) as any).eventSource || '',
      eventName: (unmarshall(item) as any).eventName || '',
      lastUsed: (unmarshall(item) as any).lastUsed || '',
    }));
  } catch {
    return [];
  }
}

function groupActionsByService(allowedActions: string[], usedActions: UsedAction[]): ServiceActions[] {
  const usedSet = new Set<string>();
  for (const ua of usedActions) {
    usedSet.add(`${ua.service}:${ua.eventName}`);
  }

  const byService = new Map<string, string[]>();
  for (const action of allowedActions) {
    let isUsed = false;
    for (const used of usedSet) {
      if (actionMatch(action, used)) {
        isUsed = true;
        break;
      }
    }
    if (!isUsed) {
      const [service, ...rest] = action.split(':');
      const list = byService.get(service) || [];
      list.push(rest.join(':'));
      byService.set(service, list);
    }
  }

  return [...byService.entries()].map(([service, actions]) => ({ service, actions }));
}

function groupUsedActionsByService(usedActions: UsedAction[]): ServiceActions[] {
  const byService = new Map<string, string[]>();
  for (const ua of usedActions) {
    const list = byService.get(ua.service) || [];
    if (!list.includes(ua.eventName)) list.push(ua.eventName);
    byService.set(ua.service, list);
  }
  return [...byService.entries()].map(([service, actions]) => ({ service, actions }));
}

function computeKeptActions(allowedActions: string[], usedActions: UsedAction[]): string[] {
  const usedSet = new Set<string>();
  for (const ua of usedActions) {
    usedSet.add(`${ua.service}:${ua.eventName}`);
  }

  return allowedActions.filter((action) => {
    for (const used of usedSet) {
      if (actionMatch(action, used)) return true;
    }
    if (isReadOnlyAction(action)) return true;
    return false;
  });
}

function actionMatch(pattern: string, action: string): boolean {
  if (pattern === '*' || pattern === '*:*') return true;
  const regexStr = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${regexStr}$`, 'i').test(action);
}

function isReadOnlyAction(action: string): boolean {
  return /^.*:Get[A-Z]/.test(action) || /^.*:List[A-Z]/.test(action) || /^.*:Describe[A-Z]/.test(action);
}