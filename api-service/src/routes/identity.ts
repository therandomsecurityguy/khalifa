import type { Request, Response } from 'express';
import { DynamoDBClient, QueryCommand } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { parseBoundedInteger } from '../middleware/gremlin-validator';
import { getApiNeptuneClient } from '../services/api-dependencies';
import { LeastPrivilegeStore } from '../services/least-privilege-store';
import type {
  EffectivePermissionsResponse,
  EscalationPathsResponse,
  UnusedPermissionsResponse,
  RightsizingResponse,
  EscalationPath,
  ConditionalGrant,
  ServiceActions,
  IamConditionBlock,
} from '../types';

const neptuneClient = getApiNeptuneClient();
const dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
const docClient = DynamoDBDocumentClient.from(dynamoClient);
const accessAnalyzerTable = process.env.ACCESS_ANALYZER_TABLE || 'AccessAnalyzerCache';
const leastPrivilegeStore = new LeastPrivilegeStore();

export async function getEffectivePermissions(
  req: Request<{ principal: string }>,
  res: Response
): Promise<void> {
  try {
    const { principal } = req.params;
    if (!principal) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'principal is required' });
      return;
    }

    const perm = await neptuneClient.getEffectivePermissions(principal);

    if (!perm) {
      res
        .status(404)
        .json({ code: 'NOT_FOUND', message: `No effective permissions found for: ${principal}` });
      return;
    }

    const response: EffectivePermissionsResponse = {
      principal: (perm.principal_arn as string) || principal,
      allowedActions: parseJsonArray(perm.allowed_actions as string),
      deniedActions: parseJsonArray(perm.denied_actions as string),
      conditionalGrants: parseConditionalGrants(perm.conditional_grants as string),
      policiesEvaluated: parseJsonArray(perm.policies_evaluated as string),
      isAdmin: (perm.is_admin as boolean) || false,
      blastRadius: (perm.blast_radius as number) || 0,
      evaluatedAt: (perm.evaluated_at as string) || '',
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting effective permissions:', error);
    res
      .status(500)
      .json({ code: 'INTERNAL_ERROR', message: 'Failed to get effective permissions' });
  }
}

export async function getEscalationPaths(req: Request, res: Response): Promise<void> {
  try {
    const { sourceAccount, targetRole, escalationType, riskLevel } = req.query;

    const paths = await neptuneClient.getEscalationPaths({
      sourceAccount: sourceAccount as string | undefined,
      targetRole: targetRole as string | undefined,
      escalationType: escalationType as string | undefined,
      riskLevel: riskLevel as string | undefined,
    });

    const escalationPaths: EscalationPath[] = paths.map((p, index) => ({
      id: (p.id as string) || `esc-${index}`,
      sourceArn: (p.source_arn as string) || '',
      targetArn: (p.target_arn as string) || '',
      path: [],
      pathLength: (p.path_length as number) || 0,
      riskLevel: (p.risk_level as 'critical' | 'high' | 'medium' | 'low') || 'medium',
      escalationType:
        (p.escalation_type as 'admin' | 'privilege_escalation' | 'lateral_movement') ||
        'privilege_escalation',
      conditions: parseConditionBlock(p.conditions_json as string),
      detectedAt: (p.detected_at as string) || '',
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

    if (!principal) {
      res
        .status(400)
        .json({ code: 'BAD_REQUEST', message: 'principal query parameter is required' });
      return;
    }

    const perm = await neptuneClient.getEffectivePermissions(principal as string);

    const usedActions = await fetchUsedActionsFromDynamo(principal as string);

    const allowedActions = perm ? parseJsonArray(perm.allowed_actions as string) : [];
    const unusedByService = groupActionsByService(allowedActions, usedActions);

    const usedByService = groupUsedActionsByService(usedActions);

    const response: UnusedPermissionsResponse = {
      principalArn: principal as string,
      unusedActions: unusedByService,
      usedActions: usedByService,
      lastAnalyzed: (perm?.evaluated_at as string) || new Date().toISOString(),
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting unused permissions:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get unused permissions' });
  }
}

export async function getRightsizingRecommendation(
  req: Request<{ principal: string }>,
  res: Response
): Promise<void> {
  try {
    const { principal } = req.params;

    if (!principal) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'principal is required' });
      return;
    }

    const perm = await neptuneClient.getEffectivePermissions(principal);

    if (!perm) {
      res
        .status(404)
        .json({ code: 'NOT_FOUND', message: `No effective permissions found for: ${principal}` });
      return;
    }

    const allowedActions = parseJsonArray(perm.allowed_actions as string);
    const usedActions = await fetchUsedActionsFromDynamo(principal);
    const keptActions = computeKeptActions(allowedActions, usedActions);
    const removedActions = allowedActions.filter((action) => !keptActions.includes(action));
    const removalRatio =
      allowedActions.length > 0 ? removedActions.length / allowedActions.length : 0;

    const response: RightsizingResponse = {
      principalArn: principal,
      currentPolicy: [
        {
          sid: 'current',
          effect: 'Allow',
          actions: allowedActions,
          resources: ['*'],
        },
      ],
      recommendedPolicy: [
        {
          sid: 'rightsized',
          effect: 'Allow',
          actions: keptActions.length > 0 ? keptActions : ['*'],
          resources: ['*'],
        },
      ],
      removedActions,
      keptActions,
      riskLevel: removalRatio > 0.5 ? 'high' : removalRatio > 0.2 ? 'medium' : 'low',
      confidence: usedActions.length > 0 ? Math.min(1, usedActions.length / 50) : 0,
    };
    res.json(response);
  } catch (error) {
    console.error('Error getting rightsizing recommendation:', error);
    res
      .status(500)
      .json({ code: 'INTERNAL_ERROR', message: 'Failed to get rightsizing recommendation' });
  }
}

export async function getTrustGraph(req: Request, res: Response): Promise<void> {
  try {
    const { account, limit, nextToken } = req.query;
    if (
      (account !== undefined && typeof account !== 'string') ||
      (nextToken !== undefined && typeof nextToken !== 'string')
    ) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'Invalid trust graph query' });
      return;
    }
    const pageSize = parseBoundedInteger(limit, 100, 1, 200, 'limit');

    const result = await neptuneClient.getTrustGraph({
      accountId: account,
      limit: pageSize,
      nextToken,
    });
    res.json(result);
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message.startsWith('limit must be') ||
        error.message.includes('trust graph cursor') ||
        error.message.includes('pagination token'))
    ) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    console.error('Error getting trust graph:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get trust graph' });
  }
}

export async function getLeastPrivilegeFindings(req: Request, res: Response): Promise<void> {
  try {
    const { accountId, riskLevel, principalType, limit, nextToken } = req.query;
    if (
      (accountId !== undefined && typeof accountId !== 'string') ||
      (riskLevel !== undefined && typeof riskLevel !== 'string') ||
      (principalType !== undefined && typeof principalType !== 'string') ||
      (nextToken !== undefined && typeof nextToken !== 'string')
    ) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'Invalid least-privilege query' });
      return;
    }
    const pageSize = parseBoundedInteger(limit, 100, 1, 200, 'limit');

    const result = await leastPrivilegeStore.listFindings({
      accountId,
      riskLevel,
      principalType,
      limit: pageSize,
      nextToken,
    });

    res.json(result);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('limit must be')) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    console.error('Error listing least-privilege findings:', error);
    res
      .status(500)
      .json({ code: 'INTERNAL_ERROR', message: 'Failed to list least-privilege findings' });
  }
}

export async function getLeastPrivilegeFinding(req: Request, res: Response): Promise<void> {
  try {
    const { accountId, principalArn } = req.params;

    if (!/^\d{12}$/.test(accountId) || !principalArn) {
      res
        .status(400)
        .json({ code: 'BAD_REQUEST', message: 'accountId and principalArn are required' });
      return;
    }

    const finding = await leastPrivilegeStore.getFinding(accountId, principalArn);

    if (!finding) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `No least-privilege finding for ${principalArn} in account ${accountId}`,
      });
      return;
    }

    res.json(finding);
  } catch (error) {
    console.error('Error getting least-privilege finding:', error);
    res
      .status(500)
      .json({ code: 'INTERNAL_ERROR', message: 'Failed to get least-privilege finding' });
  }
}

export async function getLeastPrivilegeSummary(_req: Request, res: Response): Promise<void> {
  try {
    const summary = await leastPrivilegeStore.getSummary();
    res.json(summary);
  } catch (error) {
    console.error('Error getting least-privilege summary:', error);
    res
      .status(500)
      .json({ code: 'INTERNAL_ERROR', message: 'Failed to get least-privilege summary' });
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

interface DynamoAccessItem {
  eventSource?: string;
  eventName?: string;
  lastUsed?: string;
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

    return (result.Items || []).map((item) => {
      const data = unmarshall(item) as unknown as DynamoAccessItem;
      return {
        service: data.eventSource || '',
        eventName: data.eventName || '',
        lastUsed: data.lastUsed || '',
      };
    });
  } catch (error) {
    console.error('Failed to read Access Analyzer usage:', error);
    throw error;
  }
}

function groupActionsByService(
  allowedActions: string[],
  usedActions: UsedAction[]
): ServiceActions[] {
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
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${regexStr}$`, 'i').test(action);
}

function isReadOnlyAction(action: string): boolean {
  return (
    /^.*:Get[A-Z]/.test(action) || /^.*:List[A-Z]/.test(action) || /^.*:Describe[A-Z]/.test(action)
  );
}
