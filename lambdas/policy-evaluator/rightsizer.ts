import type { ServiceActions, UnusedPermissions, RightsizingRecommendation, ParsedStatement } from './types';
import { isActionMatched, parsePolicyDocument } from './policy-parser';

export interface UsedActionEntry {
  principalArn: string;
  eventSource: string;
  eventName: string;
  lastUsed: string;
  eventCount: number;
}

export function computeUnusedPermissions(
  principalArn: string,
  allowedActions: string[],
  usedActions: UsedActionEntry[],
  days?: number
): UnusedPermissions {
  const usedActionStrings = new Set<string>();
  const usedByService = new Map<string, Set<string>>();

  const cutoff = days ? new Date(Date.now() - days * 86400000) : undefined;

  for (const entry of usedActions) {
    if (entry.principalArn !== principalArn) continue;
    if (cutoff && new Date(entry.lastUsed) < cutoff) continue;

    const service = entry.eventSource.replace('.amazonaws.com', '');
    const action = `${service}:${entry.eventName}`;
    usedActionStrings.add(action);

    const serviceSet = usedByService.get(service) || new Set();
    serviceSet.add(action);
    usedByService.set(service, serviceSet);
  }

  const unusedByService = new Map<string, Set<string>>();
  const keptByService = new Map<string, Set<string>>();

  for (const allowedAction of allowedActions) {
    let isUsed = false;
    for (const usedAction of usedActionStrings) {
      if (isActionMatched(allowedAction, usedAction)) {
        isUsed = true;
        break;
      }
    }

    const service = allowedAction.split(':')[0];
    if (isUsed) {
      const set = keptByService.get(service) || new Set();
      set.add(allowedAction);
      keptByService.set(service, set);
    } else {
      const set = unusedByService.get(service) || new Set();
      set.add(allowedAction);
      unusedByService.set(service, set);
    }
  }

  return {
    principalArn,
    unusedActions: mapToServiceActions(unusedByService),
    usedActions: mapToServiceActions(usedByService),
    lastAnalyzed: new Date().toISOString(),
  };
}

export function generateRightsizingRecommendation(
  principalArn: string,
  allowedActions: string[],
  usedActions: UsedActionEntry[],
  currentPolicyJsons: string[],
  options: { safetyMarginDays?: number; includeReadonlySafe?: boolean } = {}
): RightsizingRecommendation {
  const { safetyMarginDays = 7, includeReadonlySafe = true } = options;
  const cutoff = new Date(Date.now() - safetyMarginDays * 86400000);

  const usedActionStrings = new Set<string>();
  const recentActions = usedActions.filter((a) => a.principalArn === principalArn && new Date(a.lastUsed) >= cutoff);

  for (const entry of recentActions) {
    const service = entry.eventSource.replace('.amazonaws.com', '');
    usedActionStrings.add(`${service}:${entry.eventName}`);
  }

  const keptActions: string[] = [];
  const removedActions: string[] = [];

  for (const action of allowedActions) {
    let isUsed = false;
    for (const used of usedActionStrings) {
      if (isActionMatched(action, used)) {
        isUsed = true;
        break;
      }
    }

    if (isUsed) {
      keptActions.push(action);
    } else if (includeReadonlySafe && isReadOnlyAction(action)) {
      keptActions.push(action);
    } else {
      removedActions.push(action);
    }
  }

  const currentPolicy: ParsedStatement[] = [];
  for (const json of currentPolicyJsons) {
    try {
      const doc = parsePolicyDocument(json);
      currentPolicy.push(...doc.Statement);
    } catch (e) {}
  }

  const recommendedPolicy: ParsedStatement[] = [
    {
      sid: 'RightsizedAllow',
      effect: 'Allow',
      actions: consolidateActions(keptActions),
      resources: ['*'],
    },
  ];

  const removalRatio = allowedActions.length > 0 ? removedActions.length / allowedActions.length : 0;
  const riskLevel = removalRatio > 0.5 ? 'high' : removalRatio > 0.2 ? 'medium' : 'low';
  const confidence = recentActions.length > 0 ? Math.min(1, recentActions.length / 100) : 0;

  return {
    principalArn,
    currentPolicy,
    recommendedPolicy,
    removedActions,
    keptActions,
    riskLevel,
    confidence,
  };
}

function isReadOnlyAction(action: string): boolean {
  const readOnlyPatterns = [
    /^.*:Get[A-Z]/,
    /^.*:List[A-Z]/,
    /^.*:Describe[A-Z]/,
    /^.*:Head[A-Z]/,
    /^.*:Lookup[A-Z]/,
    /^.*:BatchGet[A-Z]/,
    /^.*:View[A-Z]/,
    /^.*:Search[A-Z]/,
    /^.*:Query/,
    /^.*:Scan/,
    /^.*:Select/,
    /^.*:Download[A-Z]/,
  ];
  return readOnlyPatterns.some((p) => p.test(action));
}

function consolidateActions(actions: string[]): string[] {
  if (actions.length === 0) return [];
  const byService = new Map<string, Set<string>>();
  for (const action of actions) {
    const [service, ...rest] = action.split(':');
    const op = rest.join(':');
    const set = byService.get(service) || new Set();
    set.add(op);
    byService.set(service, set);
  }

  const result: string[] = [];
  for (const [service, ops] of byService) {
    if (ops.size >= 10) {
      result.push(`${service}:*`);
    } else {
      const prefixes = new Set<string>();
      const remainder: string[] = [];
      for (const op of ops) {
        const prefix = op.replace(/([A-Z][a-z]*).*/, '$1');
        if (ops.size > 2 && [...ops].filter((o) => o.startsWith(prefix)).length >= 2) {
          prefixes.add(prefix);
        } else {
          remainder.push(op);
        }
      }
      for (const prefix of prefixes) {
        result.push(`${service}:${prefix}*`);
      }
      for (const op of remainder) {
        result.push(`${service}:${op}`);
      }
    }
  }
  return result;
}

function mapToServiceActions(map: Map<string, Set<string>>): ServiceActions[] {
  return [...map.entries()].map(([service, actions]) => ({
    service,
    actions: [...actions],
  }));
}