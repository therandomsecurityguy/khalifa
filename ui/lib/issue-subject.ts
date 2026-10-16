import type { Issue } from '@/types';
import { formatNodeLabel } from '@/lib/graph-labels';

// What a grouped issue's extra resources are, most telling first.
const MATCH_NOUNS: Array<[string, string]> = [
  ['SecurityHubFinding', 'finding'],
  ['SecurityGroupRule', 'security group rule'],
  ['IamPolicyStatement', 'statement'],
];
const ACCOUNT_IN_ARN = /^arn:aws[\w-]*:[^:]*:[^:]*:(\d{12}):/;

// The resource an issue is about (the first one recorded; grouped issues list
// it first), its account, and how many matches the issue groups.
export function issueSubject(issue: Issue, accountNames: Map<string, string>) {
  const [primary, ...rest] = issue.resourcesInvolved ?? [];
  if (!primary) return null;
  const name = primary.resourceName || primary.resourceId.split(/[:/]/).pop() || primary.resourceId;
  const accountId = issue.resourcesInvolved
    .map((r) => ACCOUNT_IN_ARN.exec(r.resourceId)?.[1])
    .find(Boolean);
  const matches =
    typeof issue.metadata?.matchCount === 'number' ? issue.metadata.matchCount : rest.length;
  const noun = MATCH_NOUNS.find(([type]) => rest.some((r) => r.resourceType === type))?.[1];
  return {
    name,
    type: formatNodeLabel(primary.resourceType),
    account: accountId ? accountNames.get(accountId) || accountId : null,
    matches: noun && matches > 1 ? `${matches} ${noun}s` : null,
  };
}
