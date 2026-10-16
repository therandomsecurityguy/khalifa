import type { GraphNode } from '../../shared/types';

// ListPolicies runs with Scope Local, so only customer-managed policies get an
// IamPolicy vertex. An AWS-managed policy attached to a principal is linked
// only through a vertex at its ARN -- principal -ATTACHED_TO-> policyArn
// -CONTAINS-> IamPolicyDocument -- and buildEdgeUpsert skips an edge whose
// target vertex does not exist. So every attachment of an AWS-managed policy,
// and the CONTAINS edge to its document, was silently dropped. CIS 1.17 and
// 1.22 ask exactly "is this AWS-managed policy attached to anyone", and could
// not be answered.
//
// Switching ListPolicies to Scope All would fix it by collecting ~1,300 AWS
// policies per account. Emitting a vertex only for the AWS-managed policies a
// principal actually has attached keeps the graph to what is in use.
const AWS_MANAGED_POLICY = /^arn:aws[a-z-]*:iam::aws:policy\//;

export function isAwsManagedPolicyArn(policyArn: string | undefined): policyArn is string {
  return typeof policyArn === 'string' && AWS_MANAGED_POLICY.test(policyArn);
}

// The ARN is global, so every collected account emits the same vertex id and
// the last writer's account_id wins. Nothing reads that account_id. The
// collector leaves these vertices out of reconcile scoping, as it does the
// shared Internet vertex, because a scoped shared vertex can be tombstoned by
// whichever account wrote it last. The cost is that an AWS-managed policy no
// longer attached anywhere keeps its vertex, edgeless and harmless.
export function buildAwsManagedPolicyNode(
  policyArn: string,
  policyName: string | undefined,
  accountId: string
): GraphNode {
  return {
    id: policyArn,
    label: 'IamPolicy',
    properties: {
      id: policyName ?? policyArn.slice(policyArn.lastIndexOf('/') + 1),
      arn: policyArn,
      account_id: accountId,
      name: policyName,
      policy_type: 'aws-managed',
    },
  };
}
