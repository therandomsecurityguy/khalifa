import {
  GuardDutyClient,
  ListDetectorsCommand,
  ListFindingsCommand,
  GetFindingsCommand,
  type Finding,
} from '@aws-sdk/client-guardduty';
import type { GraphNode, GraphEdge } from '../../shared/types';
import { collectPaginated } from '../../shared/pagination';

// GuardDuty findings are read from the delegated administrator's detectors,
// which see every member account, rather than through Security Hub. Security
// Hub mixes them with Config and Inspector findings under one 500-finding cap
// per account and region, and Khalifa only reads it in the regions it collects.
//
// Each finding is written with the account and region it is ABOUT, not the
// administrator account it was read from, and reconciled under its own scope.
// Under the resource-inventory scope, a member account's own collection run
// would tombstone the findings the administrator run wrote for it.

export const GUARDDUTY_FINDINGS_SCOPE_PREFIX = 'guardduty-findings';

export function guardDutyFindingsScope(region: string): string {
  return `${GUARDDUTY_FINDINGS_SCOPE_PREFIX}:${region}`;
}

// GetFindings accepts at most 50 ids per call.
const GET_FINDINGS_BATCH = 50;

// GuardDuty's own bands: 1.0-3.9 low, 4.0-6.9 medium, 7.0-8.9 high, 9.0+ critical.
export function severityLabel(severity: number | undefined): string | undefined {
  if (typeof severity !== 'number' || !Number.isFinite(severity)) return undefined;
  if (severity >= 9) return 'CRITICAL';
  if (severity >= 7) return 'HIGH';
  if (severity >= 4) return 'MEDIUM';
  return 'LOW';
}

type RemoteIpDetails = NonNullable<
  NonNullable<NonNullable<Finding['Service']>['Action']>['NetworkConnectionAction']
>['RemoteIpDetails'];

// The attacker lives under a different key for each action type; a port probe
// can carry several, of which the first is recorded.
function remoteIpDetails(finding: Finding): RemoteIpDetails | undefined {
  const action = finding.Service?.Action;
  return (
    action?.NetworkConnectionAction?.RemoteIpDetails ??
    action?.AwsApiCallAction?.RemoteIpDetails ??
    action?.KubernetesApiCallAction?.RemoteIpDetails ??
    action?.RdsLoginAttemptAction?.RemoteIpDetails ??
    action?.PortProbeAction?.PortProbeDetails?.[0]?.RemoteIpDetails
  );
}

// The resource vertex ids a finding points at, in the same form the collector
// writes them. Edges to a vertex the graph does not have are skipped by the
// writer, so a finding in an uncollected account keeps its vertex with no edge.
export function findingTargets(finding: Finding, accountId: string, region: string): string[] {
  const resource = finding.Resource;
  if (!resource) return [];
  const targets: string[] = [];
  const instanceId = resource.InstanceDetails?.InstanceId;
  if (instanceId) targets.push(`arn:aws:ec2:${region}:${accountId}:instance/${instanceId}`);
  const dbInstanceId = resource.RdsDbInstanceDetails?.DbInstanceIdentifier;
  if (dbInstanceId) targets.push(`arn:aws:rds:${region}:${accountId}:db:${dbInstanceId}`);
  const clusterName = resource.EksClusterDetails?.Name;
  if (clusterName) targets.push(`arn:aws:eks:${region}:${accountId}:cluster/${clusterName}`);
  for (const bucket of resource.S3BucketDetails || []) {
    if (bucket.Name) targets.push(`arn:aws:s3:::${bucket.Name}`);
  }
  const key = resource.AccessKeyDetails;
  if (key?.UserName && key.UserType === 'IAMUser') {
    targets.push(`arn:aws:iam::${accountId}:user/${key.UserName}`);
  } else if (key?.UserName && key.UserType === 'AssumedRole') {
    targets.push(`arn:aws:iam::${accountId}:role/${key.UserName}`);
  }
  return [...new Set(targets)];
}

export function buildFindingGraph(
  finding: Finding,
  fallbackRegion: string
): { node: GraphNode; edges: GraphEdge[] } | undefined {
  if (!finding.Id || !finding.AccountId) return undefined;
  const accountId = finding.AccountId;
  const region = finding.Region || fallbackRegion;
  const id =
    finding.Arn ||
    `arn:aws:guardduty:${region}:${accountId}:finding/${encodeURIComponent(finding.Id)}`;
  const remote = remoteIpDetails(finding);
  const type = finding.Type;
  const targets = findingTargets(finding, accountId, region);

  const node: GraphNode = {
    id,
    label: 'GuardDutyFinding',
    properties: {
      id: finding.Id,
      arn: id,
      account_id: accountId,
      region,
      type,
      // "UnauthorizedAccess" in "UnauthorizedAccess:EC2/SSHBruteForce": the
      // threat purpose, which rules filter on.
      finding_class: type?.split(':')[0],
      severity: finding.Severity,
      severity_label: severityLabel(finding.Severity),
      title: finding.Title,
      resource_type: finding.Resource?.ResourceType,
      resource_arn: targets[0],
      action_type: finding.Service?.Action?.ActionType,
      // TARGET: the resource is being attacked. ACTOR: it is doing the
      // attacking, which is the stronger sign of compromise.
      resource_role: finding.Service?.ResourceRole,
      remote_ip: remote?.IpAddressV4 ?? remote?.IpAddressV6,
      remote_asn: remote?.Organization?.Asn,
      remote_asn_org: remote?.Organization?.AsnOrg,
      remote_country: remote?.Country?.CountryName,
      // DNS findings name a domain instead of a remote IP.
      remote_domain: finding.Service?.Action?.DnsRequestAction?.Domain,
      count: finding.Service?.Count,
      first_seen: finding.Service?.EventFirstSeen,
      last_seen: finding.Service?.EventLastSeen,
      archived: finding.Service?.Archived === true,
      created_at: finding.CreatedAt,
      updated_at: finding.UpdatedAt,
    },
  };
  const edges = targets.map((to) => ({ from: id, to, label: 'DETECTS_ON' }));
  return { node, edges };
}

// Reads every unarchived finding from the region's administrator detector.
// Returns undefined when the account has no detector in the region.
export async function collectRegionFindings(
  client: GuardDutyClient,
  region: string
): Promise<{ detectorId: string; findings: Finding[] } | undefined> {
  const detectorIds = await collectPaginated(
    (token) => client.send(new ListDetectorsCommand({ NextToken: token })),
    (page) => page.DetectorIds,
    (page) => page.NextToken
  );
  const detectorId = detectorIds[0];
  if (!detectorId) return undefined;

  const findingIds = await collectPaginated(
    (token) =>
      client.send(
        new ListFindingsCommand({
          DetectorId: detectorId,
          MaxResults: 50,
          NextToken: token,
          FindingCriteria: { Criterion: { 'service.archived': { Equals: ['false'] } } },
        })
      ),
    (page) => page.FindingIds,
    (page) => page.NextToken
  );

  const findings: Finding[] = [];
  for (let start = 0; start < findingIds.length; start += GET_FINDINGS_BATCH) {
    const page = await client.send(
      new GetFindingsCommand({
        DetectorId: detectorId,
        FindingIds: findingIds.slice(start, start + GET_FINDINGS_BATCH),
      })
    );
    for (const finding of page.Findings || []) {
      // ListFindings filtered on archived; a finding archived between the two
      // calls is dropped here rather than written as active.
      if (finding.Service?.Archived !== true) findings.push(finding);
    }
  }
  return { detectorId, findings: findings.map((f) => ({ ...f, Region: f.Region || region })) };
}

export function buildRegionFindingGraph(
  findings: Finding[],
  region: string
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seen = new Set<string>();
  for (const finding of findings) {
    const built = buildFindingGraph(finding, region);
    if (!built || seen.has(built.node.id)) continue;
    seen.add(built.node.id);
    nodes.push(built.node);
    edges.push(...built.edges);
  }
  return { nodes, edges };
}
