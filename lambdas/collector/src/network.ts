import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeInternetGatewaysCommand,
  DescribeNatGatewaysCommand,
  DescribeSubnetsCommand,
} from '@aws-sdk/client-ec2';
import type { GraphNode, GraphEdge } from '../../shared/types';
import { collectPaginated } from '../../shared/pagination';
import type { TagMap } from './tags';
import { extractCommonProperties } from './tags';

export interface CollectResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const INTERNET_NODE_ID = 'arn:aws:khalifa:global:internet';

// NACL entries carry an IANA protocol number as a string, where security group
// rules carry a name. Mapping to the security group vocabulary lets one
// compliance query read both without special-casing the label.
const ACL_PROTOCOL_NAMES: Record<string, string> = {
  '-1': '-1',
  '1': 'icmp',
  '6': 'tcp',
  '17': 'udp',
  '58': 'icmpv6',
};

export function normalizeAclProtocol(protocol: string | undefined): string {
  if (protocol === undefined) return '-1';
  return ACL_PROTOCOL_NAMES[protocol] ?? protocol;
}

// A NetworkAcl vertex carries its rules in an `entries` property, which
// normalizeProperties stringifies because it is not a scalar. Gremlin cannot
// filter inside that string, so CIS 5.1 had nothing to evaluate against.
// Each entry becomes its own vertex, shaped and named like SecurityGroupRule so
// both read the same way from a traversal.
export function buildNetworkAclEntries(
  acl: { NetworkAclId?: string; Entries?: any[]; Associations?: any[] },
  aclArn: string,
  accountId: string,
  region: string
): CollectResult {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  // A NACL that no subnet uses protects nothing, so a permissive rule on it is
  // not a real exposure. Every VPC keeps an undeletable default NACL that
  // allows all traffic, so without these edges the database and IPv6 controls
  // would flag every VPC forever with no remediation that could ever clear it.
  for (const association of acl.Associations ?? []) {
    if (!association.SubnetId) continue;
    edges.push({
      from: aclArn,
      to: `arn:aws:ec2:${region}:${accountId}:subnet/${association.SubnetId}`,
      label: 'ASSOCIATED_WITH',
    });
  }

  for (const entry of acl.Entries ?? []) {
    if (entry.RuleNumber === undefined) continue;
    const direction = entry.Egress ? 'egress' : 'ingress';
    // Rule numbers are unique per direction within one NACL, and an entry
    // carries either CidrBlock or Ipv6CidrBlock, never both.
    const entryArn = `${aclArn}/entry/${direction}/${entry.RuleNumber}`;
    nodes.push({
      id: entryArn,
      label: 'NetworkAclEntry',
      properties: {
        id: entryArn,
        arn: entryArn,
        account_id: accountId,
        network_acl_id: acl.NetworkAclId,
        direction,
        rule_number: entry.RuleNumber,
        rule_action: entry.RuleAction,
        protocol: normalizeAclProtocol(entry.Protocol),
        port_from: entry.PortRange?.From ?? 0,
        port_to: entry.PortRange?.To ?? 0,
        port_range: `${entry.PortRange?.From ?? 0}-${entry.PortRange?.To ?? 0}`,
        cidr_block: entry.CidrBlock ?? entry.Ipv6CidrBlock,
      },
    });
    edges.push({ from: entryArn, to: aclArn, label: 'PART_OF' });
  }

  return { nodes, edges };
}

export async function collectSecurityGroups(
  client: EC2Client,
  accountId: string,
  region: string,
  tagsByArn: Map<string, TagMap>
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const securityGroups = await collectPaginated(
    (token) => client.send(new DescribeSecurityGroupsCommand({ NextToken: token })),
    (page) => page.SecurityGroups,
    (page) => page.NextToken
  );

  for (const sg of securityGroups) {
    if (!sg.GroupId) continue;
    const sgArn = `arn:aws:ec2:${region}:${accountId}:security-group/${sg.GroupId}`;

    const tags = tagsByArn.get(sgArn);
    const tagProps = extractCommonProperties(tags);

    // An administration port open to ::/0 is exactly as exposed as one open to
    // 0.0.0.0/0. Reading IpRanges only left IPv6 exposure absent from the graph
    // entirely, so neither RULE-002 nor any compliance control could see it.
    const ingressRules = (sg.IpPermissions || []).filter(
      (perm: any) =>
        (perm.IpRanges || []).some((r: any) => r.CidrIp === '0.0.0.0/0') ||
        (perm.Ipv6Ranges || []).some((r: any) => r.CidrIpv6 === '::/0')
    );
    const isWorldOpen = ingressRules.length > 0;

    nodes.push({
      id: sgArn,
      label: 'SecurityGroup',
      properties: {
        id: sg.GroupId,
        arn: sgArn,
        account_id: accountId,
        name: sg.GroupName,
        vpc_id: sg.VpcId,
        description: sg.Description,
        is_world_open: isWorldOpen,
        is_default: sg.GroupName === 'default',
        // EC2.2 (CIS 5.4) fails a default group that allows any inbound or
        // outbound traffic. Only world-open ingress rules become
        // SecurityGroupRule vertices, so the self-referencing inbound rule and
        // allow-all outbound rule every default group starts with were invisible.
        ingress_rule_count: (sg.IpPermissions || []).length,
        egress_rule_count: (sg.IpPermissionsEgress || []).length,
        ...tagProps,
      },
    });

    for (const perm of ingressRules) {
      // The v4 and v6 ranges of one permission share protocol and port range,
      // so they would generate the same vertex id. The suffix keeps them
      // distinct; without it the second write silently overwrites the first.
      const worldOpen: Array<{ cidr: string; suffix: string }> = [
        ...(perm.IpRanges || [])
          .filter((range: any) => range.CidrIp === '0.0.0.0/0')
          .map((range: any) => ({ cidr: range.CidrIp as string, suffix: '' })),
        ...(perm.Ipv6Ranges || [])
          .filter((range: any) => range.CidrIpv6 === '::/0')
          .map((range: any) => ({ cidr: range.CidrIpv6 as string, suffix: '/v6' })),
      ];

      for (const { cidr, suffix } of worldOpen) {
        const ruleArn = `${sgArn}/ingress/${perm.IpProtocol}/${perm.FromPort || 0}-${perm.ToPort || 0}${suffix}`;
        nodes.push({
          id: ruleArn,
          label: 'SecurityGroupRule',
          properties: {
            id: ruleArn,
            arn: ruleArn,
            account_id: accountId,
            direction: 'ingress',
            protocol: perm.IpProtocol,
            port_from: perm.FromPort ?? 0,
            port_to: perm.ToPort ?? 0,
            port_range: `${perm.FromPort || 0}-${perm.ToPort || 0}`,
            cidr_block: cidr,
          },
        });
        edges.push({ from: ruleArn, to: sgArn, label: 'PART_OF' });
      }
    }
  }

  return { nodes, edges };
}

export async function collectInternetGateways(
  client: EC2Client,
  accountId: string,
  region: string,
  tagsByArn: Map<string, TagMap>
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const internetGateways = await collectPaginated(
    (token) => client.send(new DescribeInternetGatewaysCommand({ NextToken: token })),
    (page) => page.InternetGateways,
    (page) => page.NextToken
  );
  for (const igw of internetGateways) {
    if (!igw.InternetGatewayId) continue;
    const igwArn = `arn:aws:ec2:${region}:${accountId}:internet-gateway/${igw.InternetGatewayId}`;

    const tags = tagsByArn.get(igwArn);
    const tagProps = extractCommonProperties(tags);

    nodes.push({
      id: igwArn,
      label: 'InternetGateway',
      properties: {
        id: igw.InternetGatewayId,
        arn: igwArn,
        account_id: accountId,
        ...tagProps,
      },
    });

    for (const att of igw.Attachments || []) {
      if (att.VpcId) {
        const vpcArn = `arn:aws:ec2:${region}:${accountId}:vpc/${att.VpcId}`;
        edges.push({ from: igwArn, to: vpcArn, label: 'ATTACHED_TO' });
      }
    }

    edges.push({ from: INTERNET_NODE_ID, to: igwArn, label: 'EXPOSES' });
  }

  return { nodes, edges };
}

export async function collectNatGateways(
  client: EC2Client,
  accountId: string,
  region: string,
  tagsByArn: Map<string, TagMap>
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const natGateways = await collectPaginated(
    (token) => client.send(new DescribeNatGatewaysCommand({ NextToken: token })),
    (page) => page.NatGateways,
    (page) => page.NextToken
  );
  for (const nat of natGateways) {
    if (!nat.NatGatewayId) continue;
    const natArn = `arn:aws:ec2:${region}:${accountId}:nat-gateway/${nat.NatGatewayId}`;

    const tags = tagsByArn.get(natArn);
    const tagProps = extractCommonProperties(tags);

    nodes.push({
      id: natArn,
      label: 'NatGateway',
      properties: {
        id: nat.NatGatewayId,
        arn: natArn,
        account_id: accountId,
        state: nat.State,
        ...tagProps,
      },
    });

    if (nat.SubnetId) {
      const subnetArn = `arn:aws:ec2:${region}:${accountId}:subnet/${nat.SubnetId}`;
      edges.push({ from: natArn, to: subnetArn, label: 'IN_SUBNET' });
    }
  }

  return { nodes, edges };
}

export async function collectSubnets(
  client: EC2Client,
  accountId: string,
  region: string
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[]; publicSubnetIds: Set<string> }> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const publicSubnetIds = new Set<string>();

  const subnets = await collectPaginated(
    (token) => client.send(new DescribeSubnetsCommand({ NextToken: token })),
    (page) => page.Subnets,
    (page) => page.NextToken
  );
  for (const subnet of subnets) {
    if (!subnet.SubnetId) continue;
    const subnetArn = `arn:aws:ec2:${region}:${accountId}:subnet/${subnet.SubnetId}`;
    const isPublic = subnet.MapPublicIpOnLaunch === true;

    if (isPublic) publicSubnetIds.add(subnet.SubnetId);

    nodes.push({
      id: subnetArn,
      label: 'Subnet',
      properties: {
        id: subnet.SubnetId,
        arn: subnetArn,
        account_id: accountId,
        vpc_id: subnet.VpcId,
        cidr_block: subnet.CidrBlock,
        availability_zone: subnet.AvailabilityZone,
        is_public: isPublic,
        map_public_ip_on_launch: subnet.MapPublicIpOnLaunch === true,
      },
    });

    if (subnet.VpcId) {
      const vpcArn = `arn:aws:ec2:${region}:${accountId}:vpc/${subnet.VpcId}`;
      edges.push({ from: vpcArn, to: subnetArn, label: 'CONTAINS' });
    }
  }

  return { nodes, edges, publicSubnetIds };
}

export function buildInternetNode(accountId: string): GraphNode {
  return {
    id: INTERNET_NODE_ID,
    label: 'Internet',
    properties: {
      id: INTERNET_NODE_ID,
      arn: INTERNET_NODE_ID,
      account_id: accountId,
      name: 'Internet',
      is_internet_exposed: true,
    },
  };
}

export { INTERNET_NODE_ID };
