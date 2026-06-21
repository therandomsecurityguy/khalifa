import {
  EC2Client,
  DescribeSecurityGroupsCommand,
  DescribeInternetGatewaysCommand,
  DescribeNatGatewaysCommand,
  DescribeSubnetsCommand,
} from '@aws-sdk/client-ec2';
import type { GraphNode, GraphEdge } from '../../shared/types';
import type { TagMap } from './tags';
import { extractCommonProperties } from './tags';

export interface CollectResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface NetworkContext {
  nodes: GraphNode[];
  edges: GraphEdge[];
  subnetIdsByVpc: Map<string, string[]>;
  igwIdsByVpc: Map<string, string[]>;
  publicSubnetIds: Set<string>;
}

const INTERNET_NODE_ID = 'arn:aws:khalifa:global:internet';

export async function collectSecurityGroups(
  client: EC2Client,
  accountId: string,
  region: string,
  tagsByArn: Map<string, TagMap>
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const securityGroups: any[] = [];
  let token: string | undefined;
  do {
    const response: any = await client.send(
      new DescribeSecurityGroupsCommand({ NextToken: token })
    );
    if (response.SecurityGroups) securityGroups.push(...response.SecurityGroups);
    token = response.NextToken;
  } while (token);

  for (const sg of securityGroups) {
    if (!sg.GroupId) continue;
    const sgArn = `arn:aws:ec2:${region}:${accountId}:security-group/${sg.GroupId}`;

    const tags = tagsByArn.get(sgArn);
    const tagProps = extractCommonProperties(tags);

    const ingressRules = (sg.IpPermissions || []).filter((perm: any) =>
      (perm.IpRanges || []).some((r: any) => r.CidrIp === '0.0.0.0/0')
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
        ...tagProps,
      },
    });

    for (const perm of ingressRules) {
      for (const range of perm.IpRanges || []) {
        if (range.CidrIp !== '0.0.0.0/0') continue;
        const ruleArn = `${sgArn}/ingress/${perm.IpProtocol}/${perm.FromPort || 0}-${perm.ToPort || 0}`;
        nodes.push({
          id: ruleArn,
          label: 'SecurityGroupRule',
          properties: {
            id: ruleArn,
            arn: ruleArn,
            account_id: accountId,
            direction: 'ingress',
            protocol: perm.IpProtocol,
            port_range: `${perm.FromPort || 0}-${perm.ToPort || 0}`,
            cidr_block: range.CidrIp,
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

  const response = await client.send(new DescribeInternetGatewaysCommand({}));
  for (const igw of response.InternetGateways || []) {
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

  const response = await client.send(new DescribeNatGatewaysCommand({}));
  for (const nat of response.NatGateways || []) {
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

  const response = await client.send(new DescribeSubnetsCommand({}));
  for (const subnet of response.Subnets || []) {
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
