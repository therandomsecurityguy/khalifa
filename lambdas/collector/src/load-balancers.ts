import {
  ElasticLoadBalancingV2Client,
  DescribeLoadBalancersCommand,
} from '@aws-sdk/client-elastic-load-balancing-v2';
import type { GraphNode, GraphEdge } from '../../shared/types';
import type { TagMap } from './tags';
import { extractCommonProperties } from './tags';
import { INTERNET_NODE_ID } from './network';

export async function collectLoadBalancers(
  client: ElasticLoadBalancingV2Client,
  accountId: string,
  region: string,
  tagsByArn: Map<string, TagMap>
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  let marker: string | undefined;
  do {
    const response: any = await client.send(
      new DescribeLoadBalancersCommand({ Marker: marker })
    );

    for (const lb of response.LoadBalancers || []) {
      if (!lb.LoadBalancerArn) continue;
      const tags = tagsByArn.get(lb.LoadBalancerArn);
      const tagProps = extractCommonProperties(tags);

      const isInternetFacing = lb.Scheme === 'internet-facing';

      nodes.push({
        id: lb.LoadBalancerArn,
        label: 'LoadBalancer',
        properties: {
          id: lb.LoadBalancerArn,
          arn: lb.LoadBalancerArn,
          account_id: accountId,
          name: lb.LoadBalancerName,
          type: lb.Type,
          scheme: lb.Scheme,
          dns_name: lb.DNSName,
          is_internet_facing: isInternetFacing,
          ...tagProps,
        },
      });

      if (isInternetFacing) {
        edges.push({ from: INTERNET_NODE_ID, to: lb.LoadBalancerArn, label: 'EXPOSES' });
      }

      for (const az of lb.AvailabilityZones || []) {
        if (az.SubnetId) {
          const subnetArn = `arn:aws:ec2:${region}:${accountId}:subnet/${az.SubnetId}`;
          edges.push({ from: lb.LoadBalancerArn, to: subnetArn, label: 'IN_SUBNET' });
        }
      }
    }

    marker = response.NextMarker;
  } while (marker);

  return { nodes, edges };
}