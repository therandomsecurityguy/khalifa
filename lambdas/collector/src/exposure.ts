import type { GraphNode } from '../../shared/types';

export interface ExposureContext {
  publicSubnetIds: Set<string>;
  subnetVpcIds: Map<string, string>;
  vpcHasIgw: Map<string, boolean>;
}

export function buildExposureContext(nodes: GraphNode[]): ExposureContext {
  const publicSubnetIds = new Set<string>();
  const subnetVpcIds = new Map<string, string>();
  const vpcHasIgw = new Map<string, boolean>();

  for (const node of nodes) {
    if (node.label === 'Subnet') {
      const subnetId = node.properties.id as string;
      const vpcId = node.properties.vpc_id as string;
      if (subnetId) {
        if (node.properties.is_public === true) {
          publicSubnetIds.add(subnetId);
        }
        if (vpcId) subnetVpcIds.set(subnetId, vpcId);
      }
    }
    if (node.label === 'InternetGateway') {
      const vpcId = (node.properties.vpc_id as string) || '';
      const att = node.properties.attachments as any;
      if (Array.isArray(att)) {
        for (const a of att) {
          if (a.VpcId) vpcHasIgw.set(a.VpcId, true);
        }
      }
    }
  }

  return { publicSubnetIds, subnetVpcIds, vpcHasIgw };
}

export function deriveIsInternetExposed(
  properties: Record<string, unknown>,
  ctx: ExposureContext
): boolean {
  if (properties.public_ip) return true;
  if (properties.PublicIp) return true;
  if (properties.PublicIpAddress) return true;
  if (properties.publicly_accessible === true) return true;
  if (properties.PubliclyAccessible === true) return true;
  if (properties.is_internet_facing === true) return true;

  if (properties.scheme === 'internet-facing') return true;

  if (properties.endpoint_type === 'REGIONAL' || properties.endpoint_type === 'EDGE') {
    return true;
  }

  const subnetId = properties.subnet_id as string;
  if (subnetId && ctx.publicSubnetIds.has(subnetId)) {
    const vpcId = ctx.subnetVpcIds.get(subnetId);
    if (vpcId && ctx.vpcHasIgw.get(vpcId)) return true;
  }

  return false;
}

export function applyExposureToNodes(
  nodes: GraphNode[],
  ctx: ExposureContext
): GraphNode[] {
  const exposedLabels = new Set([
    'Ec2Instance',
    'LambdaFunction',
    'RdsInstance',
    'RedshiftCluster',
    'OpenSearchDomain',
    'ApiGateway',
    'LoadBalancer',
  ]);

  return nodes.map((node) => {
    if (!exposedLabels.has(node.label)) return node;
    const isInternetExposed = deriveIsInternetExposed(node.properties, ctx);
    if (!isInternetExposed) return node;
    return {
      ...node,
      properties: {
        ...node.properties,
        is_internet_exposed: true,
      },
    };
  });
}