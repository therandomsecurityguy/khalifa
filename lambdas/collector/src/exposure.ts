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
      const _vpcId = (node.properties.vpc_id as string) || '';
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
  // Lambda: a function URL anyone can call, or a policy letting anyone invoke.
  if (properties.function_url_public === true) return true;
  if (properties.public_invoke_policy === true) return true;

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

// networkComplete: the subnets and internet-gateways stages succeeded. Without
// them, a resource exposed only through a public subnet would derive as
// unexposed, so false is not written and the previous value stands.
export function applyExposureToNodes(
  nodes: GraphNode[],
  ctx: ExposureContext,
  networkComplete: boolean
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

  // Written as true or false every run so a fixed resource stops showing as
  // exposed. A Lambda whose URLs and policy could not be read, or any resource
  // when the network stages failed, keeps its last value: unknown is not
  // unexposed.
  return nodes.map((node) => {
    if (!exposedLabels.has(node.label)) return node;
    const isInternetExposed = deriveIsInternetExposed(node.properties, ctx);
    if (
      !isInternetExposed &&
      (node.properties.lambda_exposure_restricted === true || !networkComplete)
    ) {
      return node;
    }
    return {
      ...node,
      properties: {
        ...node.properties,
        is_internet_exposed: isInternetExposed,
      },
    };
  });
}
