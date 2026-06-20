import { deriveIsInternetExposed, applyExposureToNodes, buildExposureContext } from './exposure';
import type { GraphNode } from '../../shared/types';

function node(label: string, props: Record<string, unknown>): GraphNode {
  return { id: `id-${label}`, label, properties: props };
}

describe('buildExposureContext', () => {
  it('marks subnets as public when MapPublicIpOnLaunch=true', () => {
    const ctx = buildExposureContext([
      node('Subnet', { id: 'subnet-1', vpc_id: 'vpc-1', is_public: true }),
    ]);
    expect(ctx.publicSubnetIds.has('subnet-1')).toBe(true);
  });

  it('records vpc ids for IGWs', () => {
    const ctx = buildExposureContext([
      node('InternetGateway', {
        attachments: [{ VpcId: 'vpc-1' }],
      }),
    ]);
    expect(ctx.vpcHasIgw.get('vpc-1')).toBe(true);
  });
});

describe('deriveIsInternetExposed', () => {
  const baseCtx = {
    publicSubnetIds: new Set<string>(),
    subnetVpcIds: new Map<string, string>(),
    vpcHasIgw: new Map<string, boolean>(),
  };

  it('exposes EC2 with public_ip', () => {
    expect(deriveIsInternetExposed({ public_ip: '1.2.3.4' }, baseCtx)).toBe(true);
  });

  it('exposes RDS when PubliclyAccessible=true', () => {
    expect(deriveIsInternetExposed({ PubliclyAccessible: true }, baseCtx)).toBe(true);
  });

  it('exposes internet-facing LoadBalancer', () => {
    expect(deriveIsInternetExposed({ scheme: 'internet-facing' }, baseCtx)).toBe(true);
  });

  it('does not expose private subnet without IGW', () => {
    expect(
      deriveIsInternetExposed({ subnet_id: 'subnet-x' }, {
        publicSubnetIds: new Set(['subnet-x']),
        subnetVpcIds: new Map([['subnet-x', 'vpc-1']]),
        vpcHasIgw: new Map(),
      })
    ).toBe(false);
  });

  it('exposes resource on public subnet in VPC with IGW', () => {
    expect(
      deriveIsInternetExposed({ subnet_id: 'subnet-x' }, {
        publicSubnetIds: new Set(['subnet-x']),
        subnetVpcIds: new Map([['subnet-x', 'vpc-1']]),
        vpcHasIgw: new Map([['vpc-1', true]]),
      })
    ).toBe(true);
  });
});

describe('applyExposureToNodes', () => {
  it('sets is_internet_exposed on EC2 instances with public_ip', () => {
    const nodes: GraphNode[] = [
      node('Ec2Instance', { id: 'i-1', public_ip: '1.2.3.4' }),
      node('Ec2Instance', { id: 'i-2', public_ip: null }),
    ];
    const ctx = {
      publicSubnetIds: new Set<string>(),
      subnetVpcIds: new Map<string, string>(),
      vpcHasIgw: new Map<string, boolean>(),
    };
    const result = applyExposureToNodes(nodes, ctx);
    expect(result[0].properties.is_internet_exposed).toBe(true);
    expect(result[1].properties.is_internet_exposed).toBeUndefined();
  });

  it('leaves non-exposable labels untouched', () => {
    const nodes: GraphNode[] = [node('KmsKey', { id: 'kms-1' })];
    const ctx = {
      publicSubnetIds: new Set<string>(),
      subnetVpcIds: new Map<string, string>(),
      vpcHasIgw: new Map<string, boolean>(),
    };
    const result = applyExposureToNodes(nodes, ctx);
    expect(result[0]).toEqual(nodes[0]);
  });
});