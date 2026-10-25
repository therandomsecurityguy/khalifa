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

  it.each([
    [{ function_url_public: true }, true],
    [{ public_invoke_policy: true }, true],
    [{ function_url_auth_type: 'NONE', function_url_public: false }, false],
    [{ lambda_exposure_restricted: true }, false],
  ])('exposes a Lambda from %j: %s', (props, exposed) => {
    expect(deriveIsInternetExposed(props, baseCtx)).toBe(exposed);
  });

  it('does not expose private subnet without IGW', () => {
    expect(
      deriveIsInternetExposed(
        { subnet_id: 'subnet-x' },
        {
          publicSubnetIds: new Set(['subnet-x']),
          subnetVpcIds: new Map([['subnet-x', 'vpc-1']]),
          vpcHasIgw: new Map(),
        }
      )
    ).toBe(false);
  });

  it('exposes resource on public subnet in VPC with IGW', () => {
    expect(
      deriveIsInternetExposed(
        { subnet_id: 'subnet-x' },
        {
          publicSubnetIds: new Set(['subnet-x']),
          subnetVpcIds: new Map([['subnet-x', 'vpc-1']]),
          vpcHasIgw: new Map([['vpc-1', true]]),
        }
      )
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
    const result = applyExposureToNodes(nodes, ctx, true);
    expect(result[0].properties.is_internet_exposed).toBe(true);
    expect(result[1].properties.is_internet_exposed).toBe(false);
  });

  it('keeps the last value for a Lambda whose exposure could not be read', () => {
    const nodes: GraphNode[] = [
      node('LambdaFunction', { id: 'fn-1', lambda_exposure_restricted: true }),
      node('LambdaFunction', { id: 'fn-2', lambda_exposure_restricted: false }),
    ];
    const ctx = {
      publicSubnetIds: new Set<string>(),
      subnetVpcIds: new Map<string, string>(),
      vpcHasIgw: new Map<string, boolean>(),
    };
    const result = applyExposureToNodes(nodes, ctx, true);
    expect(result[0]).toEqual(nodes[0]);
    expect(result[1].properties.is_internet_exposed).toBe(false);
  });

  it('keeps the last value when the network stages failed', () => {
    // Without subnets and internet gateways, a resource exposed only through a
    // public subnet would derive as unexposed.
    const nodes: GraphNode[] = [
      node('Ec2Instance', { id: 'i-1', public_ip: '1.2.3.4' }),
      node('RdsInstance', { id: 'db-1', subnet_id: 'subnet-1' }),
    ];
    const ctx = {
      publicSubnetIds: new Set<string>(),
      subnetVpcIds: new Map<string, string>(),
      vpcHasIgw: new Map<string, boolean>(),
    };
    const result = applyExposureToNodes(nodes, ctx, false);
    expect(result[0].properties.is_internet_exposed).toBe(true);
    expect(result[1]).toEqual(nodes[1]);
  });

  it('leaves non-exposable labels untouched', () => {
    const nodes: GraphNode[] = [node('KmsKey', { id: 'kms-1' })];
    const ctx = {
      publicSubnetIds: new Set<string>(),
      subnetVpcIds: new Map<string, string>(),
      vpcHasIgw: new Map<string, boolean>(),
    };
    const result = applyExposureToNodes(nodes, ctx, true);
    expect(result[0]).toEqual(nodes[0]);
  });
});
