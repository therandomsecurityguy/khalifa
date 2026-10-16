import { buildNetworkAclEntries, collectSecurityGroups, normalizeAclProtocol } from './network';

const ACCOUNT = '111122223333';
const REGION = 'us-west-2';
const SG_ARN = `arn:aws:ec2:${REGION}:${ACCOUNT}:security-group/sg-1`;

function ec2With(securityGroups: any[]): any {
  const send = jest.fn(async (command: { constructor: { name: string }; input: any }) => {
    if (command.constructor.name !== 'DescribeSecurityGroupsCommand') {
      throw new Error(`Unexpected command: ${command.constructor.name}`);
    }
    if (command.input.NextToken) return { SecurityGroups: [] };
    return { SecurityGroups: securityGroups };
  });
  return { send };
}

function sshPermission(overrides: Record<string, unknown>): any {
  return { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, ...overrides };
}

describe('collectSecurityGroups IPv6 exposure', () => {
  it('marks a group open only to ::/0 as world-open', async () => {
    const { nodes } = await collectSecurityGroups(
      ec2With([
        {
          GroupId: 'sg-1',
          GroupName: 'ipv6-ssh',
          VpcId: 'vpc-1',
          IpPermissions: [sshPermission({ Ipv6Ranges: [{ CidrIpv6: '::/0' }] })],
        },
      ]),
      ACCOUNT,
      REGION,
      new Map()
    );

    const group = nodes.find((node) => node.label === 'SecurityGroup');
    expect(group?.properties.is_world_open).toBe(true);

    const rules = nodes.filter((node) => node.label === 'SecurityGroupRule');
    expect(rules).toHaveLength(1);
    expect(rules[0].properties).toMatchObject({
      direction: 'ingress',
      protocol: 'tcp',
      port_from: 22,
      port_to: 22,
      cidr_block: '::/0',
    });
  });

  it('gives the v4 and v6 ranges of one permission distinct vertex ids', async () => {
    const { nodes, edges } = await collectSecurityGroups(
      ec2With([
        {
          GroupId: 'sg-1',
          GroupName: 'dual-stack-ssh',
          VpcId: 'vpc-1',
          IpPermissions: [
            sshPermission({
              IpRanges: [{ CidrIp: '0.0.0.0/0' }],
              Ipv6Ranges: [{ CidrIpv6: '::/0' }],
            }),
          ],
        },
      ]),
      ACCOUNT,
      REGION,
      new Map()
    );

    const rules = nodes.filter((node) => node.label === 'SecurityGroupRule');
    expect(rules.map((rule) => rule.properties.cidr_block).sort()).toEqual(['0.0.0.0/0', '::/0']);

    const ids = rules.map((rule) => rule.id);
    expect(new Set(ids).size).toBe(2);
    expect(edges.filter((edge) => edge.label === 'PART_OF' && edge.to === SG_ARN)).toHaveLength(2);
  });

  it('ignores IPv6 ranges narrower than ::/0', async () => {
    const { nodes } = await collectSecurityGroups(
      ec2With([
        {
          GroupId: 'sg-1',
          GroupName: 'scoped-ipv6',
          VpcId: 'vpc-1',
          IpPermissions: [sshPermission({ Ipv6Ranges: [{ CidrIpv6: '2001:db8::/32' }] })],
        },
      ]),
      ACCOUNT,
      REGION,
      new Map()
    );

    expect(nodes.find((node) => node.label === 'SecurityGroup')?.properties.is_world_open).toBe(
      false
    );
    expect(nodes.filter((node) => node.label === 'SecurityGroupRule')).toHaveLength(0);
  });
});

describe('normalizeAclProtocol', () => {
  it('maps IANA numbers onto the security group vocabulary', () => {
    expect(normalizeAclProtocol('6')).toBe('tcp');
    expect(normalizeAclProtocol('17')).toBe('udp');
    expect(normalizeAclProtocol('1')).toBe('icmp');
    expect(normalizeAclProtocol('-1')).toBe('-1');
  });

  it('defaults a missing protocol to all-protocols', () => {
    expect(normalizeAclProtocol(undefined)).toBe('-1');
  });

  it('passes an unmapped protocol number through unchanged', () => {
    expect(normalizeAclProtocol('47')).toBe('47');
  });
});

describe('buildNetworkAclEntries', () => {
  const ACL_ARN = `arn:aws:ec2:${REGION}:${ACCOUNT}:network-acl/acl-1`;

  function build(entries: any[], associations?: any[]) {
    return buildNetworkAclEntries(
      { NetworkAclId: 'acl-1', Entries: entries, Associations: associations },
      ACL_ARN,
      ACCOUNT,
      REGION
    );
  }

  it('decomposes an entry into a queryable vertex', () => {
    const { nodes, edges } = build([
      {
        RuleNumber: 100,
        Protocol: '6',
        RuleAction: 'allow',
        Egress: false,
        CidrBlock: '0.0.0.0/0',
        PortRange: { From: 22, To: 22 },
      },
    ]);

    expect(nodes).toHaveLength(1);
    expect(nodes[0].label).toBe('NetworkAclEntry');
    expect(nodes[0].properties).toMatchObject({
      network_acl_id: 'acl-1',
      direction: 'ingress',
      rule_number: 100,
      rule_action: 'allow',
      protocol: 'tcp',
      port_from: 22,
      port_to: 22,
      cidr_block: '0.0.0.0/0',
    });
    expect(edges).toEqual([{ from: nodes[0].id, to: ACL_ARN, label: 'PART_OF' }]);
  });

  it('records an all-protocols entry as covering every port', () => {
    const { nodes } = build([
      {
        RuleNumber: 100,
        Protocol: '-1',
        RuleAction: 'allow',
        Egress: false,
        CidrBlock: '0.0.0.0/0',
      },
    ]);

    expect(nodes[0].properties).toMatchObject({ protocol: '-1', port_from: 0, port_to: 0 });
  });

  it('separates ingress and egress entries that share a rule number', () => {
    const { nodes } = build([
      {
        RuleNumber: 100,
        Protocol: '-1',
        RuleAction: 'allow',
        Egress: false,
        CidrBlock: '0.0.0.0/0',
      },
      {
        RuleNumber: 100,
        Protocol: '-1',
        RuleAction: 'allow',
        Egress: true,
        CidrBlock: '0.0.0.0/0',
      },
    ]);

    expect(new Set(nodes.map((node) => node.id)).size).toBe(2);
    expect(nodes.map((node) => node.properties.direction).sort()).toEqual(['egress', 'ingress']);
  });

  it('reads the IPv6 cidr when an entry has no IPv4 one', () => {
    const { nodes } = build([
      { RuleNumber: 101, Protocol: '6', RuleAction: 'deny', Egress: false, Ipv6CidrBlock: '::/0' },
    ]);

    expect(nodes[0].properties).toMatchObject({ cidr_block: '::/0', rule_action: 'deny' });
  });

  it('skips an entry with no rule number', () => {
    expect(build([{ Protocol: '-1', RuleAction: 'allow', CidrBlock: '0.0.0.0/0' }]).nodes).toEqual(
      []
    );
  });
});

describe('buildNetworkAclEntries subnet associations', () => {
  const ACL_ARN = `arn:aws:ec2:${REGION}:${ACCOUNT}:network-acl/acl-1`;

  function build(associations: any[] | undefined) {
    return buildNetworkAclEntries(
      { NetworkAclId: 'acl-1', Entries: [], Associations: associations },
      ACL_ARN,
      ACCOUNT,
      REGION
    );
  }

  it('edges an associated NACL to each subnet that uses it', () => {
    const { edges } = build([
      { NetworkAclAssociationId: 'aclassoc-1', SubnetId: 'subnet-a' },
      { NetworkAclAssociationId: 'aclassoc-2', SubnetId: 'subnet-b' },
    ]);

    expect(edges).toEqual([
      {
        from: ACL_ARN,
        to: `arn:aws:ec2:${REGION}:${ACCOUNT}:subnet/subnet-a`,
        label: 'ASSOCIATED_WITH',
      },
      {
        from: ACL_ARN,
        to: `arn:aws:ec2:${REGION}:${ACCOUNT}:subnet/subnet-b`,
        label: 'ASSOCIATED_WITH',
      },
    ]);
  });

  // A NACL no subnet uses protects nothing. Without this the compliance queries
  // cannot tell it apart from one guarding live traffic.
  it('emits no association edge for an unused NACL', () => {
    expect(build([]).edges).toEqual([]);
    expect(build(undefined).edges).toEqual([]);
  });

  it('skips an association that carries no subnet', () => {
    expect(build([{ NetworkAclAssociationId: 'aclassoc-1' }]).edges).toEqual([]);
  });
});
