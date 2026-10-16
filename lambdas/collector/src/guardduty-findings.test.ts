import { GuardDutyClient, type Finding } from '@aws-sdk/client-guardduty';
import {
  buildFindingGraph,
  buildRegionFindingGraph,
  collectRegionFindings,
  findingTargets,
  guardDutyFindingsScope,
  severityLabel,
} from './guardduty-findings';
import { collectGuardDutyFindings } from './guardduty-sweep';
import type { GraphMutationBatch } from '../../shared/graph-batch-writer';

const ADMIN = '058264196729';
const MEMBER = '637423636046';

function createMockClient(responses: {
  [commandName: string]: (input: Record<string, unknown>) => unknown;
}) {
  const send = jest.fn(async (command: { constructor: { name: string } }) => {
    const handler = responses[command.constructor.name];
    if (!handler) throw new Error(`Unexpected command in test: ${command.constructor.name}`);
    return handler((command as unknown as { input: Record<string, unknown> }).input || {});
  });
  return { send } as unknown as GuardDutyClient & { send: jest.Mock };
}

// The shape GetFindings returns for an EC2 brute-force finding, trimmed.
function sshBruteForce(overrides: Partial<Finding> = {}): Finding {
  return {
    Id: 'f-ssh',
    AccountId: MEMBER,
    Region: 'eu-west-2',
    Arn: `arn:aws:guardduty:eu-west-2:${ADMIN}:detector/d1/finding/f-ssh`,
    Type: 'UnauthorizedAccess:EC2/SSHBruteForce',
    Severity: 5,
    Title: 'SSH brute force',
    CreatedAt: '2026-09-29T00:00:00.000Z',
    UpdatedAt: '2026-09-30T00:00:00.000Z',
    SchemaVersion: '2.0',
    Partition: 'aws',
    Resource: { ResourceType: 'Instance', InstanceDetails: { InstanceId: 'i-0abc' } },
    Service: {
      Archived: false,
      Count: 42,
      EventFirstSeen: '2026-09-29T00:00:00.000Z',
      EventLastSeen: '2026-09-30T00:00:00.000Z',
      Action: {
        ActionType: 'NETWORK_CONNECTION',
        NetworkConnectionAction: {
          RemoteIpDetails: {
            IpAddressV4: '203.0.113.9',
            Organization: { Asn: '64500', AsnOrg: 'Example Net' },
            Country: { CountryName: 'Nowhere' },
          },
        },
      },
    },
    ...overrides,
  } as Finding;
}

describe('buildFindingGraph', () => {
  it('writes the member account and region the finding describes, not the administrator', () => {
    const built = buildFindingGraph(sshBruteForce(), 'us-west-2')!;

    expect(built.node.label).toBe('GuardDutyFinding');
    expect(built.node.properties).toMatchObject({
      account_id: MEMBER,
      region: 'eu-west-2',
      type: 'UnauthorizedAccess:EC2/SSHBruteForce',
      finding_class: 'UnauthorizedAccess',
      severity: 5,
      severity_label: 'MEDIUM',
      remote_ip: '203.0.113.9',
      remote_asn: '64500',
      count: 42,
      archived: false,
    });
  });

  // Neptune properties must be scalars; an object is stringified and unqueryable.
  it('writes only scalar properties', () => {
    const { node } = buildFindingGraph(sshBruteForce(), 'us-west-2')!;
    for (const value of Object.values(node.properties)) {
      expect(['string', 'number', 'boolean', 'undefined']).toContain(typeof value);
    }
  });

  it('links DETECTS_ON to the instance vertex id the collector writes', () => {
    const { edges } = buildFindingGraph(sshBruteForce(), 'us-west-2')!;

    expect(edges).toEqual([
      {
        from: `arn:aws:guardduty:eu-west-2:${ADMIN}:detector/d1/finding/f-ssh`,
        to: `arn:aws:ec2:eu-west-2:${MEMBER}:instance/i-0abc`,
        label: 'DETECTS_ON',
      },
    ]);
  });

  it('reads the attacker from a port probe', () => {
    const finding = sshBruteForce({
      Service: {
        Action: {
          PortProbeAction: {
            PortProbeDetails: [{ RemoteIpDetails: { IpAddressV4: '198.51.100.7' } }],
          },
        },
      },
    });
    expect(buildFindingGraph(finding, 'us-west-2')!.node.properties.remote_ip).toBe('198.51.100.7');
  });

  it('records the domain of a DNS finding, which has no remote IP', () => {
    const finding = sshBruteForce({
      Type: 'UnauthorizedAccess:EC2/MetadataDNSRebind',
      Service: {
        Action: { ActionType: 'DNS_REQUEST', DnsRequestAction: { Domain: 'rebind.example' } },
      },
    });
    const { properties } = buildFindingGraph(finding, 'us-west-2')!.node;
    expect(properties.remote_domain).toBe('rebind.example');
    expect(properties.remote_ip).toBeUndefined();
  });

  it('skips a finding with no id or account', () => {
    expect(
      buildFindingGraph({ ...sshBruteForce(), AccountId: undefined }, 'us-west-2')
    ).toBeUndefined();
  });
});

describe('findingTargets', () => {
  it.each([
    [
      'RDS',
      { RdsDbInstanceDetails: { DbInstanceIdentifier: 'orders' } },
      [`arn:aws:rds:eu-west-2:${MEMBER}:db:orders`],
    ],
    [
      'EKS',
      { EksClusterDetails: { Name: 'prod' } },
      [`arn:aws:eks:eu-west-2:${MEMBER}:cluster/prod`],
    ],
    [
      'S3',
      { S3BucketDetails: [{ Name: 'b1' }, { Name: 'b2' }] },
      ['arn:aws:s3:::b1', 'arn:aws:s3:::b2'],
    ],
    [
      'IAM user',
      { AccessKeyDetails: { UserName: 'alice', UserType: 'IAMUser' } },
      [`arn:aws:iam::${MEMBER}:user/alice`],
    ],
    ['root', { AccessKeyDetails: { UserName: 'Root', UserType: 'Root' } }, []],
  ])('maps %s resources', (_label, resource, expected) => {
    expect(findingTargets({ Resource: resource } as Finding, MEMBER, 'eu-west-2')).toEqual(
      expected
    );
  });
});

describe('severityLabel', () => {
  it.each([
    [2, 'LOW'],
    [4, 'MEDIUM'],
    [7, 'HIGH'],
    [8.9, 'HIGH'],
    [9, 'CRITICAL'],
    [undefined, undefined],
  ])('%s -> %s', (severity, label) => {
    expect(severityLabel(severity)).toBe(label);
  });
});

describe('collectRegionFindings', () => {
  it('lists unarchived findings, fetches them in batches of 50, and drops any archived since', async () => {
    const ids = Array.from({ length: 60 }, (_, i) => `f-${i}`);
    const client = createMockClient({
      ListDetectorsCommand: () => ({ DetectorIds: ['d1'] }),
      ListFindingsCommand: (input) =>
        input.NextToken
          ? { FindingIds: ids.slice(50) }
          : { FindingIds: ids.slice(0, 50), NextToken: 'page-2' },
      GetFindingsCommand: (input) => ({
        Findings: (input.FindingIds as string[]).map((id) =>
          sshBruteForce({ Id: id, Arn: `arn:${id}`, Service: { Archived: id === 'f-59' } })
        ),
      }),
    });

    const result = await collectRegionFindings(client, 'eu-west-2');

    expect(result?.findings).toHaveLength(59);
    const listCall = client.send.mock.calls.find(
      ([c]) => c.constructor.name === 'ListFindingsCommand'
    )!;
    expect(listCall[0].input.FindingCriteria).toEqual({
      Criterion: { 'service.archived': { Equals: ['false'] } },
    });
    const batches = client.send.mock.calls
      .filter(([c]) => c.constructor.name === 'GetFindingsCommand')
      .map(([c]) => c.input.FindingIds.length);
    expect(batches).toEqual([50, 10]);
  });

  it('returns undefined when the region has no detector', async () => {
    const client = createMockClient({ ListDetectorsCommand: () => ({ DetectorIds: [] }) });
    await expect(collectRegionFindings(client, 'sa-east-1')).resolves.toBeUndefined();
  });
});

describe('buildRegionFindingGraph', () => {
  it('writes a finding once even if the API returns it twice', () => {
    const graph = buildRegionFindingGraph([sshBruteForce(), sshBruteForce()], 'eu-west-2');
    expect(graph.nodes).toHaveLength(1);
    expect(graph.edges).toHaveLength(1);
  });
});

describe('collectGuardDutyFindings', () => {
  function recordingWriter() {
    const batches: GraphMutationBatch[] = [];
    const write = jest.fn(async (batch: GraphMutationBatch) => {
      batches.push(batch);
      return {
        success: true as const,
        written: batch.nodes.length + batch.edges.length,
        skipped: 0,
        tombstoned: 0,
      };
    });
    return { batches, write };
  }

  it('scopes each region on its own and reconciles without an account id', async () => {
    const { batches, write } = recordingWriter();
    const client = createMockClient({
      ListDetectorsCommand: () => ({ DetectorIds: ['d1'] }),
      ListFindingsCommand: () => ({ FindingIds: ['f-ssh'] }),
      GetFindingsCommand: () => ({ Findings: [sshBruteForce()] }),
    });

    const results = await collectGuardDutyFindings(
      { administratorAccountId: ADMIN, regions: ['eu-west-2'] },
      { client: async () => client, write }
    );

    expect(results).toEqual([
      expect.objectContaining({ region: 'eu-west-2', status: 'SUCCEEDED', findings: 1 }),
    ]);
    const node = batches.flatMap((b) => b.nodes)[0];
    expect(node.properties).toMatchObject({
      account_id: MEMBER,
      collection_scope: guardDutyFindingsScope('eu-west-2'),
      collection_region: 'eu-west-2',
    });
    const reconcile = batches.find((b) => b.reconcile)?.reconcile;
    expect(reconcile).toMatchObject({ scope: 'guardduty-findings:eu-west-2', region: 'eu-west-2' });
    expect(reconcile?.accountId).toBeUndefined();
  });

  // All findings archived: nothing to write, but the old ones must still go.
  it('still reconciles a region with no active findings', async () => {
    const { batches, write } = recordingWriter();
    const client = createMockClient({
      ListDetectorsCommand: () => ({ DetectorIds: ['d1'] }),
      ListFindingsCommand: () => ({ FindingIds: [] }),
    });

    await collectGuardDutyFindings(
      { administratorAccountId: ADMIN, regions: ['eu-west-2'] },
      { client: async () => client, write }
    );

    expect(batches.filter((b) => b.reconcile)).toHaveLength(1);
  });

  // Without a complete read there is nothing to reconcile against, so a failed
  // region keeps its previous findings, and the next region still runs.
  it('neither writes nor reconciles a failed region, and carries on', async () => {
    const { batches, write } = recordingWriter();
    const good = createMockClient({
      ListDetectorsCommand: () => ({ DetectorIds: ['d1'] }),
      ListFindingsCommand: () => ({ FindingIds: [] }),
    });
    const bad = createMockClient({
      ListDetectorsCommand: () => {
        throw Object.assign(new Error('denied'), { name: 'AccessDeniedException' });
      },
    });

    const results = await collectGuardDutyFindings(
      { administratorAccountId: ADMIN, regions: ['us-east-1', 'eu-west-2'] },
      { client: async (region) => (region === 'us-east-1' ? bad : good), write }
    );

    expect(results.map((r) => r.status)).toEqual(['FAILED', 'SUCCEEDED']);
    expect(batches.every((b) => b.reconcile?.region !== 'us-east-1')).toBe(true);
  });

  it('writes nothing for a region with no detector', async () => {
    const { write } = recordingWriter();
    const client = createMockClient({ ListDetectorsCommand: () => ({ DetectorIds: [] }) });

    const [result] = await collectGuardDutyFindings(
      { administratorAccountId: ADMIN, regions: ['sa-east-1'] },
      { client: async () => client, write }
    );

    expect(result.status).toBe('NO_DETECTOR');
    expect(write).not.toHaveBeenCalled();
  });
});
