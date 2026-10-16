import Gremlin from 'gremlin';
import { extractVertex, NeptuneClient } from '../services/neptune-client';

function rawVertex(id: string, label: string, properties: Record<string, unknown> = {}) {
  return new Map<unknown, unknown>([
    [Gremlin.process.t.id, id],
    [Gremlin.process.t.label, label],
    ...Object.entries(properties),
  ]);
}

function runtime(results: unknown[][]) {
  return {
    connect: jest.fn().mockResolvedValue(undefined),
    close: jest.fn().mockResolvedValue(undefined),
    execute: jest.fn().mockImplementation(async () => results.shift() || []),
  };
}

describe('API Neptune queries', () => {
  it('lists vertex labels with counts, biggest first', async () => {
    const shared = runtime([
      [
        new Map<unknown, unknown>([
          ['IamRole', 356],
          ['S3Bucket', 1204],
          ['Internet', 0],
        ]),
      ],
    ]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await expect(graph.listResourceLabels()).resolves.toEqual([
      { label: 'S3Bucket', count: 1204 },
      { label: 'IamRole', count: 356 },
    ]);
    expect(String(shared.execute.mock.calls[0][0])).toContain('groupCount');
  });

  it("lists a label's property keys from a sample, sorted", async () => {
    const shared = runtime([['name', 'account_id', 'is_admin_role']]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await expect(graph.listResourceProperties('IamRole')).resolves.toEqual([
      'account_id',
      'is_admin_role',
      'name',
    ]);
    expect(String(shared.execute.mock.calls[0][0])).toContain('IamRole');
  });

  it('lists the most common values of a property and says when there are more', async () => {
    const counts = new Map<unknown, unknown>(
      Array.from({ length: 52 }, (_, i) => [`v${i}`, i + 1] as [string, number])
    );
    counts.set(true, 500);
    const shared = runtime([[counts]]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    const result = await graph.listPropertyValues('IamRole', 'is_admin_role');
    expect(result.more).toBe(true);
    expect(result.values).toHaveLength(50);
    expect(result.values[0]).toEqual({ value: 'true', count: 500 });
  });

  it('matches a filter value as text and as its boolean or number', async () => {
    const shared = runtime([[], [], []]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await graph.searchResources({
      label: 'IamRole',
      property: 'is_admin_role',
      value: 'true',
      limit: 5,
    });
    await graph.searchResources({
      label: 'Ec2Instance',
      property: 'key_age_days',
      value: '120',
      limit: 5,
    });
    await graph.searchResources({
      label: 'IamRole',
      property: 'account_id',
      value: '111122223333',
      limit: 5,
    });

    const [bool, number, account] = shared.execute.mock.calls.map((call) => String(call[0]));
    expect(bool).toMatch(/within.*true.*true/);
    expect(number).toMatch(/within.*120.*120/);
    expect(account).toContain('111122223333');
  });

  it('serves all-label properties and values without scanning the graph', async () => {
    const shared = runtime([
      [
        new Map<unknown, unknown>([
          ['id', '111122223333'],
          ['name', 'prod'],
        ]),
      ],
    ]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    expect(await graph.listResourceProperties('*')).toContain('account_id');
    expect(await graph.listPropertyValues('*', 'env')).toEqual({
      values: [
        { value: 'prod', count: 0 },
        { value: 'staging', count: 0 },
        { value: 'dev', count: 0 },
      ],
      more: false,
    });
    expect(await graph.listPropertyValues('*', 'owner')).toEqual({ values: [], more: true });
    expect(shared.execute).not.toHaveBeenCalled();

    expect(await graph.listPropertyValues('*', 'account_id')).toEqual({
      values: [{ value: '111122223333', count: 0, name: 'prod' }],
      more: false,
    });
  });

  it('searches every label when the label is *', async () => {
    const shared = runtime([[]]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await graph.searchResources({ label: '*', property: 'env', value: 'prod', limit: 5 });
    expect(String(shared.execute.mock.calls[0][0])).not.toContain('hasLabel');
  });

  it('browses every label in name order, one label query at a time', async () => {
    const v = (label: string, arn: string) => rawVertex(arn, label, { arn });
    const shared = runtime([
      [v('IamRole', 'arn:r1'), v('IamRole', 'arn:r2')],
      [v('Kms', 'arn:k1'), v('Kms', 'arn:k2')],
      [v('Kms', 'arn:k2')],
      [v('S3Bucket', 'arn:s1')],
    ]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });
    const labels = ['S3Bucket', 'IamRole', 'Kms'];

    const first = await graph.browseAllLabels({ labels, limit: 3 });
    expect(first.resources.map((r) => r.id)).toEqual(['arn:r1', 'arn:r2', 'arn:k1']);
    const second = await graph.browseAllLabels({ labels, limit: 3, nextToken: first.nextToken });
    expect(second.resources.map((r) => r.id)).toEqual(['arn:k2', 'arn:s1']);
    expect(second.nextToken).toBeUndefined();

    const queries = shared.execute.mock.calls.map((call) => String(call[0]));
    expect(queries.map((q) => q.match(/"hasLabel","(\w+)"/)?.[1])).toEqual([
      'IamRole',
      'Kms',
      'Kms',
      'S3Bucket',
    ]);
    expect(queries[2]).toContain('arn:k1');
    await expect(
      graph.browseAllLabels({ labels: ['IamRole'], limit: 3, nextToken: first.nextToken })
    ).rejects.toThrow('Invalid pagination token');
  });

  it("reads a job's output count and newest timestamp, and null when there is none", async () => {
    const shared = runtime([
      [
        new Map<unknown, unknown>([
          ['count', 12],
          ['latest', '2026-10-06T10:05:00Z'],
        ]),
      ],
      [
        new Map<unknown, unknown>([
          ['count', 0],
          ['latest', ''],
        ]),
      ],
    ]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await expect(graph.latestOutput('GuardDutyFinding', 'source_updated_at')).resolves.toEqual({
      count: 12,
      latest: '2026-10-06T10:05:00Z',
    });
    await expect(graph.latestOutput('CloudTrailAnomaly', 'source_updated_at')).resolves.toEqual({
      count: 0,
      latest: null,
    });
  });

  it('submits dynamic values as bytecode through the shared runtime', async () => {
    const arn = 'arn:aws:iam::123456789012:role/team/Admin';
    const shared = runtime([[rawVertex('role-1', 'IamRole', { arn })]]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await expect(graph.getResource(arn)).resolves.toEqual({
      id: 'role-1',
      label: 'IamRole',
      properties: { arn },
    });

    expect(typeof shared.execute.mock.calls[0][0]).not.toBe('string');
    expect(String(shared.execute.mock.calls[0][0])).toContain(arn);
  });

  it('uses a keyset cursor instead of an unbounded range', async () => {
    const row = (id: string) =>
      new Map([
        ['edge', rawVertex(id, 'TRUSTS')],
        ['from', rawVertex('one', 'AwsAccount')],
        ['to', rawVertex('two', 'AwsAccount')],
      ]);
    const shared = runtime([[row('edge-1'), row('edge-2')], []]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    const page = await graph.getTrustGraph({ limit: 1 });
    await graph.getTrustGraph({ limit: 1, nextToken: page.nextToken });

    expect(page.nextToken).toEqual(expect.any(String));
    expect(String(shared.execute.mock.calls[1][0])).toContain('edge-1');
    expect(String(shared.execute.mock.calls[1][0])).not.toContain('range');
  });

  it('bounds attack-path search with a loops() guard inside a single repeat', async () => {
    const shared = runtime([[], []]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await graph.searchAttackPaths({ from: 'internet', to: 'crown', maxPathLength: 6, limit: 10 });
    await graph.searchAttackPaths({
      from: 'resource',
      fromResource: 'arn:aws:iam::111122223333:role/app',
      to: 'restricted',
      maxPathLength: 4,
      limit: 10,
    });

    for (const call of shared.execute.mock.calls) {
      const bytecode = String(call[0]);
      expect(bytecode).toContain('loops');
      expect(bytecode).not.toContain('times');
    }
  });

  it('rejects non-traversal static queries', async () => {
    const shared = runtime([]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await expect(graph.executeStaticQuery('1 + 1')).rejects.toThrow('rooted at g');
    expect(shared.execute).not.toHaveBeenCalled();
  });

  it('unwraps GraphBinary token keys and cardinality lists', () => {
    expect(extractVertex(rawVertex('id', 'IamRole', { arn: ['arn:example'] }))).toEqual({
      id: 'id',
      label: 'IamRole',
      properties: { arn: 'arn:example' },
    });
  });

  it('keeps the T.id ARN when the vertex also has an id property', () => {
    const arn = 'arn:aws:iam::123456789012:role/Admin';
    expect(
      extractVertex(rawVertex(arn, 'IamRole', { id: ['Admin'], label: ['custom'], arn: [arn] }))
    ).toEqual({
      id: arn,
      label: 'IamRole',
      properties: { id: 'Admin', label: 'custom', arn },
    });
    expect(extractVertex({ id: arn, label: 'IamRole', arn })).toEqual({
      id: arn,
      label: 'IamRole',
      properties: { arn },
    });
  });

  it('reads effective permissions by their deterministic id', async () => {
    const arn = 'arn:aws:iam::123456789012:role/Admin';
    const shared = runtime([
      [
        rawVertex(`eff-perm:${arn}`, 'EffectivePermission', {
          principal_arn: arn,
          is_admin: false,
        }),
      ],
    ]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    const permission = await graph.getEffectivePermissions(arn);

    const bytecode = String(shared.execute.mock.calls[0][0]);
    expect(bytecode).toContain(JSON.stringify(['V', `eff-perm:${arn}`]));
    expect(bytecode).not.toContain('"has","principal_arn"');
    expect(permission).toMatchObject({ principal_arn: arn });
  });

  it('looks resources and neighbours up by vertex id, not by a property scan', async () => {
    const arn = 'arn:aws:iam::123456789012:role/Admin';
    const shared = runtime([[rawVertex(arn, 'IamRole', { arn })], []]);
    const graph = new NeptuneClient({ endpoint: 'cluster.example.com' }, { runtime: shared });

    await graph.getResource(arn);
    await graph.getNeighbors(arn);

    for (const call of shared.execute.mock.calls) {
      const bytecode = String(call[0]);
      expect(bytecode).toContain(`["V","${arn}"]`);
      expect(bytecode).not.toContain('"has","arn"');
    }
  });
});
