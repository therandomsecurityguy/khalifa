import type { Request, Response } from 'express';
import type { GraphVertex } from '../types';

const searchAttackPaths = jest.fn();
const getTrustedPrincipals = jest.fn();

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({ searchAttackPaths, getTrustedPrincipals }),
}));

let route: typeof import('../routes/attack-paths');

const v = (id: string, label: string, props: Record<string, unknown> = {}): GraphVertex => ({
  id,
  label,
  properties: { account_id: '111122223333', ...props },
});

function call(query: Record<string, unknown>, groups: string[] = ['khalifa-analyst']) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  const req = { query, user: { sub: 's', email: 'analyst@example.com', groups, tokenUse: 'id' } };
  return route.searchAttackPaths(req as unknown as Request, res as Response).then(() => res);
}

describe('GET /attack-paths/search', () => {
  beforeAll(async () => {
    route = await import('../routes/attack-paths');
  });
  beforeEach(() => {
    jest.clearAllMocks();
    getTrustedPrincipals.mockResolvedValue([]);
  });

  it('accepts only the preset starts and targets and a 12-digit account', async () => {
    for (const query of [
      { from: 'IamRole', to: 'restricted' },
      { from: 'any', to: "S3Bucket').drop()" },
      { to: 'restricted', account: '123' },
    ]) {
      expect((await call(query)).statusCode).toBe(400);
    }
    expect(searchAttackPaths).not.toHaveBeenCalled();
  });

  it('counts a policy chain as one hop and searches deep enough to find it', async () => {
    const ec2 = v('i', 'Ec2Instance', { is_internet_exposed: true });
    const chain = [
      ec2,
      v('r', 'IamRole'),
      v('p', 'IamPolicyDocument'),
      v('s', 'IamPolicyStatement'),
      v('b', 'S3Bucket'),
    ];
    const tooLong = [...chain, v('x', 'Secret')];
    searchAttackPaths.mockResolvedValue([
      { nodes: chain, edges: [] },
      { nodes: tooLong, edges: [] },
    ]);

    const res = await call({ from: 'internet', to: 'restricted', maxPathLength: '2' });

    expect(searchAttackPaths).toHaveBeenCalledWith(
      expect.objectContaining({ from: 'internet', to: 'restricted', maxPathLength: 8, limit: 50 })
    );
    expect(res.body.paths).toEqual([
      expect.objectContaining({ nodes: chain, edges: [], severity: expect.any(String) }),
    ]);
    expect(res.body.entries).toEqual({ i: { kind: 'internet' } });
    expect(res.body.truncated).toBe(false);
  });

  it('counts a managed-policy chain (policy, document, statement) as one hop', async () => {
    const managed = [
      v('i', 'Ec2Instance', { is_internet_exposed: true }),
      v('r', 'IamRole'),
      v('mp', 'IamPolicy'),
      v('doc', 'IamPolicyDocument'),
      v('s', 'IamPolicyStatement'),
      v('b', 'S3Bucket'),
    ];
    searchAttackPaths.mockResolvedValue([{ nodes: managed, edges: [] }]);
    const res = await call({ from: 'internet', to: 'restricted', maxPathLength: '2' });
    expect(res.body.paths).toHaveLength(1);
    expect(route.drawnHops({ nodes: managed })).toBe(2);
  });

  it('scopes to an account inside the query and keeps the collector Internet vertex as the entry', async () => {
    const internet = v('arn:aws:khalifa:global:internet', 'Internet', {
      is_internet_exposed: true,
    });
    searchAttackPaths.mockResolvedValue([
      { nodes: [internet, v('lb', 'LoadBalancer')], edges: [] },
    ]);
    const res = await call({ to: 'crown', account: '111122223333' });
    for (const from of ['internet', 'outside']) {
      expect(searchAttackPaths).toHaveBeenCalledWith(
        expect.objectContaining({ from, to: 'crown', account: '111122223333' })
      );
    }
    expect(res.body.paths).toHaveLength(1);
    expect(res.body.entries).toEqual({});
  });

  it('answers "any" from the internet and outside searches, merged without duplicates', async () => {
    const exposed = { nodes: [v('i', 'Ec2Instance', { is_internet_exposed: true })], edges: [] };
    const trusted = { nodes: [v('r', 'IamRole', { has_cross_account_trust: true })], edges: [] };
    searchAttackPaths.mockImplementation(async ({ from }: { from: string }) =>
      from === 'internet' ? [exposed, trusted] : [trusted]
    );
    const res = await call({ from: 'any', to: 'admin' });
    expect(searchAttackPaths).toHaveBeenCalledTimes(2);
    expect(res.body.paths.map((p: { nodes: GraphVertex[] }) => p.nodes[0].id).sort()).toEqual([
      'i',
      'r',
    ]);
    expect(res.body.truncated).toBe(false);
  });

  it('keeps the other search when one times out, and marks the result truncated', async () => {
    const exposed = { nodes: [v('i', 'Ec2Instance', { is_internet_exposed: true })], edges: [] };
    searchAttackPaths.mockImplementation(async ({ from }: { from: string }) => {
      if (from === 'outside') throw new Error('Neptune query timeout after 5000ms');
      return [exposed];
    });
    const res = await call({ from: 'any', to: 'admin' });
    expect(res.statusCode).toBe(200);
    expect(res.body.paths).toHaveLength(1);
    expect(res.body.truncated).toBe(true);
  });

  it('returns 504 when every search times out and 500 for any other failure', async () => {
    searchAttackPaths.mockRejectedValue(new Error('TimeLimitExceededException: query timed out'));
    expect((await call({ from: 'any', to: 'admin' })).statusCode).toBe(504);

    searchAttackPaths.mockImplementation(async ({ from }: { from: string }) => {
      if (from === 'outside') throw new Error('MalformedQueryException');
      return [];
    });
    expect((await call({ from: 'any', to: 'admin' })).statusCode).toBe(500);
  });

  it('flags results cut off at the limit', async () => {
    const path = { nodes: [v('i', 'Ec2Instance')], edges: [] };
    searchAttackPaths.mockResolvedValue([path, path]);
    const res = await call({ to: 'crown', limit: '2' });
    expect(res.body.truncated).toBe(true);
  });

  it('keeps an outside entry for a trusted role whose principals are not found', async () => {
    const role = v('r', 'IamRole', { has_cross_account_trust: true });
    searchAttackPaths.mockResolvedValue([{ nodes: [role], edges: [] }]);
    const res = await call({ from: 'outside', to: 'admin' });
    expect(res.body.entries).toEqual({ r: { kind: 'trust', principals: [] } });
  });

  it('caps Viewers at four hops', async () => {
    const res = await call({ to: 'secrets', maxPathLength: '5' }, ['khalifa-viewer']);
    expect(res.statusCode).toBe(400);
  });

  it('scores every path like the rule runner and returns the worst first', async () => {
    const mild = [v('a', 'IamRole'), v('b', 'S3Bucket')];
    const severe = [
      v('i', 'Ec2Instance', { is_internet_exposed: true, env: 'prod' }),
      v('r', 'IamRole', { is_admin_role: true }),
      v('s', 'S3Bucket', { data_classification: 'restricted', crown_jewel: true }),
    ];
    searchAttackPaths.mockResolvedValue([
      { nodes: mild, edges: [] },
      { nodes: severe, edges: [] },
    ]);
    const res = await call({ to: 'restricted' });
    expect(res.body.paths.map((p: any) => p.nodes[0].id)).toEqual(['i', 'a']);
    expect(res.body.paths[0].severity).toBe('critical');
    expect(res.body.paths[0].score).toBeGreaterThan(res.body.paths[1].score);
  });

  it('starts or ends at a specific vertex only with a valid id', async () => {
    searchAttackPaths.mockResolvedValue([]);
    const bucket = 'arn:aws:s3:::payments-exports';
    await call({ from: 'resource', fromResource: bucket, to: 'admin' });
    await call({ to: 'resource', toResource: bucket });
    expect(searchAttackPaths).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({ from: 'resource', fromResource: bucket })
    );
    expect(searchAttackPaths).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({ to: 'resource', toResource: bucket })
    );
    for (const query of [
      { from: 'resource', to: 'admin' },
      { to: 'resource' },
      { to: 'resource', toResource: 'S3Bucket' },
      { to: 'admin', toResource: bucket },
    ]) {
      expect((await call(query)).statusCode).toBe(400);
    }
  });

  it('caps a caller with only a verified email (no group) at four hops', async () => {
    const res: any = { statusCode: 200 };
    res.status = (code: number) => Object.assign(res, { statusCode: code });
    res.json = (body: unknown) => Object.assign(res, { body });
    const req = {
      query: { to: 'crown', maxPathLength: '5' },
      user: { sub: 's', email: 'viewer@example.com', groups: [], tokenUse: 'id' },
    };
    await route.searchAttackPaths(req as unknown as Request, res as Response);
    expect(res.statusCode).toBe(400);
    expect(searchAttackPaths).not.toHaveBeenCalled();
  });
});
