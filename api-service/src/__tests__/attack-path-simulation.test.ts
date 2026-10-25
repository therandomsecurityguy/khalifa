import type { Request, Response } from 'express';

const executeStaticQuery = jest.fn();

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({ executeStaticQuery }),
}));

let route: typeof import('../routes/attack-paths');

const T_ID = { elementName: 'id' };
const T_LABEL = { elementName: 'label' };

// One element as the gremlin driver deserializes `valueMap(true, …)`.
function element(
  id: string,
  label: string,
  props: Record<string, unknown> = {}
): Map<unknown, unknown> {
  const entry = new Map<unknown, unknown>([
    [T_ID, id],
    [T_LABEL, label],
  ]);
  for (const [key, value] of Object.entries(props)) entry.set(key, [value]);
  return entry;
}

function call(query: Record<string, unknown>, groups: string[] = ['khalifa-viewer']) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  const req = { query, user: { sub: 's', email: 'viewer@example.com', groups, tokenUse: 'id' } };
  return route.simulateAttackPaths(req as unknown as Request, res as Response).then(() => res);
}

// internet -> role (admin) -> crown jewel, with two alternative second hops.
function twoHopPaths(): unknown[] {
  const exposedEdge = element('edge-expose', 'HAS_IAM_ROLE');
  const crownEdge = element('edge-crown', 'GRANTS');
  const altEdge = element('edge-alt', 'GRANTS');
  const head = [
    element('ec2', 'Ec2Instance', { is_internet_exposed: true }),
    exposedEdge,
    element('role', 'IamRole', { is_admin: true }),
  ];
  return [
    [...head, crownEdge, element('bucket', 'S3Bucket', { crown_jewel: true })],
    [...head, altEdge, element('table', 'DynamoDBTable', { crown_jewel: true })],
    [...head],
  ];
}

describe('GET /attack-paths/simulate', () => {
  beforeAll(async () => {
    route = await import('../routes/attack-paths');
  });
  beforeEach(() => jest.clearAllMocks());

  it('rejects an unknown rule without querying the graph', async () => {
    const res = await call({ ruleId: 'RULE-999' });
    expect(res.statusCode).toBe(400);
    expect(executeStaticQuery).not.toHaveBeenCalled();
  });

  it('ranks each edge by how many matched paths it clears', async () => {
    executeStaticQuery.mockResolvedValue(twoHopPaths());

    const res = await call({ ruleId: 'RULE-005' });

    expect(executeStaticQuery).toHaveBeenCalledWith(expect.stringContaining('crown_jewel'));
    expect(res.body.ruleId).toBe('RULE-005');
    expect(res.body.totalPaths).toBe(3);
    expect(res.body.truncated).toBe(false);
    // Equal counts keep insertion order: the first path's second hop, then the
    // alternative one.
    expect(res.body.edges.map((edge: any) => edge.id)).toEqual([
      'edge-expose',
      'edge-crown',
      'edge-alt',
    ]);
    expect(res.body.edges[0]).toMatchObject({
      label: 'HAS_IAM_ROLE',
      from: 'ec2',
      to: 'role',
      pathsUsing: 3,
      remainingPaths: 0,
    });
    expect(res.body.edges[1]).toMatchObject({ pathsUsing: 1, remainingPaths: 2 });
    for (const edge of res.body.edges) {
      expect(edge.worstLikelihood).toBeGreaterThan(0);
      expect(edge.worstLikelihood).toBeLessThanOrEqual(1);
    }
  });

  it('deduplicates identical paths and caps the result set', async () => {
    const rows = twoHopPaths();
    executeStaticQuery.mockResolvedValue([...rows, ...rows]);
    const deduped = await call({ ruleId: 'RULE-005' });
    expect(deduped.body.totalPaths).toBe(3);

    const many = Array.from({ length: 201 }, (_, index) => [
      element(`ec2-${index}`, 'Ec2Instance', { is_internet_exposed: true }),
      element(`edge-${index}`, 'GRANTS'),
      element('bucket', 'S3Bucket'),
    ]);
    executeStaticQuery.mockResolvedValue(many);
    const capped = await call({ ruleId: 'RULE-005' });
    expect(capped.body.truncated).toBe(true);
    expect(capped.body.totalPaths).toBe(200);
  });

  it('answers 504 when the rule query times out, like the search', async () => {
    executeStaticQuery.mockRejectedValue(new Error('timeout after 5000ms'));
    const res = await call({ ruleId: 'RULE-005' });
    expect(res.statusCode).toBe(504);
    expect(res.body.code).toBe('SEARCH_TIMEOUT');
  });

  it('answers 500 on any other failure', async () => {
    executeStaticQuery.mockRejectedValue(new Error('boom'));
    const res = await call({ ruleId: 'RULE-005' });
    expect(res.statusCode).toBe(500);
  });
});
