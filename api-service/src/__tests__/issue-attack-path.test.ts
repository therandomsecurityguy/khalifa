import type { Request, Response } from 'express';
import type { GraphVertex } from '../types';

const getIssueById = jest.fn();
const getResource = jest.fn();
const getResources = jest.fn();
const getTrustedPrincipals = jest.fn();

jest.mock('@khalifa/risk-engine', () => ({
  DynamoDBIssueRepository: jest.fn().mockImplementation(() => ({ getIssueById })),
  PostureTrendStore: jest.fn(),
}));
jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({ getResource, getResources, getTrustedPrincipals }),
}));

let getIssue: typeof import('../routes/issues').getIssue;

function vertex(id: string, label: string, properties: Record<string, unknown> = {}): GraphVertex {
  return { id, label, properties: { account_id: '111122223333', ...properties } };
}

function response(): Response & { body?: any } {
  const res: any = {};
  res.status = () => res;
  res.json = (body: unknown) => Object.assign(res, { body });
  return res;
}

async function detailFor(pathVertices: GraphVertex[], resourceIds?: string[]) {
  const byId = new Map(pathVertices.map((v) => [v.id, v]));
  getResource.mockImplementation(async (id: string) => byId.get(id) ?? null);
  getIssueById.mockResolvedValue({
    id: 'issue-id',
    ruleId: 'RULE-006',
    pathSummary: resourceIds
      ? []
      : pathVertices.slice(0, -1).map((v, i) => ({
          from: v.id,
          to: pathVertices[i + 1].id,
          edgeType: 'ATTACHED_TO',
        })),
    resourcesInvolved: (resourceIds ?? []).map((resourceId) => ({
      resourceId,
      resourceType: 'S3Bucket',
    })),
  });
  const res = response();
  await getIssue({ params: { id: 'issue-id' } } as unknown as Request<{ id: string }>, res);
  return res.body.attackPath;
}

describe('issue attack path entry point', () => {
  beforeAll(async () => {
    ({ getIssue } = await import('../routes/issues'));
  });

  beforeEach(() => {
    jest.clearAllMocks();
    getTrustedPrincipals.mockResolvedValue([]);
    getResources.mockResolvedValue([]);
  });

  it('starts at the internet only when the first resource is exposed', async () => {
    const path = await detailFor([
      vertex('arn:aws:ec2:us-west-2:111122223333:instance/i-1', 'Ec2Instance', {
        is_internet_exposed: true,
      }),
      vertex('arn:aws:iam::111122223333:role/app', 'IamRole'),
    ]);
    expect(path.entry).toEqual({ kind: 'internet' });
  });

  it('starts at the trusted outside accounts for a cross-account role', async () => {
    const external = vertex('arn:aws:khalifa:external-account:999988887777', 'ExternalAccount', {
      account_id: '999988887777',
    });
    const sameAccount = vertex('arn:aws:iam::111122223333:role/ops', 'IamRole');
    getTrustedPrincipals.mockResolvedValue([external, sameAccount]);

    const path = await detailFor([
      vertex('arn:aws:iam::111122223333:role/FlanDiscoveryRole', 'IamRole', {
        has_cross_account_trust: true,
      }),
      vertex('arn:aws:iam::111122223333:policy/FlanDiscoveryReadOnly', 'IamPolicyDocument'),
    ]);

    expect(getTrustedPrincipals).toHaveBeenCalledWith(
      'arn:aws:iam::111122223333:role/FlanDiscoveryRole'
    );
    expect(path.entry).toEqual({ kind: 'trust', principals: [external] });
  });

  it('claims no entry for a path that is neither exposed nor trusted from outside', async () => {
    const path = await detailFor([
      vertex('arn:aws:iam::111122223333:role/internal', 'IamRole'),
      vertex('arn:aws:iam::111122223333:policy/p', 'IamPolicyDocument'),
    ]);
    expect(path.entry).toBeUndefined();
    expect(getTrustedPrincipals).not.toHaveBeenCalled();
  });

  it('keeps a vertex missing from the graph as a placeholder instead of bridging it', async () => {
    const role = vertex('arn:aws:iam::111122223333:role/app', 'IamRole');
    const bucket = vertex('arn:aws:s3:::data', 'S3Bucket');
    getResource.mockImplementation(async (id: string) =>
      id === role.id ? role : id === bucket.id ? bucket : null
    );
    getIssueById.mockResolvedValue({
      id: 'issue-id',
      ruleId: 'RULE-001',
      pathSummary: [
        { from: role.id, to: 'arn:aws:iam::111122223333:policy/gone', edgeType: 'ATTACHED_TO' },
        { from: 'arn:aws:iam::111122223333:policy/gone', to: bucket.id, edgeType: 'GRANTS' },
      ],
      resourcesInvolved: [],
    });
    const res = response();
    await getIssue({ params: { id: 'issue-id' } } as unknown as Request<{ id: string }>, res);
    expect(res.body.attackPath.nodes.map((n: GraphVertex) => n.label)).toEqual([
      'IamRole',
      'Missing',
      'S3Bucket',
    ]);
  });

  it('keeps the type and name the issue stored for a deleted resource', async () => {
    const role = vertex('arn:aws:iam::111122223333:role/app', 'IamRole');
    const gone = 'arn:aws:s3:::old-data';
    getResource.mockImplementation(async (id: string) => (id === role.id ? role : null));
    getIssueById.mockResolvedValue({
      id: 'issue-id',
      ruleId: 'RULE-001',
      pathSummary: [{ from: role.id, to: gone, edgeType: 'GRANTS' }],
      resourcesInvolved: [{ resourceId: gone, resourceType: 'S3Bucket', resourceName: 'old-data' }],
    });
    const res = response();
    await getIssue({ params: { id: 'issue-id' } } as unknown as Request<{ id: string }>, res);
    expect(res.body.attackPath.nodes[1]).toEqual({
      id: gone,
      label: 'Missing',
      properties: { name: 'old-data', missing: true, deleted_label: 'S3Bucket' },
    });
  });

  it('draws a single-resource match from its involved resources', async () => {
    const bucket = vertex('arn:aws:s3:::payments', 'S3Bucket', { is_publicly_accessible: true });
    const path = await detailFor([bucket], [bucket.id]);
    expect(path.nodes).toEqual([bucket]);
    expect(path.edges).toEqual([]);
    expect(path.entry).toEqual({ kind: 'internet' });
  });
});

describe('issue involved resources', () => {
  const instance = vertex('arn:aws:ec2:us-west-2:111122223333:instance/i-1', 'Ec2Instance');
  const shown = vertex(
    'arn:aws:securityhub:us-west-2:111122223333:finding/a',
    'SecurityHubFinding'
  );
  const other = vertex(
    'arn:aws:securityhub:us-west-2:111122223333:finding/b',
    'SecurityHubFinding'
  );

  beforeAll(async () => {
    ({ getIssue } = await import('../routes/issues'));
  });

  beforeEach(() => {
    jest.clearAllMocks();
    getTrustedPrincipals.mockResolvedValue([]);
    getResource.mockImplementation(async (id: string) =>
      id === shown.id ? shown : id === instance.id ? instance : null
    );
    getIssueById.mockResolvedValue({
      id: 'issue-id',
      ruleId: 'RULE-018',
      pathSummary: [{ from: shown.id, to: instance.id, edgeType: 'DETECTS_ON' }],
      resourcesInvolved: [shown, instance, other].map((v) => ({
        resourceId: v.id,
        resourceType: v.label,
      })),
    });
  });

  async function detail() {
    const res = response();
    await getIssue({ params: { id: 'issue-id' } } as unknown as Request<{ id: string }>, res);
    return res.body;
  }

  it('loads only the involved resources off the drawn path, in one read', async () => {
    getResources.mockResolvedValue([other]);
    const body = await detail();
    expect(getResources).toHaveBeenCalledTimes(1);
    expect(getResources).toHaveBeenCalledWith([other.id]);
    expect(body.involvedResources).toEqual([other]);
    expect(body.attackPath.nodes.map((n: GraphVertex) => n.id)).toEqual([shown.id, instance.id]);
  });

  it('still returns the issue and its path when that read fails', async () => {
    getResources.mockRejectedValue(new Error('neptune down'));
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    const body = await detail();
    expect(body.involvedResources).toEqual([]);
    expect(body.attackPath.nodes).toHaveLength(2);
  });

  it('skips the read when every involved resource is on the path', async () => {
    getIssueById.mockResolvedValue({
      id: 'issue-id',
      ruleId: 'RULE-018',
      pathSummary: [{ from: shown.id, to: instance.id, edgeType: 'DETECTS_ON' }],
      resourcesInvolved: [shown, instance].map((v) => ({
        resourceId: v.id,
        resourceType: v.label,
      })),
    });
    const body = await detail();
    expect(getResources).not.toHaveBeenCalled();
    expect(body.involvedResources).toEqual([]);
  });
});
