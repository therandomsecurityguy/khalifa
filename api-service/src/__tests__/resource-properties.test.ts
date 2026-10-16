import type { Request, Response } from 'express';

const listResourceProperties = jest.fn();
const listPropertyValues = jest.fn();
const searchResources = jest.fn();
const browseAllLabels = jest.fn();
const listResourceLabels = jest.fn();

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({
    listResourceProperties,
    listPropertyValues,
    searchResources,
    browseAllLabels,
    listResourceLabels,
  }),
}));
jest.mock('@khalifa/risk-engine', () => ({ DynamoDBIssueRepository: jest.fn() }));

let route: typeof import('../routes/resources');

function call(
  handler: 'listResourceProperties' | 'listPropertyValues' | 'searchResources',
  query: object
) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return route[handler]({ query } as unknown as Request, res as Response).then(() => res);
}

describe('GET /resources/properties and /resources/values', () => {
  beforeAll(async () => {
    route = await import('../routes/resources');
  });
  beforeEach(() => {
    listResourceProperties.mockReset().mockResolvedValue(['account_id']);
    listPropertyValues.mockReset().mockResolvedValue({ values: [], more: false });
  });

  it('accepts only identifier-shaped labels and property names', async () => {
    for (const query of [{}, { label: "IamRole').drop()" }, { label: ['IamRole', 'S3Bucket'] }]) {
      expect((await call('listResourceProperties', query)).statusCode).toBe(400);
    }
    for (const query of [{ label: 'IamRole' }, { label: 'IamRole', property: 'a b' }]) {
      expect((await call('listPropertyValues', query)).statusCode).toBe(400);
    }
    expect(listResourceProperties).not.toHaveBeenCalled();
    expect(listPropertyValues).not.toHaveBeenCalled();
  });

  it('returns the properties and values for valid input', async () => {
    expect((await call('listResourceProperties', { label: 'IamRole' })).body).toEqual({
      properties: ['account_id'],
    });
    await call('listPropertyValues', { label: 'IamRole', property: 'is_admin_role' });
    expect(listPropertyValues).toHaveBeenCalledWith('IamRole', 'is_admin_role');
  });

  it('accepts * for all labels', async () => {
    await call('listResourceProperties', { label: '*' });
    expect(listResourceProperties).toHaveBeenCalledWith('*');
    await call('listPropertyValues', { label: '*', property: 'env' });
    expect(listPropertyValues).toHaveBeenCalledWith('*', 'env');
  });

  it('browses every label without a filter, and filters every label with one', async () => {
    searchResources.mockResolvedValue({ resources: [] });
    browseAllLabels.mockResolvedValue({ resources: [], nextToken: 'next' });
    listResourceLabels.mockResolvedValue([
      { label: 'S3Bucket', count: 9 },
      { label: 'IamRole', count: 4 },
    ]);

    const all = await call('searchResources', { label: '*', limit: '50' });
    expect(all.statusCode).toBe(200);
    expect(all.body).toEqual({ label: '*', resources: [], nextToken: 'next' });
    expect(browseAllLabels).toHaveBeenCalledWith({
      labels: ['S3Bucket', 'IamRole'],
      limit: 50,
      nextToken: undefined,
    });
    expect(searchResources).not.toHaveBeenCalled();

    expect(
      (await call('searchResources', { label: '*', property: 'env', value: 'prod' })).statusCode
    ).toBe(200);
    expect(searchResources).toHaveBeenCalledWith(
      expect.objectContaining({ label: '*', property: 'env', value: 'prod' })
    );
  });

  it('rejects a bad all-labels cursor', async () => {
    listResourceLabels.mockResolvedValue([{ label: 'IamRole', count: 4 }]);
    browseAllLabels.mockRejectedValue(new Error('Invalid pagination token'));
    expect((await call('searchResources', { label: '*', nextToken: 'x' })).statusCode).toBe(400);
  });
});
