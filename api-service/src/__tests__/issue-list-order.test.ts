import type { Request, Response } from 'express';

const listIssues = jest.fn();

jest.mock('@khalifa/risk-engine', () => ({
  DynamoDBIssueRepository: jest.fn().mockImplementation(() => ({ listIssues })),
  PostureTrendStore: jest.fn(),
}));
jest.mock('../services/api-dependencies', () => ({ getApiNeptuneClient: () => ({}) }));

let route: typeof import('../routes/issues');

function call(query: Record<string, unknown>) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return route.listIssues({ query } as unknown as Request, res as Response).then(() => res);
}

describe('GET /issues order', () => {
  beforeAll(async () => {
    route = await import('../routes/issues');
  });
  beforeEach(() => listIssues.mockReset().mockResolvedValue({ items: [], totalCount: 0 }));

  it('lists newest first unless asked for oldest first', async () => {
    await call({});
    expect(listIssues).toHaveBeenLastCalledWith(expect.objectContaining({ order: 'desc' }));
    await call({ order: 'asc' });
    expect(listIssues).toHaveBeenLastCalledWith(expect.objectContaining({ order: 'asc' }));
  });

  it('rejects any other order, and oversized page tokens, without reading', async () => {
    for (const order of ['ASC', 'createdAt', ['asc', 'desc'], { $ne: 'asc' }]) {
      expect((await call({ order })).statusCode).toBe(400);
    }
    expect((await call({ nextToken: 'a'.repeat(2049) })).statusCode).toBe(400);
    expect(listIssues).not.toHaveBeenCalled();
  });
});
