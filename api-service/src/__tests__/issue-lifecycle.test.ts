import type { Request, Response } from 'express';

const getIssueById = jest.fn();
const suppressIssueInStore = jest.fn();
const reopenIssueInStore = jest.fn();

jest.mock('@khalifa/risk-engine', () => ({
  DynamoDBIssueRepository: jest.fn().mockImplementation(() => ({
    getIssueById,
    suppressIssue: suppressIssueInStore,
    reopenIssue: reopenIssueInStore,
  })),
}));

let suppressIssue: typeof import('../routes/integrations').suppressIssue;
let reopenIssue: typeof import('../routes/integrations').reopenIssue;
let limits: { reason: number; days: number };
// it.each tables are built before beforeAll runs, so the limits are pinned here
// and checked against the route's exports below.
const MAX_REASON_LENGTH = 500;
const MAX_SUPPRESSION_DAYS = 90;
const DAY = 24 * 60 * 60 * 1000;

function response(): Response & { statusCode: number; body?: unknown } {
  const res: any = { statusCode: 200 };
  res.status = (statusCode: number) => Object.assign(res, { statusCode });
  res.json = (body: unknown) => Object.assign(res, { body });
  return res as unknown as Response & { statusCode: number; body?: unknown };
}

describe('issue lifecycle routes', () => {
  beforeAll(async () => {
    const routes = await import('../routes/integrations');
    ({ suppressIssue, reopenIssue } = routes);
    limits = { reason: routes.MAX_REASON_LENGTH, days: routes.MAX_SUPPRESSION_DAYS };
  });

  const stored = { id: 'issue-id', ruleId: 'RULE-001', status: 'open' };
  const user = { sub: 'sub-1', email: 'analyst@example.com', groups: [], tokenUse: 'id' };
  const inDays = (days: number) => new Date(Date.now() + days * DAY).toISOString();

  function request(body: Record<string, unknown> = {}, caller: unknown = user) {
    return { params: { id: 'issue-id' }, body, user: caller } as unknown as Request<{ id: string }>;
  }

  beforeEach(() => {
    jest.clearAllMocks();
    getIssueById.mockResolvedValue(stored);
  });

  it('pins the same limits the route enforces', () => {
    expect(limits).toEqual({ reason: MAX_REASON_LENGTH, days: MAX_SUPPRESSION_DAYS });
  });

  it('suppresses the stored issue as the verified caller with a reason and expiry', async () => {
    suppressIssueInStore.mockResolvedValue(true);
    const expiresAt = inDays(30);
    const res = response();

    await suppressIssue(request({ reason: '  accepted  ', expiresAt, by: 'spoofed' }), res);

    expect(getIssueById).toHaveBeenCalledWith('issue-id');
    expect(suppressIssueInStore).toHaveBeenCalledWith(stored, {
      by: 'analyst@example.com',
      reason: 'accepted',
      until: expiresAt,
    });
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({
      id: 'issue-id',
      status: 'suppressed',
      reason: 'accepted',
      expiresAt,
    });
  });

  it.each([
    ['a missing reason', { expiresAt: inDays(7) }],
    ['a blank reason', { reason: '   ', expiresAt: inDays(7) }],
    ['an overlong reason', { reason: 'x'.repeat(MAX_REASON_LENGTH + 1), expiresAt: inDays(7) }],
    ['a missing expiry', { reason: 'accepted' }],
    ['an unparseable expiry', { reason: 'accepted', expiresAt: 'next week' }],
    ['a past expiry', { reason: 'accepted', expiresAt: inDays(-1) }],
    [
      'an expiry past the maximum',
      { reason: 'accepted', expiresAt: inDays(MAX_SUPPRESSION_DAYS + 1) },
    ],
  ])('rejects suppression with %s', async (_case, body) => {
    const res = response();

    await suppressIssue(request(body), res);

    expect(res.statusCode).toBe(400);
    expect(getIssueById).not.toHaveBeenCalled();
    expect(suppressIssueInStore).not.toHaveBeenCalled();
  });

  it('rejects a caller with no verified identity', async () => {
    const res = response();

    await suppressIssue(request({ reason: 'accepted', expiresAt: inDays(7) }, null), res);

    expect(res.statusCode).toBe(401);
    expect(suppressIssueInStore).not.toHaveBeenCalled();
  });

  it('reopens as the verified caller with a default reason', async () => {
    reopenIssueInStore.mockResolvedValue(true);
    const res = response();

    await reopenIssue(request(), res);

    expect(reopenIssueInStore).toHaveBeenCalledWith(stored, {
      by: 'analyst@example.com',
      reason: 'Reopened manually',
    });
    expect(res.body).toEqual({ id: 'issue-id', status: 'open' });
  });

  it('returns conflict when the update loses a state race', async () => {
    suppressIssueInStore.mockResolvedValue(false);
    const res = response();

    await suppressIssue(request({ reason: 'accepted', expiresAt: inDays(7) }), res);

    expect(res.statusCode).toBe(409);
    expect(res.body).toEqual({ code: 'CONFLICT', message: 'Issue state changed: issue-id' });
  });
});
