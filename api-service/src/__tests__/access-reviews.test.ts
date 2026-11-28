import type { Response } from 'express';
import type { AccessReviewEntry } from '../services/access-review-store';

const listReviews = jest.fn();
const createReview = jest.fn();
const getReview = jest.fn();
const updateReview = jest.fn();
const recordDecision = jest.fn();
const deleteReview = jest.fn();
const getResources = jest.fn();

jest.mock('../services/access-review-store', () => ({
  ...jest.requireActual('../services/access-review-store'),
  AccessReviewStore: jest.fn(() => ({
    listReviews,
    createReview,
    getReview,
    updateReview,
    recordDecision,
    deleteReview,
  })),
}));

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({ getResources }),
}));

import {
  listAccessReviews,
  createAccessReview,
  getAccessReview,
  updateAccessReview,
  recordAccessReviewDecision,
  deleteAccessReview,
} from '../routes/access-reviews';

const ARN_1 = 'arn:aws:iam::111122223333:role/Admin';
const ANALYST = { user: { email: 'analyst@example.com' } };

const entry: AccessReviewEntry = {
  id: 'q4-review',
  name: 'Q4 review',
  description: '',
  status: 'active',
  dueAt: null,
  principals: [ARN_1],
  decisions: [],
  snapshot: null,
  summary: null,
  createdAt: '2026-11-01T00:00:00.000Z',
  createdBy: 'analyst@example.com',
  updatedAt: '2026-11-01T00:00:00.000Z',
  updatedBy: 'analyst@example.com',
  decided: 0,
  pending: 1,
};

function call(handler: (req: any, res: Response) => Promise<void>, req: any) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return handler(req, res as Response).then(() => res);
}

beforeEach(() => {
  listReviews.mockReset();
  createReview.mockReset();
  getReview.mockReset();
  updateReview.mockReset();
  recordDecision.mockReset();
  deleteReview.mockReset();
  getResources.mockReset();
});

describe('access review routes', () => {
  it('lists campaigns with the truncation flag', async () => {
    listReviews.mockResolvedValue({ items: [entry], truncated: false });

    const res = await call(listAccessReviews, {});

    expect(res.body).toEqual({ items: [entry], truncated: false });
  });

  it('creates with a slug and the verified actor, rejecting bad scopes', async () => {
    createReview.mockResolvedValue(entry);

    const created = await call(createAccessReview, {
      ...ANALYST,
      body: { name: 'Q4 review', principals: [ARN_1] },
    });
    expect(created.body.review).toEqual(entry);
    expect(createReview).toHaveBeenCalledWith(
      'q4-review',
      expect.objectContaining({ principals: [ARN_1], status: 'draft' }),
      'analyst@example.com'
    );

    const badScope = await call(createAccessReview, {
      ...ANALYST,
      body: { name: 'Q4 review', principals: ['nope'] },
    });
    expect(badScope.statusCode).toBe(400);
    expect(badScope.body.message).toContain('IAM user or role ARNs');

    const anonymous = await call(createAccessReview, {
      body: { name: 'Q4 review', principals: [ARN_1] },
    });
    expect(anonymous.statusCode).toBe(401);
  });

  it('serves one review and 404s malformed ids without a store call', async () => {
    getReview.mockResolvedValue(entry);
    expect((await call(getAccessReview, { params: { id: 'q4-review' } })).body).toEqual({
      review: entry,
    });

    const malformed = await call(getAccessReview, { params: { id: 'NOT A SLUG' } });
    expect(malformed.statusCode).toBe(404);
    expect(getReview).toHaveBeenCalledTimes(1);
  });

  it('updates without a snapshot unless the status transitions to completed', async () => {
    getReview.mockResolvedValue(entry);
    updateReview.mockResolvedValue(entry);

    await call(updateAccessReview, {
      ...ANALYST,
      params: { id: 'q4-review' },
      body: { name: 'Q4 review', principals: [ARN_1], status: 'active' },
    });
    expect(updateReview).toHaveBeenCalledWith(
      'q4-review',
      expect.objectContaining({ status: 'active' }),
      'analyst@example.com',
      undefined
    );
    expect(getResources).not.toHaveBeenCalled();
  });

  it('captures the evidence snapshot when completing', async () => {
    getReview.mockResolvedValue(entry);
    updateReview.mockResolvedValue({ ...entry, status: 'completed' });
    getResources.mockResolvedValue([
      { id: ARN_1, label: 'IamRole', properties: { is_admin: true } },
    ]);

    const res = await call(updateAccessReview, {
      ...ANALYST,
      params: { id: 'q4-review' },
      body: { name: 'Q4 review', principals: [ARN_1], status: 'completed' },
    });

    expect(res.statusCode).toBe(200);
    expect(getResources).toHaveBeenCalledWith([ARN_1]);
    const completion = updateReview.mock.calls[0][3];
    expect(completion.snapshot).toEqual([
      { principalArn: ARN_1, exists: true, label: 'IamRole', isAdmin: true },
    ]);
    expect(completion.summary).toMatchObject({
      generatedBy: 'analyst@example.com',
      decisions: { approve: 0, revoke: 0, abstain: 0, pending: 1 },
      snapshotted: 1,
    });
  });

  it('fails the completion when the snapshot read fails (no hollow completion)', async () => {
    getReview.mockResolvedValue(entry);
    getResources.mockRejectedValue(new Error('neptune down'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(updateAccessReview, {
      ...ANALYST,
      params: { id: 'q4-review' },
      body: { name: 'Q4 review', principals: [ARN_1], status: 'completed' },
    });

    expect(res.statusCode).toBe(500);
    expect(updateReview).not.toHaveBeenCalled();
    error.mockRestore();
  });

  it('records decisions only while active and only for covered principals', async () => {
    getReview.mockResolvedValue(entry);
    recordDecision.mockResolvedValue(entry);

    const recorded = await call(recordAccessReviewDecision, {
      ...ANALYST,
      params: { id: 'q4-review' },
      body: { principalArn: ARN_1, decision: 'approve', note: 'still needed' },
    });
    expect(recorded.body.review).toEqual(entry);
    expect(recordDecision).toHaveBeenCalledWith(
      'q4-review',
      { principalArn: ARN_1, decision: 'approve', note: 'still needed' },
      'analyst@example.com'
    );

    const uncovered = await call(recordAccessReviewDecision, {
      ...ANALYST,
      params: { id: 'q4-review' },
      body: { principalArn: 'arn:aws:iam::111122223333:role/Other', decision: 'approve' },
    });
    expect(uncovered.statusCode).toBe(400);
    expect(uncovered.body.message).toContain('not covered');

    getReview.mockResolvedValue({ ...entry, status: 'completed' });
    const closed = await call(recordAccessReviewDecision, {
      ...ANALYST,
      params: { id: 'q4-review' },
      body: { principalArn: ARN_1, decision: 'approve' },
    });
    expect(closed.statusCode).toBe(409);
    expect(closed.body.message).toContain('not active');
  });

  it('deletes with a 404 for malformed or missing ids', async () => {
    deleteReview.mockResolvedValue(true);
    const deleted = await call(deleteAccessReview, { params: { id: 'q4-review' } });
    expect(deleted.body).toEqual({ id: 'q4-review', deleted: true });

    deleteReview.mockResolvedValue(false);
    const missing = await call(deleteAccessReview, { params: { id: 'q4-review' } });
    expect(missing.statusCode).toBe(404);

    const malformed = await call(deleteAccessReview, { params: { id: 'NOT A SLUG' } });
    expect(malformed.statusCode).toBe(404);
    expect(deleteReview).toHaveBeenCalledTimes(2);
  });

  it('answers 500 when the store fails', async () => {
    listReviews.mockRejectedValue(new Error('nope'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(listAccessReviews, {});

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ code: 'INTERNAL_ERROR', message: 'Failed to list access reviews' });
    error.mockRestore();
  });
});
