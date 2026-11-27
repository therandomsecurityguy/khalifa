import type { Response } from 'express';
import type { RiskRegisterEntry } from '../services/risk-register-store';

const listRisks = jest.fn();
const createRisk = jest.fn();
const getRisk = jest.fn();
const updateRisk = jest.fn();
const deleteRisk = jest.fn();

jest.mock('../services/risk-register-store', () => ({
  ...jest.requireActual('../services/risk-register-store'),
  RiskRegisterStore: jest.fn(() => ({ listRisks, createRisk, getRisk, updateRisk, deleteRisk })),
}));

import {
  listRisks as listRisksRoute,
  createRisk as createRiskRoute,
  getRisk as getRiskRoute,
  updateRisk as updateRiskRoute,
  deleteRisk as deleteRiskRoute,
} from '../routes/risks';

const ANALYST = { user: { email: 'analyst@example.com' } };

const entry: RiskRegisterEntry = {
  id: 'shared-admin-role',
  title: 'Shared admin role',
  description: '',
  category: 'security',
  owner: 'analyst@example.com',
  status: 'open',
  inherent: { likelihood: 3, impact: 4 },
  residual: null,
  treatment: 'mitigate',
  acceptanceExpiry: null,
  reviewCadenceDays: 90,
  lastReviewedAt: null,
  linkedIssueIds: [],
  linkedControls: [],
  createdAt: '2026-11-01T00:00:00.000Z',
  createdBy: 'analyst@example.com',
  updatedAt: '2026-11-01T00:00:00.000Z',
  updatedBy: 'analyst@example.com',
  inherentScore: 12,
  inherentLevel: 'high',
  residualScore: null,
  residualLevel: null,
  nextReviewAt: '2027-01-30T00:00:00.000Z',
};

function call(handler: (req: any, res: Response) => Promise<void>, req: any) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return handler(req, res as Response).then(() => res);
}

beforeEach(() => {
  listRisks.mockReset();
  createRisk.mockReset();
  getRisk.mockReset();
  updateRisk.mockReset();
  deleteRisk.mockReset();
});

describe('risk register routes', () => {
  it('lists entries with the truncation flag', async () => {
    listRisks.mockResolvedValue({ items: [entry], truncated: false });

    const res = await call(listRisksRoute, {});

    expect(res.body).toEqual({ items: [entry], truncated: false });
  });

  it('creates with a slug derived from the title and the verified actor', async () => {
    createRisk.mockResolvedValue(entry);

    const res = await call(createRiskRoute, {
      ...ANALYST,
      body: { title: 'Shared admin role', inherent: { likelihood: 3, impact: 4 } },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.risk).toEqual(entry);
    expect(createRisk).toHaveBeenCalledWith(
      'shared-admin-role',
      expect.objectContaining({
        owner: 'analyst@example.com',
        inherent: { likelihood: 3, impact: 4 },
      }),
      'analyst@example.com'
    );
  });

  it('rejects unknown controls, missing acceptance expiry, and bad ids with 400', async () => {
    const unknownControl = await call(createRiskRoute, {
      ...ANALYST,
      body: {
        title: 'x',
        inherent: { likelihood: 1, impact: 1 },
        linkedControls: ['NOT-A-CONTROL'],
      },
    });
    expect(unknownControl.statusCode).toBe(400);
    expect(unknownControl.body.message).toContain('unknown: NOT-A-CONTROL');

    const noExpiry = await call(createRiskRoute, {
      ...ANALYST,
      body: { title: 'x', inherent: { likelihood: 1, impact: 1 }, treatment: 'accept' },
    });
    expect(noExpiry.statusCode).toBe(400);
    expect(noExpiry.body.message).toContain('acceptanceExpiry is required');

    const badId = await call(createRiskRoute, {
      ...ANALYST,
      body: { id: 'NOT A SLUG', title: 'x', inherent: { likelihood: 1, impact: 1 } },
    });
    expect(badId.statusCode).toBe(400);
    expect(createRisk).not.toHaveBeenCalled();
  });

  it('answers 409 for a colliding id and 401 without an actor', async () => {
    createRisk.mockResolvedValue(null);
    const conflict = await call(createRiskRoute, {
      ...ANALYST,
      body: { title: 'Shared admin role', inherent: { likelihood: 1, impact: 1 } },
    });
    expect(conflict.statusCode).toBe(409);

    const anonymous = await call(createRiskRoute, {
      body: { title: 'x', inherent: { likelihood: 1, impact: 1 } },
    });
    expect(anonymous.statusCode).toBe(401);
  });

  it('serves one risk and answers 404 for malformed or missing ids', async () => {
    getRisk.mockResolvedValue(entry);
    const found = await call(getRiskRoute, { params: { id: 'shared-admin-role' } });
    expect(found.body).toEqual({ risk: entry });

    getRisk.mockResolvedValue(null);
    const missing = await call(getRiskRoute, { params: { id: 'shared-admin-role' } });
    expect(missing.statusCode).toBe(404);

    const malformed = await call(getRiskRoute, { params: { id: 'NOT A SLUG' } });
    expect(malformed.statusCode).toBe(404);
    // The two valid-shaped ids above reached the store; the malformed one did not.
    expect(getRisk).toHaveBeenCalledTimes(2);
  });

  it('updates with the verified actor and answers 404 when the row is gone', async () => {
    updateRisk.mockResolvedValue(entry);
    const updated = await call(updateRiskRoute, {
      ...ANALYST,
      params: { id: 'shared-admin-role' },
      body: { title: 'Shared admin role', inherent: { likelihood: 3, impact: 4 } },
    });
    expect(updated.body).toEqual({ risk: entry });
    expect(updateRisk).toHaveBeenCalledWith(
      'shared-admin-role',
      expect.objectContaining({ owner: 'analyst@example.com' }),
      'analyst@example.com'
    );

    updateRisk.mockResolvedValue(null);
    const gone = await call(updateRiskRoute, {
      ...ANALYST,
      params: { id: 'shared-admin-role' },
      body: { title: 'Shared admin role', inherent: { likelihood: 3, impact: 4 } },
    });
    expect(gone.statusCode).toBe(404);
  });

  it('deletes with a 404 for malformed or missing ids', async () => {
    deleteRisk.mockResolvedValue(true);
    const deleted = await call(deleteRiskRoute, { params: { id: 'shared-admin-role' } });
    expect(deleted.body).toEqual({ id: 'shared-admin-role', deleted: true });

    deleteRisk.mockResolvedValue(false);
    const missing = await call(deleteRiskRoute, { params: { id: 'shared-admin-role' } });
    expect(missing.statusCode).toBe(404);

    const malformed = await call(deleteRiskRoute, { params: { id: 'NOT A SLUG' } });
    expect(malformed.statusCode).toBe(404);
    // The two valid-shaped ids above reached the store; the malformed one did not.
    expect(deleteRisk).toHaveBeenCalledTimes(2);
  });

  it('answers 500 when the store fails', async () => {
    listRisks.mockRejectedValue(new Error('nope'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(listRisksRoute, {});

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ code: 'INTERNAL_ERROR', message: 'Failed to list risks' });
    error.mockRestore();
  });
});
