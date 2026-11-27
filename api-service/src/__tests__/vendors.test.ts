import type { Response } from 'express';
import type { VendorRegisterEntry } from '../services/vendor-register-store';

const listVendors = jest.fn();
const createVendor = jest.fn();
const getVendor = jest.fn();
const updateVendor = jest.fn();
const deleteVendor = jest.fn();

jest.mock('../services/vendor-register-store', () => ({
  ...jest.requireActual('../services/vendor-register-store'),
  VendorRegisterStore: jest.fn(() => ({
    listVendors,
    createVendor,
    getVendor,
    updateVendor,
    deleteVendor,
  })),
}));

import {
  listVendors as listVendorsRoute,
  createVendor as createVendorRoute,
  getVendor as getVendorRoute,
  updateVendor as updateVendorRoute,
  deleteVendor as deleteVendorRoute,
} from '../routes/vendors';

const ANALYST = { user: { email: 'analyst@example.com' } };

const entry: VendorRegisterEntry = {
  id: 'example-cloud',
  name: 'Example Cloud',
  category: 'cloud',
  purpose: 'Hosting',
  location: 'us-east-1',
  dpaUrl: 'https://example.com/dpa',
  dataClasses: ['internal'],
  owner: 'procurement@example.com',
  status: 'active',
  subprocessor: true,
  renewalAt: null,
  reviewCadenceDays: 365,
  lastReviewedAt: null,
  createdAt: '2026-11-01T00:00:00.000Z',
  createdBy: 'procurement@example.com',
  updatedAt: '2026-11-01T00:00:00.000Z',
  updatedBy: 'procurement@example.com',
  nextReviewAt: '2027-11-01T00:00:00.000Z',
};

function call(handler: (req: any, res: Response) => Promise<void>, req: any) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return handler(req, res as Response).then(() => res);
}

beforeEach(() => {
  listVendors.mockReset();
  createVendor.mockReset();
  getVendor.mockReset();
  updateVendor.mockReset();
  deleteVendor.mockReset();
});

describe('vendor register routes', () => {
  it('lists entries with the truncation flag', async () => {
    listVendors.mockResolvedValue({ items: [entry], truncated: false });

    const res = await call(listVendorsRoute, {});

    expect(res.body).toEqual({ items: [entry], truncated: false });
  });

  it('creates with a slug derived from the name and the verified actor', async () => {
    createVendor.mockResolvedValue(entry);

    const res = await call(createVendorRoute, {
      ...ANALYST,
      body: { name: 'Example Cloud' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.vendor).toEqual(entry);
    expect(createVendor).toHaveBeenCalledWith(
      'example-cloud',
      expect.objectContaining({ owner: 'analyst@example.com', status: 'active' }),
      'analyst@example.com'
    );
  });

  it('rejects http DPA urls, bare subprocessors, and bad ids with 400', async () => {
    const httpDpa = await call(createVendorRoute, {
      ...ANALYST,
      body: { name: 'x', dpaUrl: 'http://example.com/dpa' },
    });
    expect(httpDpa.statusCode).toBe(400);
    expect(httpDpa.body.message).toContain('dpaUrl must use https');

    const bareSubprocessor = await call(createVendorRoute, {
      ...ANALYST,
      body: { name: 'x', subprocessor: true },
    });
    expect(bareSubprocessor.statusCode).toBe(400);
    expect(bareSubprocessor.body.message).toContain('purpose and location are required');

    const badId = await call(createVendorRoute, {
      ...ANALYST,
      body: { id: 'NOT A SLUG', name: 'x' },
    });
    expect(badId.statusCode).toBe(400);
    expect(createVendor).not.toHaveBeenCalled();
  });

  it('answers 409 for a colliding id and 401 without an actor', async () => {
    createVendor.mockResolvedValue(null);
    const conflict = await call(createVendorRoute, { ...ANALYST, body: { name: 'x' } });
    expect(conflict.statusCode).toBe(409);

    const anonymous = await call(createVendorRoute, { body: { name: 'x' } });
    expect(anonymous.statusCode).toBe(401);
  });

  it('serves one vendor and answers 404 for malformed or missing ids', async () => {
    getVendor.mockResolvedValue(entry);
    const found = await call(getVendorRoute, { params: { id: 'example-cloud' } });
    expect(found.body).toEqual({ vendor: entry });

    getVendor.mockResolvedValue(null);
    const missing = await call(getVendorRoute, { params: { id: 'example-cloud' } });
    expect(missing.statusCode).toBe(404);

    const malformed = await call(getVendorRoute, { params: { id: 'NOT A SLUG' } });
    expect(malformed.statusCode).toBe(404);
    // The two valid-shaped ids above reached the store; the malformed one did not.
    expect(getVendor).toHaveBeenCalledTimes(2);
  });

  it('updates with the verified actor and answers 404 when the row is gone', async () => {
    updateVendor.mockResolvedValue(entry);
    const updated = await call(updateVendorRoute, {
      ...ANALYST,
      params: { id: 'example-cloud' },
      body: { name: 'Example Cloud' },
    });
    expect(updated.body).toEqual({ vendor: entry });

    updateVendor.mockResolvedValue(null);
    const gone = await call(updateVendorRoute, {
      ...ANALYST,
      params: { id: 'example-cloud' },
      body: { name: 'Example Cloud' },
    });
    expect(gone.statusCode).toBe(404);
  });

  it('deletes with a 404 for malformed or missing ids', async () => {
    deleteVendor.mockResolvedValue(true);
    const deleted = await call(deleteVendorRoute, { params: { id: 'example-cloud' } });
    expect(deleted.body).toEqual({ id: 'example-cloud', deleted: true });

    deleteVendor.mockResolvedValue(false);
    const missing = await call(deleteVendorRoute, { params: { id: 'example-cloud' } });
    expect(missing.statusCode).toBe(404);

    const malformed = await call(deleteVendorRoute, { params: { id: 'NOT A SLUG' } });
    expect(malformed.statusCode).toBe(404);
    expect(deleteVendor).toHaveBeenCalledTimes(2);
  });

  it('answers 500 when the store fails', async () => {
    listVendors.mockRejectedValue(new Error('nope'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(listVendorsRoute, {});

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ code: 'INTERNAL_ERROR', message: 'Failed to list vendors' });
    error.mockRestore();
  });
});
