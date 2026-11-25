import type { Response } from 'express';
import type { ServiceTokenRecord } from '../services/service-token-store';

const createToken = jest.fn();
const listTokens = jest.fn();
const revokeToken = jest.fn();

jest.mock('../services/service-token-store', () => ({
  ...jest.requireActual('../services/service-token-store'),
  ServiceTokenStore: jest.fn(() => ({ createToken, listTokens, revokeToken })),
}));

import {
  createServiceToken,
  listServiceTokens,
  revokeServiceToken,
} from '../routes/service-tokens';

const ADMIN = { user: { email: 'admin@example.com' } };
const UUID = '11111111-2222-3333-4444-555555555555';

const record: ServiceTokenRecord = {
  id: UUID,
  name: 'ci pipeline',
  role: 'viewer',
  expiresAt: '2026-12-25T00:00:00.000Z',
  createdAt: '2026-11-25T00:00:00.000Z',
  createdBy: 'admin@example.com',
  lastUsedAt: null,
  revokedAt: null,
};

function call(handler: (req: any, res: Response) => Promise<void>, req: any) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return handler(req, res as Response).then(() => res);
}

beforeEach(() => {
  createToken.mockReset();
  listTokens.mockReset();
  revokeToken.mockReset();
});

describe('service-token routes', () => {
  it('mints a token once, hashes stored, metadata returned', async () => {
    createToken.mockImplementation(async (input, actor) => ({
      token: `khalifa_${UUID}_${'a'.repeat(64)}`,
      record: { ...record, ...input, createdBy: actor },
    }));

    const res = await call(createServiceToken, {
      ...ADMIN,
      body: { name: 'ci pipeline', role: 'viewer' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body.token).toMatch(/^khalifa_/);
    expect(res.body.tokenRecord).toMatchObject({
      name: 'ci pipeline',
      createdBy: 'admin@example.com',
    });
    expect(createToken).toHaveBeenCalledWith(
      { name: 'ci pipeline', role: 'viewer', expiresInDays: 30 },
      'admin@example.com'
    );
  });

  it('answers 400 with a named-field message and 401 without an actor', async () => {
    const invalid = await call(createServiceToken, { ...ADMIN, body: { name: '', role: 'admin' } });
    expect(invalid.statusCode).toBe(400);
    expect(invalid.body.message).toContain('name is required');

    const anonymous = await call(createServiceToken, { body: { name: 'x' } });
    expect(anonymous.statusCode).toBe(401);
    expect(createToken).not.toHaveBeenCalled();
  });

  it('lists metadata only', async () => {
    listTokens.mockResolvedValue([record]);

    const res = await call(listServiceTokens, {});

    expect(res.body).toEqual({ items: [record] });
    expect(JSON.stringify(res.body)).not.toContain('secretHash');
  });

  it('revokes by id and answers 404 for unknown or malformed ids', async () => {
    revokeToken.mockResolvedValue(true);
    const revoked = await call(revokeServiceToken, { params: { id: UUID } });
    expect(revoked.body).toEqual({ id: UUID, revoked: true });

    revokeToken.mockResolvedValueOnce(false);
    const missing = await call(revokeServiceToken, { params: { id: UUID } });
    expect(missing.statusCode).toBe(404);

    const malformed = await call(revokeServiceToken, { params: { id: 'not-a-uuid' } });
    expect(malformed.statusCode).toBe(404);
    expect(revokeToken).toHaveBeenCalledTimes(2);
  });

  it('answers 500 when the store fails', async () => {
    listTokens.mockRejectedValue(new Error('nope'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(listServiceTokens, {});

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ code: 'INTERNAL_ERROR', message: 'Failed to list service tokens' });
    error.mockRestore();
  });
});
