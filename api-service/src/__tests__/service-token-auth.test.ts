import type { Request } from 'express';
import { hasRole, requireTrustCenterSync, Role } from '../middleware/rbac';

const verifyServiceTokenMock = jest.fn();

// Lazy closure: the factory runs during the import graph, before this module's
// body initializes the mock, so it must not evaluate the identifier eagerly.
jest.mock('../services/service-token-store', () => ({
  verifyServiceToken: (...args: unknown[]) => verifyServiceTokenMock(...args),
}));

const UUID = '11111111-2222-3333-4444-555555555555';
const TOKEN = `khalifa_${UUID}_${'a'.repeat(64)}`;

function makeReq(headers: Record<string, string> = {}): Request {
  return { headers, user: undefined } as unknown as Request;
}

function makeRes() {
  const res: any = {
    statusCode: 200,
    body: undefined,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
  return res;
}

async function authenticateWith(token: string) {
  const { authenticate } = await import('../middleware/auth');
  const req = makeReq({ authorization: `Bearer ${token}` });
  const res = makeRes();
  const next = jest.fn();
  await authenticate(req, res, next);
  return { req, res, next };
}

describe('service-token authentication', () => {
  beforeEach(() => {
    verifyServiceTokenMock.mockReset();
  });

  it('authenticates a valid viewer token and maps its role through RBAC', async () => {
    verifyServiceTokenMock.mockResolvedValue({ id: UUID, name: 'ci', role: 'viewer' });

    const { req, res, next } = await authenticateWith(TOKEN);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.statusCode).toBe(200);
    expect(req.user).toEqual({
      sub: `automation:${UUID}`,
      groups: ['khalifa-viewer'],
      tokenUse: 'service',
      automation: { tokenId: UUID, role: 'viewer' },
    });
    expect(hasRole(req, Role.Viewer)).toBe(true);
    expect(hasRole(req, Role.Analyst)).toBe(false);
    expect(hasRole(req, Role.Admin)).toBe(false);
  });

  it('maps an analyst token to the analyst floor, never admin', async () => {
    verifyServiceTokenMock.mockResolvedValue({ id: UUID, name: 'sync', role: 'analyst' });

    const { req, next } = await authenticateWith(TOKEN);

    expect(next).toHaveBeenCalled();
    expect(hasRole(req, Role.Analyst)).toBe(true);
    expect(hasRole(req, Role.Admin)).toBe(false);
  });

  it('does not set the trust-center service-token flag', async () => {
    verifyServiceTokenMock.mockResolvedValue({ id: UUID, name: 'ci', role: 'viewer' });

    const { req, next } = await authenticateWith(TOKEN);

    expect(next).toHaveBeenCalled();
    expect(req.user?.serviceToken).toBeUndefined();
    const res = makeRes();
    const next2 = jest.fn();
    requireTrustCenterSync(req, res, next2);
    expect(res.statusCode).toBe(403);
    expect(next2).not.toHaveBeenCalled();
  });

  it('rejects an unknown, revoked, or expired token with 401', async () => {
    verifyServiceTokenMock.mockResolvedValue(null);

    const { res, next } = await authenticateWith(TOKEN);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect(res.body).toMatchObject({ code: 'UNAUTHORIZED' });
  });

  it('answers 503 when the token store is unavailable', async () => {
    verifyServiceTokenMock.mockRejectedValue(new Error('dynamo down'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const { res, next } = await authenticateWith(TOKEN);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(503);
    expect(res.body).toMatchObject({ code: 'AUTH_UNAVAILABLE' });
    error.mockRestore();
  });
});
