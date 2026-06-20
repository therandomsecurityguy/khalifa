import type { Request, Response, NextFunction } from 'express';
import { SignJWT, generateKeyPair, exportJWK, type JWK, type KeyLike } from 'jose';

const TEST_USER_POOL_ID = 'us-east-1_testpool';
const TEST_CLIENT_ID = 'test-client-id';
const TEST_REGION = 'us-east-1';

let testKeyPair: { publicKey: KeyLike; privateKey: KeyLike } | null = null;
let jwk: JWK | null = null;

jest.mock('jose', () => {
  const actual = jest.requireActual('jose');
  return {
    ...actual,
    createRemoteJWKSet: jest.fn(() => {
      const kp = (global as any).__TEST_KEY_PAIR__;
      return async () => kp.publicKey;
    }),
  };
});

async function getKeyPair() {
  if (!testKeyPair) {
    const kp = await generateKeyPair('RS256');
    const exportedJwk = await exportJWK(kp.publicKey);
    exportedJwk.kid = 'test-key-1';
    exportedJwk.alg = 'RS256';
    exportedJwk.use = 'sig';
    testKeyPair = kp;
    jwk = exportedJwk;
  }
  return { keyPair: testKeyPair, jwk };
}

function makeReq(headers: Record<string, string> = {}): Request {
  return { headers, user: undefined } as unknown as Request;
}

function makeRes(): Response {
  const res: any = {
    statusCode: 200,
    body: undefined,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: any) {
      this.body = payload;
      return this;
    },
  };
  return res as Response;
}

async function makeToken(claims: Record<string, unknown>): Promise<string> {
  const { keyPair } = await getKeyPair();
  const issuer = `https://cognito-idp.${TEST_REGION}.amazonaws.com/${TEST_USER_POOL_ID}`;
  const sub = typeof claims.sub === 'string' ? claims.sub : 'user-123';
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
    .setIssuer(issuer)
    .setAudience(TEST_CLIENT_ID)
    .setSubject(sub)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(keyPair.privateKey);
}

describe('authenticate middleware', () => {
  const originalEnv = { ...process.env };

  beforeAll(async () => {
    const { keyPair } = await getKeyPair();
    (global as any).__TEST_KEY_PAIR__ = keyPair;
  });

  beforeEach(() => {
    jest.resetModules();
    process.env.COGNITO_USER_POOL_ID = TEST_USER_POOL_ID;
    process.env.COGNITO_CLIENT_ID = TEST_CLIENT_ID;
    process.env.COGNITO_REGION = TEST_REGION;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('rejects missing Authorization header', async () => {
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({}), res, next);
    expect(res.statusCode).toBe(401);
    expect((res as any).body.code).toBe('MISSING_TOKEN');
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects Authorization header without Bearer prefix', async () => {
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({ authorization: 'Basic abc' }), res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects expired token', async () => {
    const { keyPair } = await getKeyPair();
    const issuer = `https://cognito-idp.${TEST_REGION}.amazonaws.com/${TEST_USER_POOL_ID}`;
    const expired = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuer(issuer)
      .setAudience(TEST_CLIENT_ID)
      .setSubject('user-123')
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 3600)
      .sign(keyPair.privateKey);

    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({ authorization: `Bearer ${expired}` }), res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects token with wrong audience', async () => {
    const { keyPair } = await getKeyPair();
    const issuer = `https://cognito-idp.${TEST_REGION}.amazonaws.com/${TEST_USER_POOL_ID}`;
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
      .setIssuer(issuer)
      .setAudience('wrong-client-id')
      .setSubject('user-123')
      .setIssuedAt()
      .setExpirationTime('1h')
      .sign(keyPair.privateKey);

    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({ authorization: `Bearer ${token}` }), res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('accepts valid token and populates req.user', async () => {
    const token = await makeToken({
      email: 'user@example.com',
      'cognito:groups': ['khalifa-admin', 'khalifa-viewer'],
    });
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    const req = makeReq({ authorization: `Bearer ${token}` });
    await authenticate(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.user).toBeDefined();
    expect(req.user!.sub).toBe('user-123');
    expect(req.user!.email).toBe('user@example.com');
    expect(req.user!.groups).toEqual(['khalifa-admin', 'khalifa-viewer']);
  });
});