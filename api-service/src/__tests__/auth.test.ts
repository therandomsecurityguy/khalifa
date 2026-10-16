import type { Request, Response } from 'express';
import { SignJWT, generateKeyPair, exportJWK, type JWK, type KeyLike } from 'jose';

const TEST_USER_POOL_ID = 'us-east-1_testpool';
const TEST_CLIENT_ID = 'test-client-id';
const TEST_REGION = 'us-east-1';
const TEST_ACCESS_TEAM_DOMAIN = 'example-team.cloudflareaccess.com';
const TEST_ACCESS_AUD = 'test-access-aud';
const TEST_ACCESS_ISSUER = `https://${TEST_ACCESS_TEAM_DOMAIN}`;

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

async function makeAccessToken(
  claims: Record<string, unknown>,
  options: { audience?: string; issuer?: string } = {}
): Promise<string> {
  const { keyPair } = await getKeyPair();
  const sub = typeof claims.sub === 'string' ? claims.sub : 'access-user-123';
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key-1' })
    .setIssuer(options.issuer ?? TEST_ACCESS_ISSUER)
    .setAudience(options.audience ?? TEST_ACCESS_AUD)
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
    process.env.CLOUDFLARE_ACCESS_TEAM_DOMAIN = TEST_ACCESS_TEAM_DOMAIN;
    process.env.CLOUDFLARE_ACCESS_AUD = TEST_ACCESS_AUD;
    process.env.ACCESS_TRUSTED_EMAIL_DOMAIN = 'example.com';
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('rejects email-only Access header', async () => {
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(
      makeReq({ 'cf-access-authenticated-user-email': 'Analyst@Example.COM' }),
      res,
      next
    );
    expect(res.statusCode).toBe(401);
    expect((res as any).body.code).toBe('UNAUTHORIZED');
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects Access without a JWT assertion', async () => {
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({}), res, next);
    expect(res.statusCode).toBe(401);
    expect((res as any).body.code).toBe('UNAUTHORIZED');
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects an invalid Access JWT assertion', async () => {
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({ 'cf-access-jwt-assertion': 'not-a-jwt' }), res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects Access JWT with the wrong audience', async () => {
    const token = await makeAccessToken(
      { email: 'Analyst@Example.COM' },
      { audience: 'wrong-access-aud' }
    );
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({ 'cf-access-jwt-assertion': token }), res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('accepts a signed Access JWT with an email from the trusted domain', async () => {
    const token = await makeAccessToken({ email: 'Analyst@Example.COM' });
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    const req = makeReq({ 'cf-access-jwt-assertion': token });
    await authenticate(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.user).toEqual({
      sub: 'access-user-123',
      email: 'Analyst@Example.COM',
      groups: [],
      tokenUse: 'access',
    });
  });

  it('rejects a signed Access JWT whose email is outside the trusted domain', async () => {
    const token = await makeAccessToken({ email: 'user@other.example' });
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({ 'cf-access-jwt-assertion': token }), res, next);
    expect(res.statusCode).toBe(401);
    expect(next).not.toHaveBeenCalled();
  });

  describe('trust-center sync service token', () => {
    const CLIENT_ID = `${'a'.repeat(32)}.access`;

    it('accepts the configured service token as the sync, with no role', async () => {
      process.env.TRUST_CENTER_SYNC_CLIENT_ID = CLIENT_ID;
      const token = await makeAccessToken({ common_name: CLIENT_ID, sub: '' });
      const { authenticate } = await import('../middleware/auth');
      const { hasRole, Role } = await import('../middleware/rbac');
      const next = jest.fn();
      const req = makeReq({ 'cf-access-jwt-assertion': token });
      await authenticate(req, makeRes(), next);
      expect(next).toHaveBeenCalled();
      expect(req.user).toEqual({
        sub: `service-token:${CLIENT_ID}`,
        groups: [],
        tokenUse: 'access',
        serviceToken: true,
      });
      expect(hasRole(req, Role.Viewer)).toBe(false);
    });

    it.each([
      ['another service token', { common_name: `${'b'.repeat(32)}.access` }, CLIENT_ID],
      ['no client ID configured', { common_name: CLIENT_ID }, undefined],
      [
        'a token that also carries an untrusted email',
        { common_name: CLIENT_ID, email: 'x@other.example' },
        CLIENT_ID,
      ],
    ])('rejects %s', async (_name, claims, configured) => {
      if (configured) process.env.TRUST_CENTER_SYNC_CLIENT_ID = configured;
      const token = await makeAccessToken(claims);
      const { authenticate } = await import('../middleware/auth');
      const next = jest.fn();
      const res = makeRes();
      await authenticate(makeReq({ 'cf-access-jwt-assertion': token }), res, next);
      expect(res.statusCode).toBe(401);
      expect(next).not.toHaveBeenCalled();
    });

    it('rejects the service token with the wrong audience', async () => {
      process.env.TRUST_CENTER_SYNC_CLIENT_ID = CLIENT_ID;
      const token = await makeAccessToken({ common_name: CLIENT_ID }, { audience: 'other-app' });
      const { authenticate } = await import('../middleware/auth');
      const next = jest.fn();
      const res = makeRes();
      await authenticate(makeReq({ 'cf-access-jwt-assertion': token }), res, next);
      expect(res.statusCode).toBe(401);
      expect(next).not.toHaveBeenCalled();
    });
  });

  it('accepts any verified Access email when no trusted domain is configured', async () => {
    delete process.env.ACCESS_TRUSTED_EMAIL_DOMAIN;
    const token = await makeAccessToken({ email: 'user@anywhere.example' });
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    const req = makeReq({ 'cf-access-jwt-assertion': token });
    await authenticate(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.user?.email).toBe('user@anywhere.example');
  });

  it('rejects Access when team domain or AUD is missing and Cognito is configured', async () => {
    delete process.env.CLOUDFLARE_ACCESS_TEAM_DOMAIN;
    delete process.env.CLOUDFLARE_ACCESS_AUD;
    const token = await makeAccessToken({ email: 'Analyst@Example.COM' });
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(makeReq({ 'cf-access-jwt-assertion': token }), res, next);
    expect(res.statusCode).toBe(401);
    expect((res as any).body.code).toBe('UNAUTHORIZED');
    expect(next).not.toHaveBeenCalled();
  });

  it('returns AUTH_NOT_CONFIGURED when neither Cognito nor Access is configured', async () => {
    delete process.env.COGNITO_USER_POOL_ID;
    delete process.env.COGNITO_CLIENT_ID;
    delete process.env.CLOUDFLARE_ACCESS_TEAM_DOMAIN;
    delete process.env.CLOUDFLARE_ACCESS_AUD;
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(
      makeReq({ 'cf-access-authenticated-user-email': 'Analyst@Example.COM' }),
      res,
      next
    );
    expect(res.statusCode).toBe(500);
    expect((res as any).body.code).toBe('AUTH_NOT_CONFIGURED');
    expect(next).not.toHaveBeenCalled();
  });

  it('does not trust the email header when Cognito is unset and Access is configured', async () => {
    delete process.env.COGNITO_USER_POOL_ID;
    delete process.env.COGNITO_CLIENT_ID;
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    await authenticate(
      makeReq({ 'cf-access-authenticated-user-email': 'Analyst@Example.COM' }),
      res,
      next
    );
    expect(res.statusCode).toBe(401);
    expect((res as any).body.code).toBe('UNAUTHORIZED');
    expect(next).not.toHaveBeenCalled();
  });

  it('accepts Access JWT when Cognito is unset', async () => {
    delete process.env.COGNITO_USER_POOL_ID;
    delete process.env.COGNITO_CLIENT_ID;
    const token = await makeAccessToken({ email: 'Analyst@Example.COM' });
    const { authenticate } = await import('../middleware/auth');
    const next = jest.fn();
    const res = makeRes();
    const req = makeReq({
      authorization: 'Bearer leftover',
      'cf-access-jwt-assertion': token,
    });
    await authenticate(req, res, next);
    expect(next).toHaveBeenCalled();
    expect(req.user?.email).toBe('Analyst@Example.COM');
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
