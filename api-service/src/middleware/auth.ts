import type { Request, Response, NextFunction } from 'express';
import { jwtVerify, createRemoteJWKSet, type JWTPayload } from 'jose';

export const ACCESS_JWT_HEADER = 'cf-access-jwt-assertion';

export interface AuthenticatedUser {
  sub: string;
  email?: string;
  groups: string[];
  tokenUse: 'id' | 'access';
  // Set only for the trust-center sync's Cloudflare Access service token. It
  // carries no email or groups, so hasRole() denies it every staff route.
  serviceToken?: boolean;
}

declare module 'express-serve-static-core' {
  interface Request {
    user?: AuthenticatedUser;
  }
}

function getCognitoConfig() {
  const userPoolId = process.env.COGNITO_USER_POOL_ID;
  const clientId = process.env.COGNITO_CLIENT_ID;
  const region = process.env.COGNITO_REGION || process.env.AWS_REGION || 'us-east-1';

  if (!userPoolId || !clientId) {
    return null;
  }

  return { userPoolId, clientId, region };
}

function getIssuer(region: string, userPoolId: string): string {
  return `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
}

let cachedJWKS: ReturnType<typeof createRemoteJWKSet> | null = null;
function getJWKS(issuer: string) {
  if (cachedJWKS) return cachedJWKS;
  const jwksUrl = new URL(`${issuer}/.well-known/jwks.json`);
  cachedJWKS = createRemoteJWKSet(jwksUrl);
  return cachedJWKS;
}

function getAccessConfig() {
  const teamDomain = process.env.CLOUDFLARE_ACCESS_TEAM_DOMAIN?.trim();
  const audience = process.env.CLOUDFLARE_ACCESS_AUD?.trim();
  if (!teamDomain || !audience) {
    return null;
  }

  const host = teamDomain.replace(/^https?:\/\//, '').replace(/\/$/, '');
  if (!host) {
    return null;
  }

  return {
    issuer: `https://${host}`,
    audience,
  };
}

let cachedAccessJWKS: ReturnType<typeof createRemoteJWKSet> | null = null;
function getAccessJWKS(issuer: string) {
  if (cachedAccessJWKS) return cachedAccessJWKS;
  cachedAccessJWKS = createRemoteJWKSet(new URL(`${issuer}/cdn-cgi/access/certs`));
  return cachedAccessJWKS;
}

function extractGroups(payload: JWTPayload): string[] {
  const groups = (payload as Record<string, unknown>)['cognito:groups'];
  if (Array.isArray(groups)) return groups.filter((g): g is string => typeof g === 'string');
  return [];
}

function headerValue(req: Request, name: string): string | undefined {
  const raw = req.headers[name];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value?.trim() || undefined;
}

// Restricts the verified-email identities the Access path trusts to one domain.
// Unset (the default) keeps the path usable with any email the Access team
// already vouches for: the Access policy is the gate, not this check.
export function isTrustedEmail(email?: string): email is string {
  if (!email) return false;
  const domain = process.env.ACCESS_TRUSTED_EMAIL_DOMAIN?.trim().toLowerCase();
  if (!domain) return true;
  const at = email.lastIndexOf('@');
  if (at <= 0 || at === email.length - 1) return false;
  return email.slice(at + 1).toLowerCase() === domain;
}

export async function accessTrustedUser(req: Request): Promise<AuthenticatedUser | null> {
  const config = getAccessConfig();
  if (!config) {
    return null;
  }

  const assertion = headerValue(req, ACCESS_JWT_HEADER);
  if (!assertion) {
    return null;
  }

  try {
    const { payload } = await jwtVerify(assertion, getAccessJWKS(config.issuer), {
      issuer: config.issuer,
      audience: config.audience,
    });
    const email = typeof payload.email === 'string' ? payload.email : undefined;
    if (!isTrustedEmail(email)) {
      return serviceTokenUser(payload);
    }
    return {
      sub: typeof payload.sub === 'string' && payload.sub ? payload.sub : email,
      email,
      groups: [],
      tokenUse: 'access',
    };
  } catch {
    return null;
  }
}

// A Cloudflare Access service token's JWT names the token's client ID in
// common_name and has no email. Only the one configured client ID is accepted.
function serviceTokenUser(payload: JWTPayload): AuthenticatedUser | null {
  const clientId = process.env.TRUST_CENTER_SYNC_CLIENT_ID?.trim();
  const commonName = (payload as Record<string, unknown>).common_name;
  if (!clientId || commonName !== clientId || payload.email !== undefined) {
    return null;
  }
  return {
    sub: `service-token:${clientId}`,
    groups: [],
    tokenUse: 'access',
    serviceToken: true,
  };
}

function rejectUnauthorized(res: Response): void {
  res.status(401).json({
    code: 'UNAUTHORIZED',
    message: 'A verified account email is required',
  });
}

function rejectNotConfigured(res: Response): void {
  res.status(500).json({
    code: 'AUTH_NOT_CONFIGURED',
    message: 'Authentication is not configured',
  });
}

export async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const auth = req.headers.authorization || '';
  const match = auth.match(/^Bearer\s+(.+)$/);
  const cognito = getCognitoConfig();
  const access = getAccessConfig();

  if (match && cognito) {
    await verifyCognitoBearer(req, res, next, match[1], cognito);
    return;
  }

  if (access) {
    const user = await accessTrustedUser(req);
    if (!user) {
      rejectUnauthorized(res);
      return;
    }
    req.user = user;
    next();
    return;
  }

  if (!cognito) {
    rejectNotConfigured(res);
    return;
  }

  rejectUnauthorized(res);
}

async function verifyCognitoBearer(
  req: Request,
  res: Response,
  next: NextFunction,
  token: string,
  config: { userPoolId: string; clientId: string; region: string }
): Promise<void> {
  const issuer = getIssuer(config.region, config.userPoolId);
  const jwks = getJWKS(issuer);

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience: config.clientId,
    });

    req.user = {
      sub: payload.sub || '',
      email: typeof payload.email === 'string' ? payload.email : undefined,
      groups: extractGroups(payload),
      tokenUse: payload.token_use === 'access' ? 'access' : 'id',
    };
    next();
  } catch (error) {
    const code = (error as { code?: string }).code || 'INVALID_TOKEN';
    const messages: Record<string, string> = {
      ERR_JWT_EXPIRED: 'Token has expired',
      ERR_JWS_INVALID: 'Token signature is invalid',
      ERR_JWT_CLAIM_VALIDATION_FAILED: 'Token claim validation failed (issuer/audience/exp)',
    };
    res.status(401).json({
      code,
      message: messages[code] || 'Token verification failed',
    });
  }
}

export function optionalAuthenticate(req: Request, _res: Response, next: NextFunction): void {
  const config = getCognitoConfig();
  if (!config) {
    next();
    return;
  }
  const auth = req.headers.authorization || '';
  const match = auth.match(/^Bearer\s+(.+)$/);
  if (!match) {
    next();
    return;
  }
  authenticate(req, _res, next).catch(next);
}
