import type { Request, Response, NextFunction } from 'express';
import { jwtVerify, createRemoteJWKSet, type JWTPayload } from 'jose';
import { verifyServiceToken } from '../services/service-token-store';

export const ACCESS_JWT_HEADER = 'cf-access-jwt-assertion';

const BEARER_PREFIX = 'Bearer';

// Header whitespace per RFC 9110 (SP / HTAB); the other `\s` characters cannot
// appear in a Node header value, but accepting them keeps this equivalent to
// the regex it replaces.
function isWhitespaceCharacter(character: string): boolean {
  return (
    character === ' ' ||
    character === '\t' ||
    character === '\n' ||
    character === '\r' ||
    character === '\f' ||
    character === '\v'
  );
}

/**
 * The token from an `Authorization: Bearer <token>` header, or null when the
 * header does not match. Extracted with a linear scan instead of
 * `/^Bearer\s+(.+)$/`: CodeQL flags that pattern (js/polynomial-redos) because
 * `\s+` and `.+` both match whitespace, so a long whitespace run makes the
 * engine backtrack quadratically. Semantics are unchanged: the value must
 * start with `Bearer` (case-sensitive), carry at least one whitespace
 * character, and a non-empty token; leading whitespace is skipped and the
 * token keeps any trailing characters verbatim.
 */
export function bearerToken(headerValue: string | undefined): string | null {
  const value = headerValue || '';
  if (!value.startsWith(BEARER_PREFIX)) return null;
  let start = BEARER_PREFIX.length;
  if (!isWhitespaceCharacter(value[start] ?? '')) return null;
  while (start < value.length && isWhitespaceCharacter(value[start])) start += 1;
  const token = value.slice(start);
  return token.length > 0 ? token : null;
}

export interface AuthenticatedUser {
  sub: string;
  email?: string;
  groups: string[];
  tokenUse: 'id' | 'access' | 'service';
  // Set only for the trust-center sync's Cloudflare Access service token. It
  // carries no email or groups, so hasRole() denies it every staff route.
  serviceToken?: boolean;
  // Set for a Khalifa automation token (see service-token-store.ts): the
  // token's id and the role it carries. Administrative roles cannot be
  // minted, so automation can never reach admin-only routes.
  automation?: { tokenId: string; role: 'viewer' | 'analyst' };
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
  const token = bearerToken(req.headers.authorization);
  const cognito = getCognitoConfig();
  const access = getAccessConfig();

  // A Khalifa automation token is self-describing and self-contained: it is
  // verified against its own store before any JWT path (it is never a JWT, and
  // the store — not Cognito — is its authenticator).
  if (token && token.startsWith('khalifa_')) {
    let verified;
    try {
      verified = await verifyServiceToken(token);
    } catch (error) {
      console.error('Service token verification failed:', error);
      res
        .status(503)
        .json({ code: 'AUTH_UNAVAILABLE', message: 'Authentication store unavailable' });
      return;
    }
    if (!verified) {
      rejectUnauthorized(res);
      return;
    }
    req.user = {
      sub: `automation:${verified.id}`,
      groups: [`khalifa-${verified.role}`],
      tokenUse: 'service',
      automation: { tokenId: verified.id, role: verified.role },
    };
    next();
    return;
  }

  if (token && cognito) {
    await verifyCognitoBearer(req, res, next, token, cognito);
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
