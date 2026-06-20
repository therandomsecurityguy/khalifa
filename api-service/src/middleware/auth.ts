import type { Request, Response, NextFunction } from 'express';
import { jwtVerify, createRemoteJWKSet, type JWTPayload } from 'jose';

export interface AuthenticatedUser {
  sub: string;
  email?: string;
  groups: string[];
  tokenUse: 'id' | 'access';
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

function extractGroups(payload: JWTPayload): string[] {
  const groups = (payload as Record<string, unknown>)['cognito:groups'];
  if (Array.isArray(groups)) return groups.filter((g): g is string => typeof g === 'string');
  return [];
}

export async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const config = getCognitoConfig();
  if (!config) {
    res.status(500).json({
      code: 'AUTH_NOT_CONFIGURED',
      message:
        'Authentication is not configured (COGNITO_USER_POOL_ID / COGNITO_CLIENT_ID missing)',
    });
    return;
  }

  const auth = req.headers.authorization || '';
  const match = auth.match(/^Bearer\s+(.+)$/);
  if (!match) {
    res.status(401).json({
      code: 'MISSING_TOKEN',
      message: 'Authorization: Bearer <token> required',
    });
    return;
  }
  const token = match[1];

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
