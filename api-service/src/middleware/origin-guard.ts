import type { Request, Response, NextFunction } from 'express';

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Browser origins allowed to call the API cross-origin, from a comma-separated
// environment value. Empty means none: the UI reaches the API same-origin
// through its proxy, so there is nothing to open by default.
export function allowedOrigins(environment: NodeJS.ProcessEnv = process.env): string[] {
  return (environment.CORS_ALLOWED_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

// Deny-by-default CORS: headers go out only for an explicitly allowlisted
// origin, and never with credentials — the API authenticates with Bearer
// tokens, not cookies, so `Access-Control-Allow-Credentials` would only add a
// footgun. `Vary: Origin` keeps caches from serving one origin's grant to
// another.
export function corsMiddleware(req: Request, res: Response, next: NextFunction): void {
  const origin = req.headers.origin;
  if (origin) {
    res.vary('Origin');
    if (allowedOrigins().includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    }
  }
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
}

// CSRF defense in depth for the cookie-authenticated edge: Cloudflare Access
// injects the verified-identity header from a browser session cookie, so a
// state-changing request that carries an `Origin` must come from an
// allowlisted one. Requests without `Origin` (scripts, MCP clients, tests)
// are unaffected — they carry no ambient browser authority to ride.
export function originGuard(req: Request, res: Response, next: NextFunction): void {
  if (!MUTATING_METHODS.has(req.method)) {
    next();
    return;
  }
  const origin = req.headers.origin;
  if (!origin || allowedOrigins().includes(origin)) {
    next();
    return;
  }
  res.status(403).json({ code: 'FORBIDDEN', message: 'Cross-origin request rejected' });
}
