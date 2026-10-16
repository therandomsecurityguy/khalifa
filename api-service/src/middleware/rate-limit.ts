import type { Request, Response } from 'express';
import { rateLimit } from 'express-rate-limit';

// The limiters only run behind authentication, so the caller identity is the
// natural bucket key. req.ip is deliberately NOT a fallback: behind the
// Cloudflare/ALB proxy chain it is either the shared proxy address (all
// clients collapse into one bucket) or spoofable via X-Forwarded-For if a
// trust proxy is configured. Unauthenticated callers (if a limiter is ever
// mounted before auth) share one conservative bucket instead.
const UNAUTHENTICATED_KEY = 'unauthenticated';

function keyGenerator(req: Request): string {
  return req.user?.sub ?? UNAUTHENTICATED_KEY;
}

function positiveInteger(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || !value.trim()) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

const WINDOW_MS = 60_000;

function createLimiter(
  fallbackLimit: number,
  envName: string,
  message: string,
  environment: NodeJS.ProcessEnv
) {
  return rateLimit({
    windowMs: WINDOW_MS,
    limit: positiveInteger(environment[envName], fallbackLimit, envName),
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator,
    validate: { xForwardedForHeader: false },
    handler: (_req: Request, res: Response) => {
      res.status(429).json({ code: 'RATE_LIMITED', message });
    },
  });
}

export function createRateLimiter(
  fallbackLimit: number,
  environment: NodeJS.ProcessEnv = process.env
) {
  return createLimiter(
    fallbackLimit,
    'RATE_LIMIT_PER_MINUTE',
    'Too many requests; slow down and retry later',
    environment
  );
}

export function createExpensiveRateLimiter(
  fallbackLimit: number,
  environment: NodeJS.ProcessEnv = process.env
) {
  return createLimiter(
    fallbackLimit,
    'RATE_LIMIT_EXPENSIVE_PER_MINUTE',
    'Too many requests to a resource-intensive endpoint; retry later',
    environment
  );
}

export const apiRateLimiter = createRateLimiter(600);
export const expensiveRateLimiter = createExpensiveRateLimiter(60);
