import type { NextFunction, Request, Response } from 'express';
import { createExpensiveRateLimiter, createRateLimiter } from '../middleware/rate-limit';

interface MockResponse {
  statusCode: number;
  body: unknown;
  status(code: number): MockResponse;
  json(payload: unknown): MockResponse;
}

function makeRes(): MockResponse {
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    headers: {} as Record<string, string | number>,
    setHeader(name: string, value: string | number) {
      this.headers[name.toLowerCase()] = value;
      return this;
    },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
    send(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
  return res;
}

function makeReq(userSub?: string): Request {
  return { user: userSub ? { sub: userSub } : undefined, ip: '10.0.0.1' } as unknown as Request;
}

function run(
  limiter: (req: Request, res: Response, next: NextFunction) => void,
  req: Request
): Promise<{ res: MockResponse; nexted: boolean }> {
  return new Promise((resolve) => {
    const res = makeRes();
    limiter(req, res as unknown as Response, () => resolve({ res, nexted: true }));
    setImmediate(() => resolve({ res, nexted: false }));
  });
}

describe('API rate limiters', () => {
  it('returns 429 with a JSON body once the per-identity limit is exhausted', async () => {
    const limiter = createRateLimiter(2, { RATE_LIMIT_PER_MINUTE: '2' });
    const identity = 'viewer-1';

    await run(limiter, makeReq(identity));
    await run(limiter, makeReq(identity));

    const { res, nexted } = await run(limiter, makeReq(identity));

    expect(nexted).toBe(false);
    expect(res.statusCode).toBe(429);
    expect(res.body).toMatchObject({ code: 'RATE_LIMITED' });
  });

  it('counts identities independently', async () => {
    const limiter = createRateLimiter(1, { RATE_LIMIT_PER_MINUTE: '1' });

    const first = await run(limiter, makeReq('viewer-1'));
    const second = await run(limiter, makeReq('viewer-2'));

    expect(first.nexted).toBe(true);
    expect(second.nexted).toBe(true);
  });

  it('exposes the expensive limiter as a separate bucket', async () => {
    const expensive = createExpensiveRateLimiter(1, { RATE_LIMIT_EXPENSIVE_PER_MINUTE: '1' });
    const general = createRateLimiter(10, { RATE_LIMIT_PER_MINUTE: '10' });

    const first = await run(expensive, makeReq('viewer-1'));
    const generalResult = await run(general, makeReq('viewer-1'));
    const blocked = await run(expensive, makeReq('viewer-1'));

    expect(first.nexted).toBe(true);
    expect(generalResult.nexted).toBe(true);
    expect(blocked.nexted).toBe(false);
    expect(blocked.res.statusCode).toBe(429);
  });

  it('shares one conservative bucket for unauthenticated callers instead of trusting proxy IPs', async () => {
    const limiter = createRateLimiter(1, { RATE_LIMIT_PER_MINUTE: '1' });

    const first = await run(limiter, makeReq());
    const second = await run(limiter, makeReq());

    // Both unauthenticated requests collapse into the shared bucket (no req.ip
    // reliance), while an identity bucket is unaffected.
    expect(first.nexted).toBe(true);
    expect(second.nexted).toBe(false);
    expect(second.res.statusCode).toBe(429);
  });

  it('rejects non-integer rate limit configuration at construction', () => {
    expect(() => createRateLimiter(10, { RATE_LIMIT_PER_MINUTE: 'many' })).toThrow(
      'RATE_LIMIT_PER_MINUTE must be a positive integer'
    );
  });
});
