import type { Request } from 'express';
import { allowedOrigins, corsMiddleware, originGuard } from '../middleware/origin-guard';

const ORIGIN = 'https://ui.example.com';

function request(method: string, headers: Record<string, string> = {}): Request {
  return { method, headers } as unknown as Request;
}

function response() {
  const res: any = {
    statusCode: 200,
    headers: {} as Record<string, string>,
    varied: [] as string[],
    setHeader(name: string, value: string) {
      this.headers[name.toLowerCase()] = value;
      return this;
    },
    vary(field: string) {
      this.varied.push(field);
      return this;
    },
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(body: unknown) {
      this.body = body;
      return this;
    },
    end() {
      this.ended = true;
      return this;
    },
  };
  return res;
}

afterEach(() => {
  delete process.env.CORS_ALLOWED_ORIGINS;
});

describe('allowedOrigins', () => {
  it('parses a comma-separated allowlist with trimming', () => {
    expect(
      allowedOrigins({
        CORS_ALLOWED_ORIGINS: ' https://a.example.com ,, https://b.example.com ',
      } as NodeJS.ProcessEnv)
    ).toEqual(['https://a.example.com', 'https://b.example.com']);
    expect(allowedOrigins({} as NodeJS.ProcessEnv)).toEqual([]);
  });
});

describe('corsMiddleware', () => {
  it('reflects only an allowlisted origin, never credentials, and varies on Origin', () => {
    process.env.CORS_ALLOWED_ORIGINS = ORIGIN;
    const res = response();
    const next = jest.fn();

    corsMiddleware(request('GET', { origin: ORIGIN }), res, next);

    expect(res.headers['access-control-allow-origin']).toBe(ORIGIN);
    expect(res.headers['access-control-allow-credentials']).toBeUndefined();
    expect(res.varied).toContain('Origin');
    expect(next).toHaveBeenCalled();
  });

  it('denies by default: no headers when the allowlist is empty or the origin differs', () => {
    delete process.env.CORS_ALLOWED_ORIGINS;
    const empty = response();
    corsMiddleware(request('GET', { origin: ORIGIN }), empty, jest.fn());
    expect(empty.headers['access-control-allow-origin']).toBeUndefined();
    expect(empty.varied).toContain('Origin');

    process.env.CORS_ALLOWED_ORIGINS = 'https://other.example.com';
    const other = response();
    corsMiddleware(request('GET', { origin: ORIGIN }), other, jest.fn());
    expect(other.headers['access-control-allow-origin']).toBeUndefined();
  });

  it('answers preflight without opening a disallowed origin', () => {
    process.env.CORS_ALLOWED_ORIGINS = 'https://other.example.com';
    const res = response();
    const next = jest.fn();

    corsMiddleware(request('OPTIONS', { origin: ORIGIN }), res, next);

    expect(res.statusCode).toBe(204);
    expect(res.ended).toBe(true);
    expect(res.headers['access-control-allow-origin']).toBeUndefined();
    expect(next).not.toHaveBeenCalled();
  });
});

describe('originGuard', () => {
  function run(method: string, headers: Record<string, string> = {}) {
    const res = response();
    const next = jest.fn();
    originGuard(request(method, headers), res, next);
    return { res, next };
  }

  it('allows mutations from an allowlisted origin', () => {
    process.env.CORS_ALLOWED_ORIGINS = ORIGIN;
    expect(run('POST', { origin: ORIGIN }).next).toHaveBeenCalled();
    expect(run('DELETE', { origin: ORIGIN }).next).toHaveBeenCalled();
  });

  it('rejects a browser mutation from a disallowed origin', () => {
    process.env.CORS_ALLOWED_ORIGINS = ORIGIN;
    const { res, next } = run('POST', { origin: 'https://evil.example.com' });

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(res.body).toMatchObject({ code: 'FORBIDDEN' });
  });

  it('rejects a browser mutation when no allowlist is configured', () => {
    delete process.env.CORS_ALLOWED_ORIGINS;
    const { res, next } = run('DELETE', { origin: ORIGIN });

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it('leaves origin-less clients and read methods alone', () => {
    delete process.env.CORS_ALLOWED_ORIGINS;
    expect(run('POST').next).toHaveBeenCalled();
    expect(run('GET', { origin: 'https://evil.example.com' }).next).toHaveBeenCalled();
  });
});
