import { KhalifaApiClient, KhalifaApiError, queryString } from './client';
import type { KhalifaConfig } from './config';

const base: KhalifaConfig = { apiUrl: 'http://api.test', token: 'token-1', timeoutMs: 5_000 };

describe('queryString', () => {
  it('skips empty values and repeats arrays', () => {
    expect(queryString({ a: 1, b: undefined, c: '', d: null, e: [1, 2] })).toBe('?a=1&e=1&e=2');
    expect(queryString({})).toBe('');
  });
});

describe('KhalifaApiClient', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('sends the Bearer token when configured', () => {
    expect(new KhalifaApiClient(base).authHeaders()).toEqual({
      authorization: 'Bearer token-1',
    });
  });

  it('falls back to the Access JWT header', () => {
    const client = new KhalifaApiClient({ ...base, token: undefined, accessJwt: 'jwt-1' });
    expect(client.authHeaders()).toEqual({ 'cf-access-jwt-assertion': 'jwt-1' });
  });

  it('builds the URL, headers, and timeout signal for a read', async () => {
    const calls: Array<[string, RequestInit]> = [];
    global.fetch = jest.fn(async (url: string, init: RequestInit) => {
      calls.push([url, init]);
      return { ok: true, status: 200, json: async () => ({ items: [] }) };
    }) as unknown as typeof fetch;

    const result = await new KhalifaApiClient(base).get('/issues', {
      status: 'open',
      limit: 10,
      skip: undefined,
    });

    expect(result).toEqual({ items: [] });
    expect(calls[0][0]).toBe('http://api.test/issues?status=open&limit=10');
    expect(calls[0][1].headers).toMatchObject({
      accept: 'application/json',
      authorization: 'Bearer token-1',
    });
    expect(calls[0][1].signal).toBeInstanceOf(AbortSignal);
  });

  it('maps an API error body to a KhalifaApiError', async () => {
    global.fetch = jest.fn(async () => ({
      ok: false,
      status: 403,
      json: async () => ({ message: 'Forbidden', code: 'FORBIDDEN' }),
    })) as unknown as typeof fetch;

    await expect(new KhalifaApiClient(base).get('/issues')).rejects.toEqual(
      expect.objectContaining({ name: 'KhalifaApiError', status: 403, message: 'Forbidden' })
    );
  });

  it('falls back to the status code when the body is unreadable', async () => {
    global.fetch = jest.fn(async () => ({
      ok: false,
      status: 500,
      json: async () => {
        throw new Error('not json');
      },
    })) as unknown as typeof fetch;

    await expect(new KhalifaApiClient(base).get('/issues')).rejects.toThrow('HTTP 500');
  });

  it('reports unreachable and timed-out transport failures as status 0', async () => {
    global.fetch = jest
      .fn()
      .mockRejectedValue(new TypeError('fetch failed')) as unknown as typeof fetch;
    await expect(new KhalifaApiClient(base).get('/issues')).rejects.toEqual(
      expect.objectContaining({ status: 0, message: 'Khalifa API unreachable' })
    );

    const timeout = new Error('timed out');
    timeout.name = 'TimeoutError';
    global.fetch = jest.fn().mockRejectedValue(timeout) as unknown as typeof fetch;
    await expect(new KhalifaApiClient(base).get('/issues')).rejects.toEqual(
      expect.objectContaining({ status: 0, message: 'Khalifa API timed out after 5000ms' })
    );
  });

  it('checks liveness against /livez', async () => {
    const calls: string[] = [];
    global.fetch = jest.fn(async (url: string) => {
      calls.push(url);
      return { ok: true, status: 200, json: async () => ({ status: 'ok' }) };
    }) as unknown as typeof fetch;

    await new KhalifaApiClient(base).check();

    expect(calls).toEqual(['http://api.test/livez']);
  });

  it('is an Error subclass with the status exposed', () => {
    const error = new KhalifaApiError(404, 'missing');
    expect(error).toBeInstanceOf(Error);
    expect(error.status).toBe(404);
  });
});
