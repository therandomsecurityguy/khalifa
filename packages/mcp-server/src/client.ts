import type { KhalifaConfig } from './config';

/**
 * A failed Khalifa API call. `status` is 0 for transport failures (unreachable
 * or timed out) so tool results can distinguish "the API said no" from
 * "the API was never reached".
 */
export class KhalifaApiError extends Error {
  constructor(
    public readonly status: number,
    message: string
  ) {
    super(message);
    this.name = 'KhalifaApiError';
  }
}

export function queryString(params: Record<string, unknown> = {}): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === '') continue;
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, String(item));
      continue;
    }
    search.append(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : '';
}

/**
 * Read-only client over the Khalifa REST API. The token is only ever placed in
 * a request header; it is never logged, and error messages come from the API's
 * own response body so failures read the same to an agent as to a person.
 */
export class KhalifaApiClient {
  constructor(private readonly config: KhalifaConfig) {}

  authHeaders(): Record<string, string> {
    if (this.config.token) return { authorization: `Bearer ${this.config.token}` };
    return { 'cf-access-jwt-assertion': this.config.accessJwt as string };
  }

  async get<T>(path: string, params?: Record<string, unknown>): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`${this.config.apiUrl}${path}${queryString(params)}`, {
        headers: { accept: 'application/json', ...this.authHeaders() },
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
    } catch (error) {
      const timedOut = error instanceof Error && error.name === 'TimeoutError';
      throw new KhalifaApiError(
        0,
        timedOut
          ? `Khalifa API timed out after ${this.config.timeoutMs}ms`
          : 'Khalifa API unreachable'
      );
    }
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      const message =
        typeof body.message === 'string' && body.message ? body.message : `HTTP ${response.status}`;
      throw new KhalifaApiError(response.status, message);
    }
    return (await response.json()) as T;
  }

  /** Used by `--check`: the API's unauthenticated liveness probe. */
  async check(): Promise<void> {
    await this.get('/livez');
  }
}
