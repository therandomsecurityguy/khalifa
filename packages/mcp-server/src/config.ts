export interface KhalifaConfig {
  apiUrl: string;
  /** Cognito access token, sent as `Authorization: Bearer`. */
  token?: string;
  /** Cloudflare Access JWT, sent as the `cf-access-jwt-assertion` header. */
  accessJwt?: string;
  timeoutMs: number;
}

const DEFAULT_TIMEOUT_MS = 15_000;

// A linear scan, not a regex: CodeQL flags `/\/+$/` as polynomial on
// operator-controlled input, and the fix is trivially cheaper.
function stripTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 47 /* '/' */) end -= 1;
  return value.slice(0, end);
}

/**
 * Configuration comes from the environment so the server holds no state and
 * the operator's existing token is the only credential. Exactly one of
 * KHALIFA_TOKEN / KHALIFA_ACCESS_JWT is needed; both are read but the Bearer
 * token wins when both are set.
 */
export function readConfig(environment: NodeJS.ProcessEnv = process.env): KhalifaConfig {
  const apiUrl = stripTrailingSlashes((environment.KHALIFA_API_URL || '').trim());
  if (!apiUrl) {
    throw new Error('KHALIFA_API_URL is required (for example http://localhost:8080)');
  }
  if (!/^https?:\/\//.test(apiUrl)) {
    throw new Error('KHALIFA_API_URL must start with http:// or https://');
  }
  const token = (environment.KHALIFA_TOKEN || '').trim() || undefined;
  const accessJwt = (environment.KHALIFA_ACCESS_JWT || '').trim() || undefined;
  if (!token && !accessJwt) {
    throw new Error(
      'Set KHALIFA_TOKEN (a Cognito access token) or KHALIFA_ACCESS_JWT (a Cloudflare Access JWT)'
    );
  }
  let timeoutMs = DEFAULT_TIMEOUT_MS;
  if (environment.KHALIFA_TIMEOUT_MS) {
    const parsed = Number(environment.KHALIFA_TIMEOUT_MS);
    if (!Number.isSafeInteger(parsed) || parsed < 1_000 || parsed > 120_000) {
      throw new Error('KHALIFA_TIMEOUT_MS must be an integer between 1000 and 120000');
    }
    timeoutMs = parsed;
  }
  return { apiUrl, token, accessJwt, timeoutMs };
}
