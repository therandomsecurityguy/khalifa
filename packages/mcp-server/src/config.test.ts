import { readConfig } from './config';

describe('readConfig', () => {
  it('reads a Bearer token and trims the API url', () => {
    const config = readConfig({
      KHALIFA_API_URL: 'http://localhost:8080/',
      KHALIFA_TOKEN: 'token-1',
    } as NodeJS.ProcessEnv);

    expect(config).toEqual({
      apiUrl: 'http://localhost:8080',
      token: 'token-1',
      accessJwt: undefined,
      timeoutMs: 15_000,
    });
  });

  it('accepts an Access JWT instead of a token, and a custom timeout', () => {
    const config = readConfig({
      KHALIFA_API_URL: 'https://api.example.com',
      KHALIFA_ACCESS_JWT: 'jwt-1',
      KHALIFA_TIMEOUT_MS: '30000',
    } as NodeJS.ProcessEnv);

    expect(config).toEqual({
      apiUrl: 'https://api.example.com',
      token: undefined,
      accessJwt: 'jwt-1',
      timeoutMs: 30_000,
    });
  });

  it.each([
    [{}, 'KHALIFA_API_URL is required'],
    [{ KHALIFA_API_URL: 'ftp://x', KHALIFA_TOKEN: 't' }, 'must start with http'],
    [{ KHALIFA_API_URL: 'http://x' }, 'Set KHALIFA_TOKEN'],
    [
      { KHALIFA_API_URL: 'http://x', KHALIFA_TOKEN: 't', KHALIFA_TIMEOUT_MS: '0' },
      'KHALIFA_TIMEOUT_MS',
    ],
    [
      { KHALIFA_API_URL: 'http://x', KHALIFA_TOKEN: 't', KHALIFA_TIMEOUT_MS: '99999999' },
      'KHALIFA_TIMEOUT_MS',
    ],
  ])('rejects %j with a named-field message', (environment, message) => {
    expect(() => readConfig(environment as NodeJS.ProcessEnv)).toThrow(message);
  });
});
