import {
  hashServiceSecret,
  mapServiceTokenRecord,
  parseServiceToken,
  parseServiceTokenInput,
  serviceSecretMatches,
} from '../services/service-token-store';

const UUID = '11111111-2222-3333-4444-555555555555';
// A hex-letter UUID, so the uppercase rejection below actually changes bytes.
const LETTER_UUID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const SECRET = 'a'.repeat(64);

describe('parseServiceToken', () => {
  it('splits a well-formed token into id and secret', () => {
    expect(parseServiceToken(`khalifa_${UUID}_${SECRET}`)).toEqual({ id: UUID, secret: SECRET });
  });

  it.each([
    [''],
    ['Bearer x'],
    [`khalifa_${UUID}`],
    [`khalifa_not-a-uuid_${SECRET}`],
    [`khalifa_${UUID}_short`],
    [`khalifa_${UUID}_${'z'.repeat(64)}`],
    [`khalifa_${LETTER_UUID.toUpperCase()}_${SECRET}`],
  ])('rejects %j', (token) => {
    expect(parseServiceToken(token)).toBeNull();
  });
});

describe('secret hashing', () => {
  it('hashes deterministically and compares in constant time', () => {
    const hash = hashServiceSecret(SECRET);

    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hashServiceSecret(SECRET)).toBe(hash);
    expect(serviceSecretMatches(SECRET, hash)).toBe(true);
    expect(serviceSecretMatches('b'.repeat(64), hash)).toBe(false);
    // A malformed stored hash must not throw; it simply fails to match.
    expect(serviceSecretMatches(SECRET, 'not-a-hash')).toBe(false);
  });
});

describe('parseServiceTokenInput', () => {
  it('applies the least-privilege defaults', () => {
    expect(parseServiceTokenInput({ name: ' ci pipeline ' })).toEqual({
      input: { name: 'ci pipeline', role: 'viewer', expiresInDays: 30 },
    });
  });

  it('accepts an analyst token with a custom expiry', () => {
    expect(parseServiceTokenInput({ name: 'sync', role: 'analyst', expiresInDays: 90 })).toEqual({
      input: { name: 'sync', role: 'analyst', expiresInDays: 90 },
    });
  });

  it.each([
    [{}, 'name is required'],
    [{ name: 'x'.repeat(121) }, 'name is required'],
    [{ name: 'x', role: 'admin' }, 'role must be one of'],
    [{ name: 'x', expiresInDays: 0 }, 'expiresInDays must be an integer between 1 and 90'],
    [{ name: 'x', expiresInDays: 91 }, 'expiresInDays must be an integer between 1 and 90'],
    [{ name: 'x', expiresInDays: 1.5 }, 'expiresInDays must be an integer between 1 and 90'],
  ])('rejects %j with a named-field message', (body, message) => {
    const parsed = parseServiceTokenInput(body as Record<string, unknown>);

    expect('error' in parsed && parsed.error).toContain(message);
  });
});

describe('mapServiceTokenRecord', () => {
  it('maps metadata and drops unknown roles to viewer', () => {
    const record = mapServiceTokenRecord({
      id: UUID,
      name: 'ci',
      role: 'superuser',
      createdAt: '2026-11-01T00:00:00.000Z',
      createdBy: 'admin@example.com',
      expiresAt: '2026-12-01T00:00:00.000Z',
      lastUsedAt: null,
      revokedAt: '2026-11-05T00:00:00.000Z',
    });

    expect(record).toEqual({
      id: UUID,
      name: 'ci',
      role: 'viewer',
      createdAt: '2026-11-01T00:00:00.000Z',
      createdBy: 'admin@example.com',
      expiresAt: '2026-12-01T00:00:00.000Z',
      lastUsedAt: null,
      revokedAt: '2026-11-05T00:00:00.000Z',
    });
  });

  it('degrades a malformed row to safe defaults', () => {
    const record = mapServiceTokenRecord({ id: 'x', lastUsedAt: 7 });

    expect(record).toMatchObject({ name: '', role: 'viewer', expiresAt: '', lastUsedAt: null });
  });
});
