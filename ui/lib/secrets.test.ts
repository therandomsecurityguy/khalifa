import type { SecretInventoryItem } from '@/types';
import {
  SECRET_FILTERS,
  compareSecrets,
  datesCollected,
  daysSince,
  facetValues,
  fixSteps,
  isRotationOff,
  lastAccessedLabel,
  matchesFacets,
  matchesSearch,
  severityCounts,
  sharingLabel,
} from './secrets';

const NOW = Date.parse('2026-10-22T00:00:00.000Z');

function issue(severity: SecretInventoryItem['issues'][number]['severity'], id: string = severity) {
  return {
    id,
    ruleId: 'RULE-010',
    severity,
    title: 'Shared',
    openedAt: '2026-10-01T00:00:00.000Z',
  };
}

function item(overrides: Partial<SecretInventoryItem> = {}): SecretInventoryItem {
  return {
    id: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:a',
    kind: 'secrets-manager',
    name: 'a',
    accountId: '111122223333',
    region: 'us-west-2',
    encryption: 'aws-managed',
    rotationEnabled: true,
    lastRotated: '2026-10-12T00:00:00.000Z',
    createdAt: null,
    lastAccessed: null,
    lastModified: null,
    collectionRestricted: false,
    env: null,
    owner: null,
    sharing: { scope: 'account', accounts: 0 },
    issues: [],
    ...overrides,
  };
}

describe('secret filters', () => {
  it('counts days since a timestamp, and none for a missing one', () => {
    expect(daysSince('2026-10-12T00:00:00.000Z', NOW)).toBe(10);
    expect(daysSince(null, NOW)).toBeNull();
  });

  it('treats never rotated as not rotated recently, with rotation on or off', () => {
    expect(SECRET_FILTERS.stale(item({ rotationEnabled: false, lastRotated: null }), NOW)).toBe(
      true
    );
    expect(SECRET_FILTERS.stale(item({ rotationEnabled: true, lastRotated: null }), NOW)).toBe(
      true
    );
    expect(SECRET_FILTERS.stale(item(), NOW)).toBe(false);
    expect(SECRET_FILTERS.stale(item({ lastRotated: '2026-06-01T00:00:00.000Z' }), NOW)).toBe(true);
  });

  it('never counts a parameter as rotation off or stale', () => {
    const parameter = item({ kind: 'ssm-parameter', rotationEnabled: null, lastRotated: null });
    expect(SECRET_FILTERS.rotationOff(parameter, NOW)).toBe(false);
    expect(SECRET_FILTERS.stale(parameter, NOW)).toBe(false);
  });

  it('labels each sharing scope', () => {
    expect(sharingLabel(item({ sharing: { scope: 'outside', accounts: 0 } }))).toBe(
      'Outside the org'
    );
    expect(sharingLabel(item({ sharing: { scope: 'collected', accounts: 2 } }))).toBe(
      '2 collected accounts'
    );
    expect(sharingLabel(item({ sharing: null }))).toBe('Unknown');
  });

  it('sorts the worst open issue first, then outside shares, then name', () => {
    const sorted = [
      item({ name: 'c' }),
      item({ name: 'b', sharing: { scope: 'outside', accounts: 0 } }),
      item({ name: 'a', issues: [issue('high')] }),
    ].sort(compareSecrets);
    expect(sorted.map((s) => s.name)).toEqual(['a', 'b', 'c']);
  });

  it('ages a never-rotated secret from its creation', () => {
    expect(
      SECRET_FILTERS.stale(item({ lastRotated: null, createdAt: '2026-10-01T00:00:00.000Z' }), NOW)
    ).toBe(false);
    expect(
      SECRET_FILTERS.stale(item({ lastRotated: null, createdAt: '2026-05-01T00:00:00.000Z' }), NOW)
    ).toBe(true);
  });

  it('counts a secret unused when last read 90+ days ago, or never read in 90+ days', () => {
    const old = '2026-05-01T00:00:00.000Z';
    expect(SECRET_FILTERS.unused(item({ createdAt: old, lastAccessed: old }), NOW)).toBe(true);
    expect(
      SECRET_FILTERS.unused(item({ createdAt: old, lastAccessed: '2026-10-20T00:00:00.000Z' }), NOW)
    ).toBe(false);
    expect(SECRET_FILTERS.unused(item({ createdAt: old, lastAccessed: null }), NOW)).toBe(true);
    expect(
      SECRET_FILTERS.unused(
        item({ createdAt: '2026-10-01T00:00:00.000Z', lastAccessed: null }),
        NOW
      )
    ).toBe(false);
  });

  it('says nothing about use before the collector recorded dates', () => {
    const uncollected = item({ createdAt: null, lastAccessed: null });
    expect(SECRET_FILTERS.unused(uncollected, NOW)).toBe(false);
    expect(lastAccessedLabel(uncollected, NOW)).toBe('Not collected yet');
    expect(lastAccessedLabel(item({ createdAt: '2026-01-01T00:00:00.000Z' }), NOW)).toBe('Never');
    expect(lastAccessedLabel(item({ lastAccessed: '2026-10-22T00:00:00.000Z' }), NOW)).toBe(
      'Today'
    );
    expect(lastAccessedLabel(item({ kind: 'ssm-parameter' }), NOW)).toBe('Not tracked');
  });

  it('treats a secret whose rotation was never configured as rotation off', () => {
    expect(isRotationOff(item({ rotationEnabled: null }))).toBe(true);
    expect(SECRET_FILTERS.rotationOff(item({ rotationEnabled: null }), NOW)).toBe(true);
    expect(isRotationOff(item({ rotationEnabled: true }))).toBe(false);
    expect(isRotationOff(item({ kind: 'ssm-parameter', rotationEnabled: null }))).toBe(false);
  });

  it('knows whether the collector has recorded dates yet', () => {
    expect(datesCollected([item({ createdAt: null })])).toBe(false);
    expect(datesCollected([item({ createdAt: '2026-01-01T00:00:00.000Z' })])).toBe(true);
  });

  it('counts open issues per severity, worst first, leaving out empty ones', () => {
    expect(
      severityCounts(
        item({ issues: [issue('low', 'a'), issue('critical', 'b'), issue('low', 'c')] })
      )
    ).toEqual([
      { severity: 'critical', count: 1 },
      { severity: 'low', count: 2 },
    ]);
  });

  it('matches column filters, any value within a column and every column together', () => {
    const secret = item({
      rotationEnabled: null,
      issues: [issue('high')],
      sharing: { scope: 'outside', accounts: 0 },
    });
    expect(facetValues('rotation', secret, NOW)).toEqual(['off']);
    expect(facetValues('issues', item(), NOW)).toEqual(['none']);
    expect(facetValues('access', item({ kind: 'ssm-parameter' }), NOW)).toEqual(['untracked']);
    expect(matchesFacets(secret, { rotation: ['on', 'off'], sharing: ['outside'] }, NOW)).toBe(
      true
    );
    expect(matchesFacets(secret, { rotation: ['off'], issues: ['critical'] }, NOW)).toBe(false);
    expect(matchesFacets(secret, { issues: ['critical'] }, NOW, 'issues')).toBe(true);
  });

  it('suggests fixes from the collected facts, most urgent first', () => {
    const steps = fixSteps(
      item({
        rotationEnabled: null,
        lastRotated: null,
        createdAt: '2025-10-22T00:00:00.000Z',
        lastAccessed: null,
        sharing: { scope: 'outside', accounts: 0 },
      }),
      NOW
    );
    expect(steps[0]).toMatch(/Remove the outside account/);
    expect(steps[1]).toBe('Turn on rotation. It has not changed in 365 days.');
    expect(steps[2]).toMatch(/Nothing has ever read it/);
    expect(fixSteps(item(), NOW)).toEqual([]);
  });

  it('treats a plain-text parameter as untracked for rotation, access and sharing', () => {
    const plain = item({
      kind: 'ssm-plaintext',
      encryption: 'none',
      rotationEnabled: null,
      sharing: null,
    });
    expect(SECRET_FILTERS.plaintext(plain, NOW)).toBe(true);
    expect(SECRET_FILTERS.rotationOff(plain, NOW)).toBe(false);
    expect(facetValues('rotation', plain, NOW)).toEqual(['none']);
    expect(facetValues('access', plain, NOW)).toEqual(['untracked']);
    expect(sharingLabel(plain)).toBe('Not tracked');
    expect(fixSteps(plain, NOW)[0]).toMatch(/SecureString parameter or Secrets Manager/);
  });

  it('searches name, ARN, account, region, env and owner, ignoring case', () => {
    const secret = item({ name: 'prod/api', env: 'prod', owner: 'payments' });
    for (const query of [
      'api',
      'secretsmanager:us-west-2',
      'billing',
      '111122223333',
      'us-west',
      'payments',
    ]) {
      expect(matchesSearch(secret, query, 'example.com - billing')).toBe(true);
    }
    expect(matchesSearch(secret, 'growth', 'example.com - billing')).toBe(false);
    expect(matchesSearch(secret, '', 'x')).toBe(true);
  });
});
