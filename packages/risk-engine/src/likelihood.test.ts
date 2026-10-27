import { coverageLevelForAge } from './coverage';
import { pathLikelihood } from './likelihood';
import type { RiskScoreInput } from './types';

const base: RiskScoreInput = {
  exposureLevel: 'internal',
  dataClassification: 'public',
  environment: 'dev',
  isCrownJewel: false,
};

describe('pathLikelihood', () => {
  it('multiplies the five factors', () => {
    const result = pathLikelihood({
      ...base,
      exposureLevel: 'internet',
      identityBlastRadius: { type: 'admin', scope: 1 },
      exploitability: { cvssBaseScore: 10 },
    });
    expect(result.factors).toEqual({
      exposure: 1,
      coverage: 1,
      privilege: 1,
      exploitability: 1,
      reachability: 1,
    });
    expect(result.value).toBe(1);
  });

  it('uses mid-values for detail that was not collected', () => {
    const result = pathLikelihood({ ...base, exposureLevel: 'internet' });
    expect(result.factors.privilege).toBe(0.5);
    expect(result.factors.exploitability).toBe(0.5);
    expect(result.value).toBe(0.25);
  });

  it('halves the value when a vertex says reachability is unknown', () => {
    const derived = pathLikelihood({ ...base, exposureLevel: 'internet' });
    const restricted = pathLikelihood({
      ...base,
      exposureLevel: 'internet',
      reachabilityRestricted: true,
    });
    expect(restricted.factors.reachability).toBe(0.5);
    expect(restricted.value).toBe(Math.round(derived.value * 0.5 * 10000) / 10000);
  });

  it('adds the exploit bonus without exceeding 1 and ranks admin above scoped', () => {
    const exploit = pathLikelihood({
      ...base,
      exposureLevel: 'internet',
      exploitability: { cvssBaseScore: 9.5, exploitAvailable: true },
    });
    expect(exploit.factors.exploitability).toBe(1);

    const admin = pathLikelihood({
      ...base,
      exposureLevel: 'internet',
      identityBlastRadius: { type: 'admin', scope: 1 },
    });
    const scoped = pathLikelihood({
      ...base,
      exposureLevel: 'internet',
      identityBlastRadius: { type: 'service-linked', scope: 1 },
    });
    expect(admin.value).toBeGreaterThan(scoped.value);
  });

  it('ranks exposure above internal on otherwise identical paths', () => {
    const internet = pathLikelihood({ ...base, exposureLevel: 'internet' });
    const inside = pathLikelihood({ ...base, exposureLevel: 'internal' });
    expect(internet.value).toBeGreaterThan(inside.value);
  });
});

describe('pathLikelihood observed reachability', () => {
  const base: RiskScoreInput = {
    exposureLevel: 'internet',
    dataClassification: 'public',
    environment: 'dev',
    isCrownJewel: false,
  };

  it('keeps reachability at 1 when traffic was observed despite a restricted read', () => {
    const restricted = pathLikelihood({ ...base, reachabilityRestricted: true });
    const observed = pathLikelihood({
      ...base,
      reachabilityRestricted: true,
      reachabilityObserved: true,
    });
    expect(restricted.factors.reachability).toBe(0.5);
    expect(observed.factors.reachability).toBe(1);
    expect(observed.value).toBeGreaterThan(restricted.value);
  });
});

describe('coverage tempering', () => {
  const input: RiskScoreInput = {
    ...base,
    exposureLevel: 'internet',
    identityBlastRadius: { type: 'admin', scope: 1 },
  };

  it('discounts aging and stale graphs deterministically', () => {
    const fresh = pathLikelihood(input, 'fresh');
    const aging = pathLikelihood(input, 'aging');
    const stale = pathLikelihood(input, 'stale');

    expect(fresh.factors.coverage).toBe(1);
    expect(aging.factors.coverage).toBe(0.8);
    expect(stale.factors.coverage).toBe(0.5);
    expect(aging.value).toBeLessThan(fresh.value);
    expect(stale.value).toBeLessThan(aging.value);
  });

  it('labels unknown coverage without discounting it, and defaults to no tempering', () => {
    const unknown = pathLikelihood(input, 'unknown');
    const omitted = pathLikelihood(input);

    expect(unknown.factors.coverage).toBe(1);
    expect(omitted.factors.coverage).toBe(1);
    expect(unknown.value).toBe(omitted.value);
  });

  it('multiplies the tempered product with the other factors', () => {
    const result = pathLikelihood(
      { ...input, exploitability: { cvssBaseScore: 10, exploitAvailable: true } },
      'stale'
    );
    expect(result.value).toBe(0.5);
    expect(result.factors).toMatchObject({
      exposure: 1,
      privilege: 1,
      exploitability: 1,
      coverage: 0.5,
    });
  });
});

describe('coverageLevelForAge', () => {
  it('grades at the collector cadence boundaries', () => {
    expect(coverageLevelForAge(0)).toBe('fresh');
    expect(coverageLevelForAge(8)).toBe('fresh');
    expect(coverageLevelForAge(8.1)).toBe('aging');
    expect(coverageLevelForAge(72)).toBe('aging');
    expect(coverageLevelForAge(72.1)).toBe('stale');
  });
});
