import { pathLikelihood } from './likelihood';
import type { RiskScoreInput } from './types';

const base: RiskScoreInput = {
  exposureLevel: 'internal',
  dataClassification: 'public',
  environment: 'dev',
  isCrownJewel: false,
};

describe('pathLikelihood', () => {
  it('multiplies the four factors', () => {
    const result = pathLikelihood({
      ...base,
      exposureLevel: 'internet',
      identityBlastRadius: { type: 'admin', scope: 1 },
      exploitability: { cvssBaseScore: 10 },
    });
    expect(result.factors).toEqual({
      exposure: 1,
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
