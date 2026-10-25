import type { RiskScoreInput } from './types';

// Explainable v1 path likelihood: the product of four independent 0..1
// factors, deliberately not a calibrated probability. The factors are
// persisted with the value so a ranking can be argued with, and calibration
// against outcomes (was the path ever used?) is a later phase. Severity
// (computeRiskScore) stays the impact judgement; likelihood is the "how
// plausible is this route" judgement beside it.
export interface PathLikelihoodFactors {
  /** Internet 1, cross-account 0.7, internal 0.3. */
  exposure: number;
  /** Admin 1, wildcard 0.9, cross-account 0.7, service-linked 0.4, none 0.5. */
  privilege: number;
  /** CVSS/10, +0.2 when an exploit is known, capped at 1; no data 0.5. */
  exploitability: number;
  /** 1 when exposure was derived from complete data, 0.5 when a vertex says it was not. */
  reachability: number;
}

export interface PathLikelihood {
  /** Product of the factors, 0..1, rounded to 4 decimals. */
  value: number;
  factors: PathLikelihoodFactors;
}

const EXPOSURE: Record<RiskScoreInput['exposureLevel'], number> = {
  internet: 1,
  'cross-account': 0.7,
  internal: 0.3,
};

const PRIVILEGE: Record<NonNullable<RiskScoreInput['identityBlastRadius']>['type'], number> = {
  admin: 1,
  wildcard: 0.9,
  'cross-account': 0.7,
  'service-linked': 0.4,
};

// Unknown is a mid-value, not zero: a reachable path whose identity or
// vulnerability detail was not collected is less likely than an admin path
// with a known exploit and more likely than a scoped one.
const UNKNOWN = 0.5;

export function pathLikelihood(input: RiskScoreInput): PathLikelihood {
  const exposure = EXPOSURE[input.exposureLevel];
  const privilege = input.identityBlastRadius ? PRIVILEGE[input.identityBlastRadius.type] : UNKNOWN;

  let exploitability = UNKNOWN;
  if (input.exploitability) {
    const cvss = input.exploitability.cvssBaseScore;
    let value = typeof cvss === 'number' && Number.isFinite(cvss) ? cvss / 10 : UNKNOWN;
    if (input.exploitability.exploitAvailable) value += 0.2;
    exploitability = Math.min(1, Math.max(0, value));
  }

  const reachability = input.reachabilityRestricted ? UNKNOWN : 1;

  return {
    value: Math.round(exposure * privilege * exploitability * reachability * 10000) / 10000,
    factors: { exposure, privilege, exploitability, reachability },
  };
}
