import { coverageFactor, type CoverageLevel } from './coverage';
import { exploitabilityValue } from './exploitability';
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
  /** max(CVSS/10, EPSS), +0.2 when an exploit is known, capped at 1; no data 0.5. */
  exploitability: number;
  /**
   * 1 when exposure was derived (or observed traffic proves it), 0.5 when a
   * vertex says exposure or state could not be read.
   */
  reachability: number;
  /**
   * 1 when the graph is fresh (or no level was provided), 0.8 when aging,
   * 0.5 when stale: a prediction over evidence older than the collector
   * cadence should not read as confident. `unknown` coverage is labelled on
   * the surface rather than discounted — see coverage.ts.
   */
  coverage: number;
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

export function pathLikelihood(
  input: RiskScoreInput,
  coverageLevel?: CoverageLevel
): PathLikelihood {
  const exposure = EXPOSURE[input.exposureLevel];
  const privilege = input.identityBlastRadius ? PRIVILEGE[input.identityBlastRadius.type] : UNKNOWN;

  // Shared with the score (exploitability.ts): CVSS or EPSS, +0.2 for a known
  // exploit (Inspector or an imported KEV list).
  const exploitability = input.exploitability ? exploitabilityValue(input.exploitability) : UNKNOWN;

  // Observed traffic (the flow-log analyzer's facts on a workload) proves
  // reachability even when a restricted read left the configuration unknown:
  // confidence becomes observed AND configured, and observation wins.
  const reachability = input.reachabilityObserved ? 1 : input.reachabilityRestricted ? UNKNOWN : 1;

  // Freshness tempering: the same path over a stale graph is less plausible
  // evidence, so the level scales the product and rides along in the factors.
  const coverage = coverageFactor(coverageLevel);

  return {
    value:
      Math.round(exposure * privilege * exploitability * reachability * coverage * 10000) / 10000,
    factors: { exposure, privilege, exploitability, reachability, coverage },
  };
}
