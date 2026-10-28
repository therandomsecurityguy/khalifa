// Graph coverage vocabulary, shared by every surface that predicts: the API's
// coverage statements, the rule runner's likelihood tempering and the
// risk-plan report all grade freshness the same way. The thresholds follow
// the collector cadence: fresh is one collection window (two runs' worth,
// matching the compliance engine's COLLECTION_MAX_AGE_MS), aging is three
// days, stale is beyond that.
export type CoverageLevel = 'fresh' | 'aging' | 'stale' | 'unknown';

export const COVERAGE_FRESH_HOURS = 8;
export const COVERAGE_AGING_HOURS = 72;

export function coverageLevelForAge(ageHours: number): CoverageLevel {
  return ageHours <= COVERAGE_FRESH_HOURS
    ? 'fresh'
    : ageHours <= COVERAGE_AGING_HOURS
      ? 'aging'
      : 'stale';
}

// How much a coverage level tempers a likelihood. Fresh evidence is not
// punished, aging evidence is discounted, and stale evidence halves the
// plausibility. `unknown` is deliberately NOT discounted: no coverage
// statement (a fresh install, a read failure) is a *labelling* concern — the
// surfaces say so in words — while a stale graph is a *fact* that the score
// should carry. Callers with no level at all get 1, unchanged behavior.
export const COVERAGE_FACTORS: Record<CoverageLevel, number> = {
  fresh: 1,
  aging: 0.8,
  stale: 0.5,
  unknown: 1,
};

export function coverageFactor(level?: CoverageLevel): number {
  return level ? COVERAGE_FACTORS[level] : 1;
}
