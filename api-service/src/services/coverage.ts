import {
  COVERAGE_AGING_HOURS,
  COVERAGE_FRESH_HOURS,
  coverageLevelForAge,
  type CoverageLevel,
} from '@khalifa/risk-engine';
import type { GraphVertex } from '../types';

// Every predictive surface states how fresh the graph it read is, so a
// count computed from a days-old collection cannot look confident. The
// thresholds and levels are shared with the likelihood they temper
// (@khalifa/risk-engine coverage.ts) so grading never drifts.
export type { CoverageLevel };
export { COVERAGE_AGING_HOURS, COVERAGE_FRESH_HOURS };

export interface CoverageStatement {
  level: CoverageLevel;
  latestSuccessAt?: string;
  ageHours?: number;
  note: string;
}

export function coverageFromVertices(
  coverage: GraphVertex[],
  now: Date = new Date()
): CoverageStatement {
  const completions = coverage
    .filter(
      (vertex) =>
        vertex.properties?.service === 'resource-inventory' &&
        vertex.properties?.status === 'SUCCEEDED' &&
        typeof vertex.properties?.completed_at === 'string'
    )
    .map((vertex) => Date.parse(vertex.properties.completed_at as string))
    .filter((time) => Number.isFinite(time));

  if (completions.length === 0) {
    return {
      level: 'unknown',
      note: 'No completed resource collection is recorded, so this prediction has no coverage statement.',
    };
  }

  const latest = new Date(Math.max(...completions));
  const ageHours = Math.round(((now.getTime() - latest.getTime()) / 3_600_000) * 10) / 10;
  const level = coverageLevelForAge(Math.max(0, ageHours));
  const note =
    level === 'fresh'
      ? `Newest complete collection ${ageHours}h ago.`
      : `Newest complete collection ${ageHours}h ago; treat the counts as ${level} evidence.`;
  return { level, latestSuccessAt: latest.toISOString(), ageHours, note };
}

// Failure-tolerant by construction: an unreadable graph is "unknown", never a
// failed prediction.
export async function graphCoverage(
  client: { listCollectionCoverage(): Promise<GraphVertex[]> },
  now: Date = new Date()
): Promise<CoverageStatement> {
  try {
    return coverageFromVertices(await client.listCollectionCoverage(), now);
  } catch {
    return {
      level: 'unknown',
      note: 'Coverage could not be read, so this prediction has no coverage statement.',
    };
  }
}
