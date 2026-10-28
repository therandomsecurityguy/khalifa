import type { Severity } from './types';

// Per-issue risk windows: how long each severity class may stay open before
// the finding has burned its SLA budget. The windows are deliberate policy,
// not measurements — a critical reaches exploitation faster than a low, so
// its window is a week and a low's is half a year — and every derived number
// is deterministic from the issue's own createdAt.
export const SLO_WINDOW_DAYS: Record<Severity, number> = {
  critical: 7,
  high: 30,
  medium: 90,
  low: 180,
};

// Past this fraction of the window the issue is burning (a warning band);
// past 1.0 it has breached.
export const SLO_BURNING_THRESHOLD = 0.8;

export type SloState = 'ok' | 'burning' | 'breached';

export interface IssueSlo {
  windowDays: number;
  ageDays: number;
  /** ageDays / windowDays, rounded to 2 decimals. */
  burn: number;
  state: SloState;
  /** Whole days until burn reaches 1.0; 0 once breached. */
  breachInDays: number;
}

const DAY_MS = 86_400_000;

export function issueSlo(
  issue: { severity: Severity; createdAt: string },
  now: Date = new Date()
): IssueSlo {
  const windowDays = SLO_WINDOW_DAYS[issue.severity] ?? SLO_WINDOW_DAYS.medium;
  const createdMs = Date.parse(issue.createdAt);
  const ageMs = Number.isFinite(createdMs) ? Math.max(0, now.getTime() - createdMs) : 0;
  const ageDays = Math.round((ageMs / DAY_MS) * 10) / 10;
  const burn = Math.round((ageDays / windowDays) * 100) / 100;
  const state: SloState = burn > 1 ? 'breached' : burn >= SLO_BURNING_THRESHOLD ? 'burning' : 'ok';
  const breachInDays = Math.max(0, Math.ceil(windowDays - ageDays));
  return { windowDays, ageDays, burn, state, breachInDays };
}
