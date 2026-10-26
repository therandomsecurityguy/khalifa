// Per-rule quality from the issue lifecycle. There is no ground-truth label
// today, so the honest available signal is the human one: an issue an analyst
// suppressed was judged not worth fixing (or accepted), while a resolved issue
// stopped matching on its own. dismissalRate = suppressed / handled is a
// proxy for noise, not precision — outcome labels from GuardDuty/Security Hub
// would make a true precision possible later.
export interface RuleStatusCounts {
  open: number;
  suppressed: number;
  resolved: number;
}

export type RuleQualityVerdict = 'insufficient-data' | 'reliable' | 'mixed' | 'noisy';

export interface RuleQuality extends RuleStatusCounts {
  ruleId: string;
  /** Closed outcomes: suppressed + resolved. */
  handled: number;
  /** suppressed / handled, rounded to 3 decimals; null until something closed. */
  dismissalRate: number | null;
  verdict: RuleQualityVerdict;
}

// A verdict needs enough closed outcomes to mean anything, and the thresholds
// are deliberately explicit so a calibration change is an edit to constants
// with the report as evidence, not a judgement call buried in code.
export const RULE_QUALITY_MIN_HANDLED = 10;
export const RULE_QUALITY_RELIABLE_DISMISSAL_RATE = 0.2;
export const RULE_QUALITY_NOISY_DISMISSAL_RATE = 0.5;

const VERDICT_ORDER: Record<RuleQualityVerdict, number> = {
  noisy: 0,
  mixed: 1,
  'insufficient-data': 2,
  reliable: 3,
};

export function buildRuleQuality(counts: Record<string, RuleStatusCounts>): RuleQuality[] {
  return Object.entries(counts)
    .map(([ruleId, status]) => {
      const handled = status.suppressed + status.resolved;
      const dismissalRate =
        handled > 0 ? Math.round((status.suppressed / handled) * 1000) / 1000 : null;
      let verdict: RuleQualityVerdict = 'insufficient-data';
      if (handled >= RULE_QUALITY_MIN_HANDLED && dismissalRate !== null) {
        if (dismissalRate <= RULE_QUALITY_RELIABLE_DISMISSAL_RATE) verdict = 'reliable';
        else if (dismissalRate >= RULE_QUALITY_NOISY_DISMISSAL_RATE) verdict = 'noisy';
        else verdict = 'mixed';
      }
      return { ruleId, ...status, handled, dismissalRate, verdict };
    })
    .sort(
      (a, b) =>
        VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict] ||
        b.handled - a.handled ||
        a.ruleId.localeCompare(b.ruleId)
    );
}
