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
  /** Issues an independent detector (Security Hub / GuardDuty) corroborated. */
  corroborated?: number;
  /** Issues the runner could label at all (corroborated + not corroborated). */
  labeled?: number;
}

export type RuleQualityVerdict = 'insufficient-data' | 'reliable' | 'mixed' | 'noisy';

export interface RuleQuality extends RuleStatusCounts {
  ruleId: string;
  /** Closed outcomes: suppressed + resolved. */
  handled: number;
  /** suppressed / handled, rounded to 3 decimals; null until something closed. */
  dismissalRate: number | null;
  /**
   * corroborated / labeled — the share of this rule's labelled issues whose
   * resources an independent detector flagged too. A corroboration proxy, not
   * ground-truth precision; published beside the dismissal rate, and the
   * verdict deliberately stays dismissal-based until the label volume and a
   * calibration decision support moving it.
   */
  corroborationRate: number | null;
  verdict: RuleQualityVerdict;
}

// A verdict needs enough closed outcomes to mean anything, and the thresholds
// are deliberately explicit so a calibration change is an edit to constants
// with the report as evidence, not a judgement call buried in code.
export const RULE_QUALITY_MIN_HANDLED = 10;
export const RULE_QUALITY_RELIABLE_DISMISSAL_RATE = 0.2;
export const RULE_QUALITY_NOISY_DISMISSAL_RATE = 0.5;
// Below this many labelled issues a corroboration rate is noise, so none is
// published (null) rather than a tiny-sample percentage.
export const CORROBORATION_MIN_LABELED = 5;

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
      const labeled = status.labeled ?? 0;
      const corroborationRate =
        labeled >= CORROBORATION_MIN_LABELED
          ? Math.round(((status.corroborated ?? 0) / labeled) * 1000) / 1000
          : null;
      return { ruleId, ...status, handled, dismissalRate, corroborationRate, verdict };
    })
    .sort(
      (a, b) =>
        VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict] ||
        b.handled - a.handled ||
        a.ruleId.localeCompare(b.ruleId)
    );
}
