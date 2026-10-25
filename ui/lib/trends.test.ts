import {
  deltaTone,
  formatSigned,
  formatTrendDate,
  metricCopy,
  severityChips,
  summarizeTrend,
  TREND_METRICS,
} from './trends';

describe('trend copy and insight', () => {
  it('maps catalog ids to human names', () => {
    expect(metricCopy('openIssuesBySeverity').label).toBe('Open issues');
    expect(metricCopy('issuesResolved').href).toBe('/issues');
    expect(metricCopy('mttrHours').unit).toBe('hours');
    expect(metricCopy('adminPrincipals').href).toBe('/identity');
    expect(metricCopy('openRiskScore').lowerIsBetter).toBe(true);
  });

  it('formats ISO dates without timezone drift', () => {
    expect(formatTrendDate('2026-09-16')).toBe('Sep 16');
    expect(formatSigned(-2)).toBe('-2');
    expect(formatSigned(3)).toBe('+3');
  });

  it('explains a declining open-issue series', () => {
    const insight = summarizeTrend('openIssuesBySeverity', [
      { date: '2026-09-05', value: 3 },
      { date: '2026-09-15', value: 2 },
      { date: '2026-09-16', value: 1 },
    ]);

    expect(insight?.direction).toBe('improving');
    expect(insight?.headline).toBe('Open issues: 1 as of Sep 16.');
  });

  it('reads more resolved issues as improving', () => {
    const insight = summarizeTrend('issuesResolved', [
      { date: '2026-09-27', value: 4 },
      { date: '2026-09-28', value: 9 },
    ]);

    expect(insight?.direction).toBe('improving');
  });

  it('reads more opened issues as worsening', () => {
    const insight = summarizeTrend('issuesCreated', [
      { date: '2026-09-27', value: 4 },
      { date: '2026-09-28', value: 9 },
    ]);

    expect(insight?.direction).toBe('worsening');
  });

  it('shows severity changes, first-day counts, and nothing for old days', () => {
    const old = { date: '2026-09-26', value: 1275 };
    const first = {
      date: '2026-09-27',
      value: 1281,
      bySeverity: { critical: 39, high: 298, medium: 661, low: 283 },
    };
    const next = {
      date: '2026-09-28',
      value: 1361,
      bySeverity: { critical: 42, high: 318, medium: 701, low: 300 },
    };

    expect(severityChips(old, null)).toEqual([]);
    expect(severityChips(first, old).map((chip) => chip.text)).toEqual(['39', '298', '661', '283']);
    expect(severityChips(next, first)).toEqual([
      { severity: 'critical', text: '+3' },
      { severity: 'high', text: '+20' },
      { severity: 'medium', text: '+40' },
      { severity: 'low', text: '+17' },
    ]);
  });

  it('colors a delta by the metric direction', () => {
    expect(deltaTone(5, true)).toBe('bad');
    expect(deltaTone(-5, true)).toBe('good');
    expect(deltaTone(5, false)).toBe('good');
    expect(deltaTone(-5, false)).toBe('bad');
    expect(deltaTone(0, false)).toBe('neutral');
    expect(deltaTone(null, true)).toBe('neutral');
  });

  it('only lists metrics something writes', () => {
    expect(Object.keys(TREND_METRICS).sort()).toEqual([
      'adminPrincipals',
      'issuesCreated',
      'issuesResolved',
      'mttrHours',
      'openIssuesBySeverity',
      'openRiskScore',
    ]);
  });
});
