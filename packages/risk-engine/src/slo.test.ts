import { issueSlo, SLO_WINDOW_DAYS } from './slo';

const NOW = new Date('2026-10-28T12:00:00Z');
const issue = (severity: 'critical' | 'high' | 'medium' | 'low', daysAgo: number) => ({
  severity,
  createdAt: new Date(NOW.getTime() - daysAgo * 86_400_000).toISOString(),
});

describe('issueSlo', () => {
  it('uses the severity window and reports the burn deterministically', () => {
    const slo = issueSlo(issue('high', 15), NOW);
    expect(slo).toEqual({
      windowDays: 30,
      ageDays: 15,
      burn: 0.5,
      state: 'ok',
      breachInDays: 15,
    });
  });

  it('flips to burning at the threshold and breached past the window', () => {
    expect(issueSlo(issue('critical', 5.6), NOW).state).toBe('burning');
    expect(issueSlo(issue('critical', 7), NOW).state).toBe('burning');
    expect(issueSlo(issue('critical', 7.1), NOW).state).toBe('breached');
    expect(issueSlo(issue('critical', 7.1), NOW).breachInDays).toBe(0);
  });

  it('windows grow with lower severity', () => {
    expect(SLO_WINDOW_DAYS.critical).toBeLessThan(SLO_WINDOW_DAYS.high);
    expect(SLO_WINDOW_DAYS.high).toBeLessThan(SLO_WINDOW_DAYS.medium);
    expect(SLO_WINDOW_DAYS.medium).toBeLessThan(SLO_WINDOW_DAYS.low);
  });

  it('treats an unparseable createdAt as brand new rather than failing', () => {
    const slo = issueSlo({ severity: 'low', createdAt: 'not-a-date' }, NOW);
    expect(slo.ageDays).toBe(0);
    expect(slo.state).toBe('ok');
  });
});
