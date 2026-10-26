import { buildRuleQuality, RULE_QUALITY_MIN_HANDLED } from './rule-quality';

describe('buildRuleQuality', () => {
  it('is insufficient-data below the minimum closed outcomes', () => {
    const [quality] = buildRuleQuality({ 'RULE-001': { open: 5, suppressed: 4, resolved: 1 } });
    expect(quality).toMatchObject({
      ruleId: 'RULE-001',
      open: 5,
      handled: 5,
      dismissalRate: 0.8,
      verdict: 'insufficient-data',
    });
  });

  it('is reliable when few closed issues were suppressed', () => {
    const [quality] = buildRuleQuality({
      'RULE-002': { open: 3, suppressed: 1, resolved: 19 },
    });
    expect(quality).toMatchObject({ handled: 20, dismissalRate: 0.05, verdict: 'reliable' });
  });

  it('is noisy when half or more closed issues were suppressed', () => {
    const [quality] = buildRuleQuality({
      'RULE-006': { open: 40, suppressed: 12, resolved: 8 },
    });
    expect(quality).toMatchObject({ dismissalRate: 0.6, verdict: 'noisy' });
  });

  it('is mixed between the thresholds and null-rate until something closes', () => {
    const [mixed] = buildRuleQuality({ 'RULE-010': { open: 1, suppressed: 3, resolved: 7 } });
    expect(mixed.verdict).toBe('mixed');

    const [nothingClosed] = buildRuleQuality({
      'RULE-020': { open: 9, suppressed: 0, resolved: 0 },
    });
    expect(nothingClosed).toMatchObject({
      handled: 0,
      dismissalRate: null,
      verdict: 'insufficient-data',
    });
  });

  it('sorts noisy first, then mixed, insufficient data, and reliable', () => {
    const quality = buildRuleQuality({
      'RULE-A': { open: 0, suppressed: 0, resolved: 12 },
      'RULE-B': { open: 0, suppressed: 6, resolved: 6 },
      'RULE-C': { open: 1, suppressed: 0, resolved: 0 },
      'RULE-D': { open: 0, suppressed: 3, resolved: 9 },
    });
    expect(quality.map((entry) => [entry.ruleId, entry.verdict])).toEqual([
      ['RULE-B', 'noisy'],
      ['RULE-D', 'mixed'],
      ['RULE-C', 'insufficient-data'],
      ['RULE-A', 'reliable'],
    ]);
  });

  it('keeps the minimum threshold meaningful', () => {
    expect(RULE_QUALITY_MIN_HANDLED).toBeGreaterThan(1);
  });
});
