import {
  ACCESS_DENIED_BASELINE_DAYS,
  ACCESS_DENIED_MIN_COUNT,
  ACCESS_DENIED_SPIKE_THRESHOLD,
  detectDeniedSpikes,
  parseDeniedCountRow,
  type DailyDeniedCount,
} from './baseline';

// Fixed clock: the evaluation window is Oct 14-20, the baseline Sep 14-Oct 13.
const NOW = new Date('2026-10-20T12:00:00Z');
const principal = 'arn:aws:sts::111122223333:assumed-role/Deployer/session-1';
const ip = '198.51.100.7';

function day(offsetFromEvalEnd: number): string {
  return new Date(Date.parse('2026-10-20T00:00:00Z') + offsetFromEvalEnd * 86_400_000)
    .toISOString()
    .slice(0, 10);
}

function row(
  dayText: string,
  count: number,
  principalArn = principal,
  sourceIp = ip
): DailyDeniedCount {
  return {
    principalArn,
    sourceIp,
    day: dayText,
    count,
    firstSeen: `${dayText}T01:00:00Z`,
    lastSeen: `${dayText}T02:00:00Z`,
  };
}

// Every day of the baseline carrying the same count, plus eval days.
function steady(baselineCount: number, evalCounts: number[]): DailyDeniedCount[] {
  const rows: DailyDeniedCount[] = [];
  for (let offset = -36; offset <= -7; offset++) rows.push(row(day(offset), baselineCount));
  evalCounts.forEach((count, index) => rows.push(row(day(-6 + index), count)));
  return rows;
}

describe('detectDeniedSpikes', () => {
  it('does not flag a steady principal at its normal level', () => {
    expect(detectDeniedSpikes(steady(25, [25, 24, 26, 25]), NOW)).toEqual([]);
    expect(detectDeniedSpikes(steady(25, [28, 31]), NOW)).toEqual([]);
  });

  it('flags a steady principal only well above its own level', () => {
    const [record] = detectDeniedSpikes(steady(25, [25, 33]), NOW);
    expect(record).toMatchObject({
      type: 'ACCESS_DENIED_SPIKE',
      principalArn: principal,
      sourceIp: ip,
      eventCount: 33,
      basis: 'baseline',
      baselineMean: 25,
      baselineStddev: 0,
      baselineDays: ACCESS_DENIED_BASELINE_DAYS,
    });
  });

  it('flags a quiet principal the old fixed threshold missed', () => {
    const rows = [row(day(-30), 1), row(day(-4), 12)];

    const [record] = detectDeniedSpikes(rows, NOW);

    expect(record).toMatchObject({ eventCount: 12, basis: 'baseline' });
    expect(record.eventCount).toBeLessThan(ACCESS_DENIED_SPIKE_THRESHOLD);
  });

  it('leaves a noisy principal at its usual burst size alone and flags the outlier', () => {
    const noisy: DailyDeniedCount[] = [];
    for (let offset = -36; offset <= -7; offset++) {
      noisy.push(row(day(offset), offset % 2 === 0 ? 40 : 0));
    }

    expect(detectDeniedSpikes([...noisy, row(day(-3), 50)], NOW)).toEqual([]);
    const [spike] = detectDeniedSpikes([...noisy, row(day(-3), 100)], NOW);
    expect(spike.eventCount).toBe(100);
    expect(spike.baselineStddev).toBeGreaterThan(0);
    expect(spike.deviation).toBeGreaterThan(3);
  });

  it('falls back to the fixed threshold while the baseline is cold', () => {
    const cold = [row(day(-4), 12), row(day(-2), 12), row(day(-1), 21)];

    const spikes = detectDeniedSpikes(cold, NOW);

    expect(spikes).toHaveLength(1);
    expect(spikes[0]).toMatchObject({
      eventCount: 21,
      basis: 'cold-start',
      baselineDays: expect.any(Number),
    });
    expect(spikes[0].baselineDays).toBeLessThan(7);
  });

  it('reports the worst evaluation day per principal and IP', () => {
    const rows = [row(day(-30), 2), row(day(-6), 11), row(day(-2), 40), row(day(-1), 15)];

    const [record] = detectDeniedSpikes(rows, NOW);

    expect(record.eventCount).toBe(40);
    expect(record.firstSeen).toBe(`${day(-2)}T01:00:00Z`);
  });

  it('keeps principals and IPs apart', () => {
    const other = row(day(-2), 40, principal, '203.0.113.9');
    const rows = [row(day(-30), 1), row(day(-2), 12), other];

    const spikes = detectDeniedSpikes(rows, NOW);

    expect(spikes.map((spike) => spike.sourceIp).sort()).toEqual(['198.51.100.7', '203.0.113.9']);
  });

  it('returns nothing for an empty window', () => {
    expect(detectDeniedSpikes([], NOW)).toEqual([]);
  });

  it('keeps the floor for tiny baselines', () => {
    const rows = [row(day(-31), 1), row(day(-20), 1), row(day(-2), 9)];
    expect(detectDeniedSpikes(rows, NOW)).toEqual([]);
    const [flagged] = detectDeniedSpikes(
      [row(day(-31), 1), row(day(-20), 1), row(day(-2), ACCESS_DENIED_MIN_COUNT)],
      NOW
    );
    expect(flagged.eventCount).toBe(ACCESS_DENIED_MIN_COUNT);
  });
});

describe('parseDeniedCountRow', () => {
  const data = (values: string[]) => values.map((VarCharValue) => ({ VarCharValue }));

  it('parses a well-formed daily row', () => {
    expect(
      parseDeniedCountRow(
        data([principal, ip, '2026-10-18', '12', '2026-10-18T01:00:00Z', '2026-10-18T02:00:00Z']),
        2
      )
    ).toEqual({
      principalArn: principal,
      sourceIp: ip,
      day: '2026-10-18',
      count: 12,
      firstSeen: '2026-10-18T01:00:00Z',
      lastSeen: '2026-10-18T02:00:00Z',
    });
  });

  it.each([
    ['short row', data([principal, ip, '2026-10-18', '12', 'x'])],
    ['bad day', data([principal, ip, '18/10/2026', '12', '2026-10-18T01:00:00Z', 'x'])],
    ['non-numeric count', data([principal, ip, '2026-10-18', 'x', 'x', 'x'])],
    ['zero count', data([principal, ip, '2026-10-18', '0', 'x', 'x'])],
    ['bad timestamp', data([principal, ip, '2026-10-18', '12', 'nope', 'x'])],
  ])('rejects %s', (_label, values) => {
    expect(() => parseDeniedCountRow(values, 3)).toThrow('Invalid Athena denied-count row 3');
  });
});
