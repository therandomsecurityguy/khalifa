import { nextRuns } from '../services/cron';

describe('nextRuns', () => {
  const after = new Date('2026-10-07T19:00:00Z');

  it('steps through an hourly range in UTC', () => {
    expect(nextRuns('30 2-22/4 * * *', 'UTC', after, 2).map((d) => d.toISOString())).toEqual([
      '2026-10-07T22:30:00.000Z',
      '2026-10-08T02:30:00.000Z',
    ]);
  });

  it('reads the hours in the schedule time zone', () => {
    // 19:00Z is 12:00 Pacific; the next slot is 14:30 Pacific (21:30Z).
    expect(nextRuns('30 2-22/4 * * *', 'America/Los_Angeles', after)[0].toISOString()).toBe(
      '2026-10-07T21:30:00.000Z'
    );
  });

  it('handles lists, single values and weekdays', () => {
    expect(nextRuns('0 9,17 * * 1', 'UTC', after)[0].toISOString()).toBe(
      '2026-10-12T09:00:00.000Z'
    );
    expect(nextRuns('0 2 * * *', 'UTC', after)[0].toISOString()).toBe('2026-10-08T02:00:00.000Z');
  });

  it('rejects schedules it cannot read', () => {
    expect(() => nextRuns('*/0 * * * *', 'UTC', after)).toThrow('Invalid cron field');
    expect(() => nextRuns('0 25 * * *', 'UTC', after)).toThrow('Invalid cron field');
    expect(() => nextRuns('@hourly', 'UTC', after)).toThrow('Invalid cron schedule');
  });
});
