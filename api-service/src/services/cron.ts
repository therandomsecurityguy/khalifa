// The next times a five-field cron schedule ("m h dom mon dow") fires, in an
// IANA time zone. Supports *, numbers, lists, ranges and steps, which is all
// the chart's CronJob schedules use.

const BOUNDS: Array<[number, number]> = [
  [0, 59],
  [0, 23],
  [1, 31],
  [1, 12],
  [0, 6],
];
const MAX_MINUTES = 8 * 24 * 60;

function field(spec: string, [min, max]: [number, number]): Set<number> {
  const values = new Set<number>();
  for (const part of spec.split(',')) {
    const [range, stepText] = part.split('/');
    const step = stepText === undefined ? 1 : Number(stepText);
    const [from, to] =
      range === '*'
        ? [min, max]
        : range.includes('-')
          ? range.split('-').map(Number)
          : [Number(range), stepText === undefined ? Number(range) : max];
    if (
      ![from, to, step].every(Number.isInteger) ||
      step < 1 ||
      from < min ||
      to > max ||
      from > to
    ) {
      throw new Error(`Invalid cron field: ${spec}`);
    }
    for (let value = from; value <= to; value += step) values.add(value);
  }
  return values;
}

export function nextRuns(schedule: string, timeZone: string, after: Date, count = 1): Date[] {
  const specs = schedule.trim().split(/\s+/);
  if (specs.length !== 5) throw new Error(`Invalid cron schedule: ${schedule}`);
  const [minutes, hours, days, months, weekdays] = specs.map((spec, i) => field(spec, BOUNDS[i]));
  const local = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    minute: 'numeric',
    hour: 'numeric',
    day: 'numeric',
    month: 'numeric',
    weekday: 'short',
  });
  const WEEKDAY: Record<string, number> = {
    Sun: 0,
    Mon: 1,
    Tue: 2,
    Wed: 3,
    Thu: 4,
    Fri: 5,
    Sat: 6,
  };

  const runs: Date[] = [];
  const start = Math.floor(after.getTime() / 60_000) * 60_000 + 60_000;
  for (let i = 0; i < MAX_MINUTES && runs.length < count; i++) {
    const at = new Date(start + i * 60_000);
    const parts = Object.fromEntries(local.formatToParts(at).map((p) => [p.type, p.value]));
    if (
      minutes.has(Number(parts.minute)) &&
      hours.has(Number(parts.hour)) &&
      days.has(Number(parts.day)) &&
      months.has(Number(parts.month)) &&
      weekdays.has(WEEKDAY[parts.weekday])
    ) {
      runs.push(at);
    }
  }
  return runs;
}
