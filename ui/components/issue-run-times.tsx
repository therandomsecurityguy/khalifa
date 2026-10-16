'use client';

import { getIssueSchedule } from '@/lib/api';
import { useRequest } from '@/lib/use-request';

function span(ms: number): string {
  const minutes = Math.max(1, Math.round(ms / 60_000));
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return minutes % 60 ? `${hours}h ${minutes % 60}m` : `${hours}h`;
}

const exact = (at: string) => new Date(at).toLocaleString();

// When the rule runner last updated issues and when it runs next. Late is no
// update for more than two scheduled intervals.
export function IssueRunTimes() {
  const schedule = useRequest((signal) => getIssueSchedule({ signal }), []);
  if (schedule.status !== 'success') return null;
  const { lastRunAt, nextRunAt, intervalMinutes } = schedule.data;
  const now = Date.now();
  const late =
    lastRunAt !== null &&
    intervalMinutes !== null &&
    now - Date.parse(lastRunAt) > intervalMinutes * 2 * 60_000;
  return (
    <div className={`text-right text-sm ${late ? 'text-amber-800' : 'text-gray-600'}`}>
      <p title={lastRunAt ? exact(lastRunAt) : undefined}>
        {lastRunAt
          ? `Issues last updated ${span(now - Date.parse(lastRunAt))} ago`
          : 'Issues not updated yet'}
        {late && ' · overdue'}
      </p>
      {nextRunAt && (
        <p className="text-gray-500" title={exact(nextRunAt)}>
          Next update in about {span(Date.parse(nextRunAt) - now)}
        </p>
      )}
    </div>
  );
}
