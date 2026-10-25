import type { Severity } from '@/types';
import { TONES } from '@/components/ui';

const LETTER: Record<Severity, string> = { critical: 'C', high: 'H', medium: 'M', low: 'L' };

// Open issues per severity as small circles, "1C 2H 1L"; the letter keeps them
// apart without relying on colour, and the label reads the counts in full.
export function SeverityCounts({
  counts,
  size = 'sm',
}: {
  counts: Array<{ severity: Severity; count: number }>;
  size?: 'sm' | 'md';
}) {
  const label = `${counts.map((entry) => `${entry.count} ${entry.severity}`).join(', ')} open ${
    counts.reduce((sum, entry) => sum + entry.count, 0) === 1 ? 'issue' : 'issues'
  }`;
  const circle = size === 'md' ? 'h-9 min-w-9 text-sm' : 'h-7 min-w-7 text-xs';
  return (
    <span role="img" aria-label={label} title={label} className="inline-flex flex-wrap gap-1.5">
      {counts.map((entry) => (
        <span
          key={entry.severity}
          aria-hidden="true"
          className={`inline-flex items-center justify-center rounded-full px-1 font-bold tabular-nums ${circle} ${TONES.severity[entry.severity]}`}
        >
          {entry.count}
          {LETTER[entry.severity]}
        </span>
      ))}
    </span>
  );
}
