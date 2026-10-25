const DAY_MS = 86_400_000;

function validDate(value: Date | undefined): Date | undefined {
  return value instanceof Date && !Number.isNaN(value.getTime()) ? value : undefined;
}

function daysSince(value: Date | undefined, now: Date): number | undefined {
  return value ? Math.max(0, Math.floor((now.getTime() - value.getTime()) / DAY_MS)) : undefined;
}

// Ages for a secret from the dates DescribeSecret (or its ListSecrets entry)
// already returns. A secret never rotated counts from its creation, so turning
// rotation on without it ever succeeding still ages. AWS records last access
// to the day; a secret never read has no access age.
export function secretAgeProperties(
  entry: { CreatedDate?: Date; LastRotatedDate?: Date; LastAccessedDate?: Date },
  now: Date
): Record<string, string | number | undefined> {
  const created = validDate(entry.CreatedDate);
  const rotated = validDate(entry.LastRotatedDate);
  const accessed = validDate(entry.LastAccessedDate);
  return {
    created_at: created?.toISOString(),
    last_accessed: accessed?.toISOString(),
    days_since_rotation: daysSince(rotated ?? created, now),
    days_since_access: daysSince(accessed, now),
  };
}
