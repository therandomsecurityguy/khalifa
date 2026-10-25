import type { SecretInventoryItem, Severity } from '@/types';

const DAY_MS = 86_400_000;
export const STALE_DAYS = 90;
const RECENT_DAYS = 30;
export const WIDE_READERS = 20;

export type SecretFilter =
  'all' | 'rotationOff' | 'stale' | 'unused' | 'plaintext' | 'outside' | 'shared' | 'issues';

export function daysSince(iso: string | null, now = Date.now()): number | null {
  const at = iso ? Date.parse(iso) : NaN;
  return Number.isFinite(at) ? Math.max(0, Math.floor((now - at) / DAY_MS)) : null;
}

// AWS returns RotationEnabled only for a secret that ever had rotation set up,
// so a missing value is rotation never configured: off.
export function isRotationOff(item: SecretInventoryItem): boolean {
  return item.kind === 'secrets-manager' && item.rotationEnabled !== true;
}

// The collector records creation and access dates from the release that added
// them; until its next run, no secret has them.
export function datesCollected(items: SecretInventoryItem[]): boolean {
  return items.some((item) => item.kind === 'secrets-manager' && item.createdAt !== null);
}

// Secrets Manager only: a parameter has no rotation of its own. A secret never
// rotated ages from its creation, so rotation turned on but failing still
// counts; with no dates at all it counts too, as nothing shows it rotating.
function notRotatedRecently(item: SecretInventoryItem, now: number): boolean {
  if (item.kind !== 'secrets-manager') return false;
  const days = daysSince(item.lastRotated ?? item.createdAt, now);
  return days === null || days >= STALE_DAYS;
}

// Last read 90+ days ago, or never read in 90+ days of existing. Without a
// creation date the collector has not recorded access yet, so it says nothing.
function unusedRecently(item: SecretInventoryItem, now: number): boolean {
  if (item.kind !== 'secrets-manager') return false;
  const accessed = daysSince(item.lastAccessed, now);
  if (accessed !== null) return accessed >= STALE_DAYS;
  const created = daysSince(item.createdAt, now);
  return created !== null && created >= STALE_DAYS;
}

export const SECRET_FILTERS: Record<
  SecretFilter,
  (item: SecretInventoryItem, now: number) => boolean
> = {
  all: () => true,
  rotationOff: isRotationOff,
  stale: notRotatedRecently,
  unused: unusedRecently,
  plaintext: (item) => item.kind === 'ssm-plaintext',
  outside: (item) => item.sharing?.scope === 'outside',
  shared: (item) => item.sharing?.scope === 'org' || item.sharing?.scope === 'collected',
  issues: (item) => item.issues.length > 0,
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

// Open issues per severity, worst first, leaving out severities with none.
export function severityCounts(
  item: SecretInventoryItem
): Array<{ severity: Severity; count: number }> {
  return SEVERITY_ORDER.map((severity) => ({
    severity,
    count: item.issues.filter((issue) => issue.severity === severity).length,
  })).filter((entry) => entry.count > 0);
}

// Worst open issue first, then outside shares, then by name.
export function compareSecrets(a: SecretInventoryItem, b: SecretInventoryItem): number {
  const worst = (item: SecretInventoryItem) =>
    Math.min(4, ...item.issues.map((issue) => SEVERITY_RANK[issue.severity] ?? 4));
  const outside = (item: SecretInventoryItem) => (item.sharing?.scope === 'outside' ? 0 : 1);
  return worst(a) - worst(b) || outside(a) - outside(b) || a.name.localeCompare(b.name);
}

export function sharingLabel(item: SecretInventoryItem): string {
  if (item.kind !== 'secrets-manager') return 'Not tracked';
  if (!item.sharing) return 'Unknown';
  switch (item.sharing.scope) {
    case 'outside':
      return 'Outside the org';
    case 'org':
      return 'Org only (PrincipalOrgID)';
    case 'collected':
      return item.sharing.accounts === 1
        ? '1 collected account'
        : `${item.sharing.accounts} collected accounts`;
    default:
      return 'This account only';
  }
}

export function lastAccessedLabel(item: SecretInventoryItem, now = Date.now()): string {
  if (item.kind !== 'secrets-manager') return 'Not tracked';
  const days = daysSince(item.lastAccessed, now);
  if (days !== null) return days === 0 ? 'Today' : `${days} days ago`;
  return item.createdAt ? 'Never' : 'Not collected yet';
}

// Column filters: each maps a secret to the option values it matches.
export type SecretFacet = 'type' | 'rotation' | 'access' | 'sharing' | 'readers' | 'issues';

export const FACET_OPTIONS: Record<SecretFacet, Array<{ value: string; label: string }>> = {
  type: [
    { value: 'secrets-manager', label: 'Secrets Manager' },
    { value: 'ssm-parameter', label: 'SSM SecureString' },
    { value: 'ssm-plaintext', label: 'SSM String (plain text)' },
  ],
  rotation: [
    { value: 'on', label: 'On' },
    { value: 'off', label: 'Off' },
    { value: 'none', label: 'No rotation (SSM)' },
  ],
  access: [
    { value: 'recent', label: `Within ${RECENT_DAYS} days` },
    { value: 'month', label: `${RECENT_DAYS}–${STALE_DAYS} days` },
    { value: 'stale', label: `${STALE_DAYS}+ days ago` },
    { value: 'never', label: 'Never' },
    { value: 'untracked', label: 'Not tracked' },
    { value: 'pending', label: 'Not collected yet' },
  ],
  sharing: [
    { value: 'outside', label: 'Outside the org' },
    { value: 'collected', label: 'Collected accounts' },
    { value: 'org', label: 'Org only' },
    { value: 'account', label: 'This account only' },
    { value: 'unknown', label: 'Unknown' },
    { value: 'untracked', label: 'Not tracked' },
  ],
  readers: [
    { value: 'none', label: 'None found' },
    { value: 'few', label: '1–5' },
    { value: 'some', label: `6–${WIDE_READERS - 1}` },
    { value: 'many', label: `${WIDE_READERS}+` },
    { value: 'unknown', label: 'Not evaluated' },
  ],
  issues: [
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
    { value: 'none', label: 'No open issues' },
  ],
};

function accessBucket(item: SecretInventoryItem, now: number): string {
  if (item.kind !== 'secrets-manager') return 'untracked';
  const days = daysSince(item.lastAccessed, now);
  if (days === null) return item.createdAt ? 'never' : 'pending';
  if (days < RECENT_DAYS) return 'recent';
  return days < STALE_DAYS ? 'month' : 'stale';
}

export function facetValues(facet: SecretFacet, item: SecretInventoryItem, now: number): string[] {
  switch (facet) {
    case 'type':
      return [item.kind];
    case 'rotation':
      return [item.kind !== 'secrets-manager' ? 'none' : isRotationOff(item) ? 'off' : 'on'];
    case 'access':
      return [accessBucket(item, now)];
    case 'sharing':
      if (item.kind !== 'secrets-manager') return ['untracked'];
      return [item.sharing?.scope ?? 'unknown'];
    case 'readers': {
      const total = item.readers?.total;
      if (total === undefined) return ['unknown'];
      if (total === 0) return ['none'];
      if (total <= 5) return ['few'];
      return [total < WIDE_READERS ? 'some' : 'many'];
    }
    case 'issues': {
      const severities = severityCounts(item).map((entry) => entry.severity);
      return severities.length ? severities : ['none'];
    }
  }
}

export function matchesFacets(
  item: SecretInventoryItem,
  selected: Partial<Record<SecretFacet, string[]>>,
  now: number,
  skip?: SecretFacet
): boolean {
  return (Object.entries(selected) as Array<[SecretFacet, string[]]>).every(
    ([facet, values]) =>
      facet === skip ||
      values.length === 0 ||
      facetValues(facet, item, now).some((value) => values.includes(value))
  );
}

// Plain next steps from the collected facts, most urgent first.
export function fixSteps(item: SecretInventoryItem, now = Date.now()): string[] {
  const steps: string[] = [];
  if (item.kind === 'ssm-plaintext') {
    steps.push(
      'Move this value to a SecureString parameter or Secrets Manager, then rotate it: it has been stored unencrypted.'
    );
  }
  if (item.sharing?.scope === 'outside') {
    steps.push(
      'Remove the outside account or anyone from the resource policy, or limit it with aws:PrincipalOrgID.'
    );
  } else if (item.sharing?.scope === 'org' || item.sharing?.scope === 'collected') {
    steps.push(
      'Confirm each account the resource policy allows still needs this secret, and narrow it to the roles that read it.'
    );
  }
  if (item.kind === 'secrets-manager') {
    const age = daysSince(item.lastRotated ?? item.createdAt, now);
    if (isRotationOff(item)) {
      steps.push(
        age === null ? 'Turn on rotation.' : `Turn on rotation. It has not changed in ${age} days.`
      );
    } else if (age !== null && age >= STALE_DAYS) {
      steps.push(`Rotation is on but has not run in ${age} days. Check the rotation function.`);
    }
    if (unusedRecently(item, now)) {
      steps.push(
        item.lastAccessed
          ? `Nothing has read it in ${daysSince(item.lastAccessed, now)} days. Delete it if it is no longer needed.`
          : 'Nothing has ever read it. Delete it if it is no longer needed.'
      );
    }
  }
  return steps;
}

// Free-text search over what people know a secret by: its name or ARN, its
// account (name or id), region, env and owner.
export function matchesSearch(
  item: SecretInventoryItem,
  query: string,
  accountName: string
): boolean {
  if (!query) return true;
  return [item.name, item.id, accountName, item.accountId, item.region, item.env, item.owner].some(
    (field) => field?.toLowerCase().includes(query)
  );
}
