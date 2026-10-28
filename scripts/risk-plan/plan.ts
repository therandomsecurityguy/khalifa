export class PlanParseError extends Error {}

export interface PlannedResource {
  address: string;
  type: string;
  name: string;
  /** Normalized: 'create' when the plan creates or replaces, else the raw action. */
  actions: string[];
  /** Known `after` values; a key is absent when the plan cannot know it. */
  after: Record<string, unknown>;
  /** Known `before` values, for diff semantics (an unchanged grant is not new). */
  before: Record<string, unknown>;
}

interface ChangeShape {
  actions?: unknown;
  after?: unknown;
  before?: unknown;
  after_unknown?: unknown;
}

interface ResourceChangeShape {
  address?: unknown;
  mode?: unknown;
  type?: unknown;
  name?: unknown;
  change?: unknown;
}

// Terraform's `show -json` shape, read defensively: the CLI only needs the
// managed resources a plan would create or update. Unknown values appear as
// null in `after` with a flag in `after_unknown`, so they are dropped here and
// every check treats a missing key as "not known yet".
export function parsePlan(text: string): PlannedResource[] {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    throw new PlanParseError('Plan file is not valid JSON; run `terraform show -json plan.out`');
  }
  const changes = (document as { resource_changes?: unknown })?.resource_changes;
  if (!Array.isArray(changes)) {
    throw new PlanParseError(
      'Plan file has no resource_changes; not a `terraform show -json` output'
    );
  }

  const resources: PlannedResource[] = [];
  changes.forEach((raw, index) => {
    const change = raw as ResourceChangeShape;
    if (change.mode !== undefined && change.mode !== 'managed') return;
    if (typeof change.address !== 'string' || typeof change.type !== 'string') {
      throw new PlanParseError(`resource_changes[${index}] is missing address or type`);
    }
    const actions = normalizeActions((change.change as ChangeShape | undefined)?.actions, index);
    if (actions.length === 0) return;
    resources.push({
      address: change.address,
      type: change.type,
      name: typeof change.name === 'string' ? change.name : change.address,
      actions,
      after: knownValues((change.change as ChangeShape | undefined)?.after),
      before: knownValues((change.change as ChangeShape | undefined)?.before),
    });
  });
  return resources;
}

function normalizeActions(actions: unknown, index: number): string[] {
  if (!Array.isArray(actions) || actions.some((action) => typeof action !== 'string')) {
    throw new PlanParseError(`resource_changes[${index}].change.actions must be a string array`);
  }
  const list = actions as string[];
  if (list.includes('no-op') || list.length === 0) return [];
  // A replacement is a create for risk purposes; a delete removes risk.
  if (list.includes('create')) return ['create'];
  if (list.includes('update')) return ['update'];
  return [];
}

function knownValues(after: unknown): Record<string, unknown> {
  if (!after || typeof after !== 'object') return {};
  const known: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(after as Record<string, unknown>)) {
    if (value === null || value === undefined) continue;
    known[key] = value;
  }
  return known;
}
