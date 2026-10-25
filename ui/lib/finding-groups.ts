import type { GraphVertex, ResourceInvolved } from '@/types';

export const FINDING_LABEL = 'SecurityHubFinding';

// Inspector titles name the CVE, then the packages that carry it:
// "CVE-2026-74517 - linux-image-aws, linux-image-aws".
const INSPECTOR_TITLE = /^(\S+) - (.+)$/;
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];
const UNAVAILABLE = 'Details unavailable';

export interface FindingItem {
  resource: ResourceInvolved;
  name: string;
  severity?: string;
}

export interface FindingGroup {
  fix: string;
  items: FindingItem[];
  severities: Array<[string, number]>;
}

function inspectorTitle(vertex: GraphVertex): RegExpExecArray | null {
  const { title, product_arn: product } = vertex.properties;
  if (typeof title !== 'string' || !String(product ?? '').includes('/inspector')) return null;
  return INSPECTOR_TITLE.exec(title.trim());
}

// What fixes a finding: the affected packages for Inspector, else its title.
function findingFix(vertex: GraphVertex | undefined): string {
  if (!vertex || vertex.properties.missing) return UNAVAILABLE;
  const match = inspectorTitle(vertex);
  if (match) {
    const packages = new Set(
      match[2]
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean)
    );
    return [...packages].join(', ');
  }
  const title = vertex.properties.title;
  return typeof title === 'string' && title.trim() ? title.trim() : UNAVAILABLE;
}

function findingName(resource: ResourceInvolved, vertex: GraphVertex | undefined): string {
  const match = vertex && inspectorTitle(vertex);
  if (match) return match[1];
  const title = vertex?.properties.title;
  if (typeof title === 'string' && title.trim()) return title.trim();
  return resource.resourceName || resource.resourceId.split('/').pop() || resource.resourceId;
}

function rank(severity: string | undefined): number {
  const index = severity ? SEVERITIES.indexOf(severity) : -1;
  return index === -1 ? SEVERITIES.length : index;
}

// Findings grouped by what fixes them, worst and largest groups first.
export function groupFindings(
  findings: ResourceInvolved[],
  vertices: Map<string, GraphVertex>
): FindingGroup[] {
  const groups = new Map<string, FindingItem[]>();
  for (const resource of findings) {
    const vertex = vertices.get(resource.resourceId);
    const severity = vertex?.properties.severity;
    const fix = findingFix(vertex);
    const items = groups.get(fix) ?? [];
    items.push({
      resource,
      name: findingName(resource, vertex),
      severity: typeof severity === 'string' ? severity.toUpperCase() : undefined,
    });
    groups.set(fix, items);
  }
  return [...groups.entries()]
    .map(([fix, items]) => {
      items.sort((a, b) => rank(a.severity) - rank(b.severity) || a.name.localeCompare(b.name));
      const counts = new Map<string, number>();
      for (const item of items) {
        if (item.severity) counts.set(item.severity, (counts.get(item.severity) ?? 0) + 1);
      }
      const severities = [...counts.entries()].sort((a, b) => rank(a[0]) - rank(b[0]));
      return { fix, items, severities };
    })
    .sort(
      (a, b) =>
        Number(a.fix === UNAVAILABLE) - Number(b.fix === UNAVAILABLE) ||
        rank(a.items[0]?.severity) - rank(b.items[0]?.severity) ||
        b.items.length - a.items.length ||
        a.fix.localeCompare(b.fix)
    );
}
