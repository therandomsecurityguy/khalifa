import { readFileSync } from 'fs';
import { join } from 'path';
import { KHALIFA_AUTOMATED_BEYOND_SECURITY_HUB, getControlsByFramework } from './compliance-types';

/**
 * The CIS catalogue measured against the stored AWS Security Hub page, the
 * single source of truth for CIS AWS Foundations v3.0.0
 * (benchmarks/cis-aws-foundations-3.0.0). A failure here is drift between the
 * catalogue and the benchmark mapping, to be fixed or deliberately recorded.
 */
const page = readFileSync(
  join(
    __dirname,
    '../benchmarks/cis-aws-foundations-3.0.0/aws-securityhub-cis-aws-foundations-benchmark.md'
  ),
  'utf8'
);

// "Controls that apply to CIS AWS Foundations Benchmark version 3.0.0".
function controlsListedForV3(): string[] {
  const start = page.indexOf('<a name="cis3v0-controls"></a>');
  const end = page.indexOf('## CIS AWS Foundations Benchmark version 1.4.0');
  if (start < 0 || end < 0) throw new Error('v3.0.0 control list not found in the stored page');
  return [...page.slice(start, end).matchAll(/^\[\[([A-Za-z0-9.]+)\]/gm)].map((m) => m[1]);
}

// The version-comparison table: control -> v3.0.0 requirement, where numeric.
function v3RequirementsByControl(): Map<string, string> {
  const map = new Map<string, string>();
  for (const m of page.matchAll(/^\| \[\[([A-Za-z0-9.]+)\][^|]*\|[^|]*\| ([^|]+)\|/gm)) {
    const requirement = m[2].trim();
    if (/^\d+(\.\d+)+$/.test(requirement)) map.set(m[1], requirement);
  }
  return map;
}

// The page lists S3.22 and S3.23 for v3.0.0 but its comparison table has no
// rows for them. Their titles are CIS 3.8 and 3.9 word for word (object-level
// write / read event logging), so they are mapped here rather than dropped.
const LISTED_WITHOUT_TABLE_ROW: Record<string, string> = { 'S3.22': '3.8', 'S3.23': '3.9' };

describe('CIS v3.0.0 catalogue against the Security Hub source of truth', () => {
  const listed = controlsListedForV3();
  const table = v3RequirementsByControl();
  const automatedBySecurityHub = new Set<string>();
  for (const control of listed) {
    const requirement = table.get(control) ?? LISTED_WITHOUT_TABLE_ROW[control];
    if (requirement) automatedBySecurityHub.add(requirement);
  }
  const catalogue = new Map(getControlsByFramework('CIS_AWS_FOUNDATIONS').map((c) => [c.id, c]));

  it('parses the stored page', () => {
    expect(listed).toHaveLength(37);
    expect(automatedBySecurityHub.size).toBe(36);
  });

  it('every listed control maps to a requirement, from the table or the documented gap', () => {
    const unmapped = listed.filter((c) => !table.has(c) && !(c in LISTED_WITHOUT_TABLE_ROW));
    expect(unmapped).toEqual([]);
  });

  it('every requirement Security Hub automates is in the catalogue, marked automated', () => {
    const problems = [...automatedBySecurityHub].filter(
      (id) => catalogue.get(id)?.automated !== true
    );
    expect(problems).toEqual([]);
  });

  it('every other automated CIS control is a recorded, deliberate extension', () => {
    const beyond = [...catalogue.values()]
      .filter((c) => c.automated && !automatedBySecurityHub.has(c.id))
      .map((c) => c.id)
      .sort();
    expect(beyond).toEqual(Object.keys(KHALIFA_AUTOMATED_BEYOND_SECURITY_HUB).sort());
  });

  it('records no extension that Security Hub already automates', () => {
    const redundant = Object.keys(KHALIFA_AUTOMATED_BEYOND_SECURITY_HUB).filter((id) =>
      automatedBySecurityHub.has(id)
    );
    expect(redundant).toEqual([]);
  });
});
