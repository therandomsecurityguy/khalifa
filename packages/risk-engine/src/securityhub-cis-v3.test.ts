import { readFileSync } from 'fs';
import { join } from 'path';
import { SECURITY_HUB_CIS_V3_REQUIREMENT, controlsByRequirement } from './securityhub-cis-v3';

// The reconciliation map must match the stored Security Hub page, the source of
// truth for CIS v3.0.0. Parsed the same way as cis-v3-source-of-truth.test.ts.
const page = readFileSync(
  join(
    __dirname,
    '../benchmarks/cis-aws-foundations-3.0.0/aws-securityhub-cis-aws-foundations-benchmark.md'
  ),
  'utf8'
);

function mappingFromPage(): Record<string, string> {
  const start = page.indexOf('<a name="cis3v0-controls"></a>');
  const end = page.indexOf('## CIS AWS Foundations Benchmark version 1.4.0');
  const listed = [...page.slice(start, end).matchAll(/^\[\[([A-Za-z0-9.]+)\]/gm)].map((m) => m[1]);
  const table = new Map<string, string>();
  for (const m of page.matchAll(/^\| \[\[([A-Za-z0-9.]+)\][^|]*\|[^|]*\| ([^|]+)\|/gm)) {
    const requirement = m[2].trim();
    if (/^\d+(\.\d+)+$/.test(requirement)) table.set(m[1], requirement);
  }
  const gap: Record<string, string> = { 'S3.22': '3.8', 'S3.23': '3.9' };
  return Object.fromEntries(listed.map((c) => [c, table.get(c) ?? gap[c]]));
}

describe('Security Hub CIS v3.0.0 control map', () => {
  it('matches the stored source-of-truth page exactly', () => {
    expect(SECURITY_HUB_CIS_V3_REQUIREMENT).toEqual(mappingFromPage());
  });

  it('groups controls that share a requirement', () => {
    expect(controlsByRequirement().get('2.1.4')?.sort()).toEqual(['S3.1', 'S3.8']);
    expect(controlsByRequirement().size).toBe(36);
  });
});
