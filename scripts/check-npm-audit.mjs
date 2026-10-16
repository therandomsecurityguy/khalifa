import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const baselinePath = fileURLToPath(new URL('../.github/npm-audit-baseline.json', import.meta.url));
const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
const audit = spawnSync('npm', ['audit', '--json'], {
  encoding: 'utf8',
  maxBuffer: 16 * 1024 * 1024,
});

if (audit.error) {
  throw audit.error;
}

let report;
try {
  report = JSON.parse(audit.stdout);
} catch {
  process.stderr.write(audit.stderr || audit.stdout);
  throw new Error('npm audit did not return valid JSON');
}

if (report.error || (audit.status !== 0 && audit.status !== 1)) {
  process.stderr.write(JSON.stringify(report.error ?? report, null, 2));
  process.exit(audit.status || 1);
}

const current = new Map();
for (const [packageName, vulnerability] of Object.entries(report.vulnerabilities ?? {})) {
  for (const advisory of vulnerability.via ?? []) {
    if (typeof advisory !== 'object' || !['high', 'critical'].includes(advisory.severity)) {
      continue;
    }

    const match = String(advisory.url ?? '').match(/GHSA-[A-Za-z0-9-]+/);
    const id = match?.[0] ?? `source:${advisory.source}`;
    const packages = current.get(id) ?? [];
    packages.push(packageName);
    current.set(id, packages);
  }
}

const normalizedBaseline = new Map(baseline.map((id) => [id.toLowerCase(), id]));
const newAdvisories = [...current.keys()].filter((id) => !normalizedBaseline.has(id.toLowerCase()));
const resolvedAdvisories = baseline.filter(
  (id) => ![...current.keys()].some((currentId) => currentId.toLowerCase() === id.toLowerCase())
);

if (newAdvisories.length > 0 || resolvedAdvisories.length > 0) {
  if (newAdvisories.length > 0) {
    console.error('New high or critical npm advisories:');
    for (const id of newAdvisories.sort()) {
      console.error(`- ${id}: ${[...new Set(current.get(id))].sort().join(', ')}`);
    }
  }

  if (resolvedAdvisories.length > 0) {
    console.error('Resolved advisories still present in the baseline:');
    for (const id of resolvedAdvisories.sort()) {
      console.error(`- ${id}`);
    }
  }

  process.exit(1);
}

console.log(`No audit regressions; ${baseline.length} known high or critical advisories remain`);
