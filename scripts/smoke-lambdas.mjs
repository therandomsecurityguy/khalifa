import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const archives = [
  'cloudtrail-analyzer',
  'collector',
  'dspm-scanner',
  'graph-writer',
  'incremental-collector',
  'least-privilege-sweep',
  'list-accounts',
  'policy-evaluator',
  'risk-engine',
];

for (const name of archives) {
  const extractDir = mkdtempSync(path.join(tmpdir(), `khalifa-${name}-`));
  try {
    const archive = path.join(repoRoot, 'artifacts', 'lambdas', `${name}.zip`);
    execFileSync('unzip', ['-qq', archive, '-d', extractDir]);
    const artifact = require(path.join(extractDir, 'index.js'));
    if (typeof artifact.handler !== 'function') {
      throw new Error(`${name}.zip does not export index.handler`);
    }
  } finally {
    rmSync(extractDir, { recursive: true, force: true });
  }
}

console.log(`Validated ${archives.length} Lambda archives`);
