import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fetchPublishable } from './fetch-publishable';
import { CIS_NAME, buildTrustFragment } from './map';
import type { BuildMeta, TrustConfigFragment } from './types';

export class FailClosedError extends Error {}

export interface SyncEnvironment {
  KHALIFA_API_URL?: string;
  CF_ACCESS_CLIENT_ID?: string;
  CF_ACCESS_CLIENT_SECRET?: string;
  TRUST_CENTER_OUT_DIR?: string;
}

export interface SyncDependencies {
  fetchImpl?: typeof fetch;
  now?: () => Date;
  log?: (line: string) => void;
}

export interface SyncResult {
  outDir: string;
  frameworkStatus: TrustConfigFragment['frameworks'][number]['status'];
  requirementCount: number;
  domains: number;
}

const DEFAULT_OUT_DIR = 'trust-center-config';

/**
 * Fetches the publishable CIS posture and writes trust.config.json and
 * build-meta.json. Fails closed: unless the record is OK, existing outputs
 * are left untouched and the caller exits non-zero so the previous
 * deployment stays live.
 */
export async function runSync(
  environment: SyncEnvironment,
  dependencies: SyncDependencies = {}
): Promise<SyncResult> {
  const now = dependencies.now ?? (() => new Date());
  const log = dependencies.log ?? (() => undefined);
  const apiUrl = required(environment, 'KHALIFA_API_URL');
  const clientId = required(environment, 'CF_ACCESS_CLIENT_ID');
  const clientSecret = required(environment, 'CF_ACCESS_CLIENT_SECRET');
  const outDir = environment.TRUST_CENTER_OUT_DIR?.trim() || DEFAULT_OUT_DIR;

  const response = await fetchPublishable({
    apiUrl,
    clientId,
    clientSecret,
    fetchImpl: dependencies.fetchImpl,
  });

  if (response.status !== 'OK') {
    throw new FailClosedError(
      `publishable endpoint returned ${response.status}; keeping the previous trust-center configuration`
    );
  }

  const fragment = buildTrustFragment(response);
  const meta = buildMeta(response, apiUrl, now(), log);

  mkdirSync(outDir, { recursive: true });
  writeAtomic(join(outDir, 'trust.config.json'), JSON.stringify(fragment, null, 2));
  writeAtomic(join(outDir, 'build-meta.json'), JSON.stringify(meta, null, 2));

  log(`wrote ${outDir}/trust.config.json from ${response.requirements.length} requirement(s)`);
  return {
    outDir,
    frameworkStatus: fragment.frameworks[0].status,
    requirementCount: response.requirements.length,
    domains: fragment.controls.length,
  };
}

function buildMeta(
  response: Awaited<ReturnType<typeof fetchPublishable>>,
  apiUrl: string,
  now: Date,
  log: (line: string) => void
): BuildMeta {
  const pass = response.requirements.filter((requirement) => requirement.status === 'PASS').length;
  const source: BuildMeta['source'] = {
    endpoint: `${apiUrl.trim().replace(/\/+$/, '')}/compliance/reconciliation/publishable`,
    recordStatus: 'OK',
    recordGeneratedAt: response.generatedAt,
  };
  if (response.generatedAt) {
    const ageMs = now.getTime() - Date.parse(response.generatedAt);
    if (Number.isFinite(ageMs)) source.recordAgeHours = Math.max(0, Math.round(ageMs / 3_600_000));
  }
  if (response.maxAgeHours !== undefined) {
    source.maxAgeHours = response.maxAgeHours;
  } else {
    log(
      'publishable endpoint did not publish maxAgeHours; the page will omit the staleness window'
    );
  }
  return {
    generatedAt: now.toISOString(),
    framework: { id: 'CIS_AWS_FOUNDATIONS', name: CIS_NAME, version: '3.0.0' },
    source,
    counts: {
      requirements: response.requirements.length,
      pass,
      fail: response.requirements.length - pass,
      domains: new Set(response.requirements.map((requirement) => requirement.section)).size,
    },
    generator: { name: 'khalifa-trust-center-sync' },
  };
}

function required(environment: SyncEnvironment, name: keyof SyncEnvironment): string {
  const value = environment[name]?.trim();
  if (!value) throw new FailClosedError(`${name} is required`);
  return value;
}

function writeAtomic(path: string, contents: string): void {
  const temporary = `${path}.tmp-${process.pid}`;
  writeFileSync(temporary, `${contents}\n`);
  renameSync(temporary, path);
}

async function main(): Promise<void> {
  try {
    const result = await runSync(process.env, { log: (line) => console.log(line) });
    console.log(
      `trust-center config written to ${result.outDir}: ${result.requirementCount} requirement(s) in ${result.domains} domain(s), framework ${result.frameworkStatus}`
    );
    process.exit(0);
  } catch (error) {
    console.error(
      `trust-center sync failed: ${error instanceof Error ? error.message : String(error)}`
    );
    process.exit(1);
  }
}

if (require.main === module) {
  void main();
}
