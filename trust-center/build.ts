import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { renderSite } from './render';
import type { BuildMeta, GeneratedConfig, SiteConfig } from './types';

export interface BuildOptions {
  siteConfigPath?: string;
  generatedDir?: string;
  outDir?: string;
}

export interface BuildResult {
  outDir: string;
  files: string[];
}

const DEFAULT_OUT = join(__dirname, 'dist');
const DEFAULT_GENERATED = 'trust-center-config';

export function loadSiteConfig(path: string): SiteConfig {
  const parsed = parseJson(readFile(path), path);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error(`${path} must contain a JSON object`);
  }
  const config = parsed as SiteConfig;
  if (!config.company || typeof config.company.name !== 'string' || !config.company.name.trim()) {
    throw new Error(`${path} must set company.name`);
  }
  if (config.theme?.primary && !/^#[0-9a-fA-F]{6}$/.test(config.theme.primary)) {
    throw new Error(`${path} theme.primary must be a 6-digit hex color`);
  }
  const staleAfterHours = config.monitoring?.staleAfterHours;
  if (
    staleAfterHours !== undefined &&
    (!Number.isSafeInteger(staleAfterHours) || staleAfterHours < 1)
  ) {
    throw new Error(`${path} monitoring.staleAfterHours must be a positive integer`);
  }
  return config;
}

export function loadGenerated(dir: string): {
  generated: GeneratedConfig;
  meta: BuildMeta | null;
} {
  const configPath = join(dir, 'trust.config.json');
  const generated = parseJson(readFile(configPath), configPath) as GeneratedConfig;
  if (!generated || typeof generated !== 'object') {
    throw new Error(`${configPath} must contain a JSON object`);
  }
  if (generated.frameworks !== undefined && !Array.isArray(generated.frameworks)) {
    throw new Error(`${configPath} frameworks must be an array`);
  }
  if (generated.controls !== undefined && !Array.isArray(generated.controls)) {
    throw new Error(`${configPath} controls must be an array`);
  }

  const metaPath = join(dir, 'build-meta.json');
  let meta: BuildMeta | null = null;
  try {
    meta = parseJson(readFile(metaPath), metaPath) as BuildMeta;
  } catch {
    meta = null;
  }
  return { generated, meta };
}

export function buildSite(options: BuildOptions = {}): BuildResult {
  const siteConfigPath = options.siteConfigPath ?? join(__dirname, 'site.config.json');
  const generatedDir = options.generatedDir ?? DEFAULT_GENERATED;
  const outDir = options.outDir ?? DEFAULT_OUT;

  const config = loadSiteConfig(siteConfigPath);
  const { generated, meta } = loadGenerated(generatedDir);

  // A claimed staleness window is only published when the API reports the same
  // one; a contradiction fails the build instead of shipping a false claim.
  const configuredStale = config.monitoring?.staleAfterHours;
  const serverStale = meta?.source?.maxAgeHours;
  if (
    configuredStale !== undefined &&
    serverStale !== undefined &&
    configuredStale !== serverStale
  ) {
    throw new Error(
      `site.config.json monitoring.staleAfterHours (${configuredStale}) contradicts the API's published maxAgeHours (${serverStale}); ` +
        'the page would claim a staleness window the API does not enforce'
    );
  }

  const rendered = renderSite(config, generated, meta);

  mkdirSync(outDir, { recursive: true });
  const files = Object.keys(rendered);
  for (const file of files) {
    writeFileSync(join(outDir, file), rendered[file as keyof typeof rendered]);
  }
  return { outDir, files };
}

function readFile(path: string): string {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    if (path.endsWith('trust.config.json')) {
      throw new Error(
        `missing ${path}; run "npm run trust-center:sync" first or pass --generated <dir>`
      );
    }
    throw new Error(`missing ${path}`);
  }
}

function parseJson(contents: string, path: string): unknown {
  try {
    return JSON.parse(contents);
  } catch (error) {
    throw new Error(`${path} is not valid JSON: ${(error as Error).message}`);
  }
}

interface CliArgs {
  config?: string;
  generated?: string;
  out?: string;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--config') args.config = argv[++index];
    else if (arg === '--generated') args.generated = argv[++index];
    else if (arg === '--out') args.out = argv[++index];
    else throw new Error(`unknown argument: ${arg}`);
  }
  return args;
}

function main(): void {
  try {
    const args = parseArgs(process.argv.slice(2));
    const result = buildSite({
      siteConfigPath: args.config,
      generatedDir: args.generated,
      outDir: args.out,
    });
    console.log(`trust-center site written to ${result.outDir}: ${result.files.join(', ')}`);
    process.exit(0);
  } catch (error) {
    console.error(
      `trust-center build failed: ${error instanceof Error ? error.message : String(error)}`
    );
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
