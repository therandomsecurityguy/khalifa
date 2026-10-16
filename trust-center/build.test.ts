import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { BuildMeta, GeneratedConfig, SiteConfig } from './types';
import { buildSite, loadGenerated, loadSiteConfig } from './build';

const siteConfig: SiteConfig = {
  company: { name: 'Example Corp', securityEmail: 'security@example.com' },
  title: 'Example Trust Center',
};

const generated: GeneratedConfig = {
  frameworks: [
    {
      name: 'CIS AWS Foundations Benchmark v3.0.0',
      status: 'in-progress',
      description: 'Continuous posture from automated graph evaluation.',
      lastVerified: '2026-10-16T00:00:00.000Z',
    },
  ],
  controls: [
    {
      domain: '2. Logging',
      items: [{ title: 'CloudTrail enabled', status: 'partial' }],
    },
    {
      domain: '1. Identity',
      items: [
        { title: 'Root has MFA', status: 'implemented' },
        { title: 'Password policy strong', status: 'planned' },
      ],
    },
  ],
};

const meta: BuildMeta = {
  generatedAt: '2026-10-16T12:00:00.000Z',
  source: { recordStatus: 'OK', recordGeneratedAt: '2026-10-16T00:00:00.000Z' },
};

describe('buildSite', () => {
  let workspace: string;

  beforeEach(() => {
    workspace = mkdtempSync(join(tmpdir(), 'trust-center-site-'));
  });

  afterEach(() => {
    rmSync(workspace, { recursive: true, force: true });
  });

  function writeFixtures(options: { skipMeta?: boolean } = {}): {
    configPath: string;
    generatedDir: string;
  } {
    const configPath = join(workspace, 'site.config.json');
    const generatedDir = join(workspace, 'generated');
    mkdirSync(generatedDir, { recursive: true });
    writeFileSync(configPath, JSON.stringify(siteConfig));
    writeFileSync(join(generatedDir, 'trust.config.json'), JSON.stringify(generated));
    if (!options.skipMeta) {
      writeFileSync(join(generatedDir, 'build-meta.json'), JSON.stringify(meta));
    }
    return { configPath, generatedDir };
  }

  it('writes a static site with the generated posture', () => {
    const { configPath, generatedDir } = writeFixtures();
    const outDir = join(workspace, 'dist');
    const result = buildSite({ siteConfigPath: configPath, generatedDir, outDir });

    expect(result.files.sort()).toEqual(['index.html', 'styles.css']);
    const html = readFileSync(join(outDir, 'index.html'), 'utf8');
    expect(html).toContain('Example Corp');
    expect(html).toContain('CIS AWS Foundations Benchmark v3.0.0');
    expect(html).toContain('Implemented');
    expect(html).toContain('Partial');
    expect(html).toContain('CloudTrail enabled');
    expect(html).toContain('Page generated 2026-10-16T12:00:00.000Z');
    expect(html).toContain('security@example.com');
    expect(readFileSync(join(outDir, 'styles.css'), 'utf8')).toContain('--accent: #1e3a8a');
  });

  it('builds without a build-meta.json', () => {
    const { configPath, generatedDir } = writeFixtures({ skipMeta: true });
    const outDir = join(workspace, 'dist');
    expect(() => buildSite({ siteConfigPath: configPath, generatedDir, outDir })).not.toThrow();
  });

  it('fails with a helpful message when the sync output is missing', () => {
    const { configPath } = writeFixtures();
    expect(() =>
      buildSite({
        siteConfigPath: configPath,
        generatedDir: join(workspace, 'missing'),
        outDir: join(workspace, 'dist'),
      })
    ).toThrow('run "npm run trust-center:sync" first');
  });

  it('rejects invalid configuration', () => {
    const configPath = join(workspace, 'site.config.json');
    writeFileSync(configPath, JSON.stringify({ company: { name: '' } }));
    expect(() => loadSiteConfig(configPath)).toThrow('company.name');

    writeFileSync(
      configPath,
      JSON.stringify({ company: { name: 'x' }, theme: { primary: 'blue' } })
    );
    expect(() => loadSiteConfig(configPath)).toThrow('theme.primary');

    writeFileSync(configPath, 'not json');
    expect(() => loadSiteConfig(configPath)).toThrow('not valid JSON');
  });

  it('rejects generated files with the wrong shape', () => {
    const generatedDir = join(workspace, 'generated');
    mkdirSync(generatedDir, { recursive: true });
    writeFileSync(join(generatedDir, 'trust.config.json'), JSON.stringify({ frameworks: 'nope' }));
    expect(() => loadGenerated(generatedDir)).toThrow('frameworks must be an array');
  });
});
