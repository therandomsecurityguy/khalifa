import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type ServerResponse } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { FailClosedError, runSync, type SyncEnvironment } from './index';

const okPayload = {
  status: 'OK',
  generatedAt: '2026-10-16T00:00:00.000Z',
  maxAgeHours: 24,
  requirements: [
    { requirement: '1.5', title: 'Root has MFA', section: '1. Identity', status: 'PASS' },
    { requirement: '2.1', title: 'CloudTrail enabled', section: '2. Logging', status: 'FAIL' },
  ],
};

async function withServer(
  payload: unknown,
  statusCode: number,
  test: (apiUrl: string) => Promise<void>
): Promise<void> {
  const server = createServer((_request, response: ServerResponse) => {
    response.writeHead(statusCode, { 'content-type': 'application/json' });
    response.end(JSON.stringify(payload));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    const { port } = server.address() as AddressInfo;
    await test(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve()))
    );
  }
}

function environment(apiUrl: string, outDir: string): SyncEnvironment {
  return {
    KHALIFA_API_URL: apiUrl,
    CF_ACCESS_CLIENT_ID: 'sync.access',
    CF_ACCESS_CLIENT_SECRET: 'super-secret',
    TRUST_CENTER_OUT_DIR: outDir,
  };
}

describe('runSync', () => {
  let outDir: string;

  beforeEach(() => {
    outDir = mkdtempSync(join(tmpdir(), 'trust-center-sync-'));
  });

  afterEach(() => {
    rmSync(outDir, { recursive: true, force: true });
  });

  it('writes trust.config.json and build-meta.json for an OK record', async () => {
    await withServer(okPayload, 200, async (apiUrl) => {
      const result = await runSync(environment(apiUrl, outDir), {
        now: () => new Date('2026-10-16T12:00:00.000Z'),
      });
      expect(result).toMatchObject({
        frameworkStatus: 'in-progress',
        requirementCount: 2,
        domains: 2,
      });

      const config = JSON.parse(readFileSync(join(outDir, 'trust.config.json'), 'utf8'));
      expect(config.frameworks[0].status).toBe('in-progress');
      expect(config.frameworks).toHaveLength(3);
      expect(config.controls.map((domain: { domain: string }) => domain.domain)).toEqual([
        '1. Identity',
        '2. Logging',
      ]);

      const meta = JSON.parse(readFileSync(join(outDir, 'build-meta.json'), 'utf8'));
      expect(meta).toMatchObject({
        generatedAt: '2026-10-16T12:00:00.000Z',
        source: {
          recordStatus: 'OK',
          recordGeneratedAt: '2026-10-16T00:00:00.000Z',
          recordAgeHours: 12,
          maxAgeHours: 24,
        },
        counts: { requirements: 2, pass: 1, fail: 1, domains: 2 },
      });
    });
  });

  it('omits the staleness window when the endpoint does not publish one', async () => {
    const payload = { ...okPayload } as Record<string, unknown>;
    delete payload.maxAgeHours;
    await withServer(payload, 200, async (apiUrl) => {
      const logs: string[] = [];
      await runSync(environment(apiUrl, outDir), {
        now: () => new Date('2026-10-16T12:00:00.000Z'),
        log: (line) => logs.push(line),
      });
      const meta = JSON.parse(readFileSync(join(outDir, 'build-meta.json'), 'utf8'));
      expect(meta.source.maxAgeHours).toBeUndefined();
      expect(meta.source.recordAgeHours).toBe(12);
      expect(logs.join(' ')).toContain('did not publish maxAgeHours');
    });
  });

  it('keeps previous outputs when the record is not OK', async () => {
    const configPath = join(outDir, 'trust.config.json');
    writeFileSync(configPath, '{"previous":true}');

    await withServer(
      { status: 'STALE', generatedAt: null, requirements: [] },
      200,
      async (apiUrl) => {
        await expect(runSync(environment(apiUrl, outDir))).rejects.toThrow(FailClosedError);
      }
    );
    expect(readFileSync(configPath, 'utf8')).toBe('{"previous":true}');
  });

  it('keeps previous outputs on transport errors', async () => {
    const configPath = join(outDir, 'trust.config.json');
    writeFileSync(configPath, '{"previous":true}');

    await withServer({ error: 'boom' }, 500, async (apiUrl) => {
      await expect(runSync(environment(apiUrl, outDir))).rejects.toThrow('HTTP 500');
    });
    expect(readFileSync(configPath, 'utf8')).toBe('{"previous":true}');
  });

  it('requires its configuration', async () => {
    await expect(runSync({})).rejects.toThrow('KHALIFA_API_URL is required');
    await expect(runSync({ KHALIFA_API_URL: 'http://x' })).rejects.toThrow(
      'CF_ACCESS_CLIENT_ID is required'
    );
  });
});
