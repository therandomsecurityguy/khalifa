import { z } from 'zod';
import { KhalifaApiError, type KhalifaApiClient } from './client';
import { buildTools, type KhalifaTool } from './tools';

function fakeClient(response: unknown = { ok: true }) {
  const calls: Array<{ path: string; params?: Record<string, unknown> }> = [];
  const client = {
    get: jest.fn(async (path: string, params?: Record<string, unknown>) => {
      calls.push({ path, params });
      return response;
    }),
  } as unknown as KhalifaApiClient;
  return { client, calls };
}

function tool(name: string, client: KhalifaApiClient): KhalifaTool {
  const found = buildTools(client).find((candidate) => candidate.name === name);
  if (!found) throw new Error(`No tool ${name}`);
  return found;
}

async function run(name: string, args: Record<string, unknown>, client: KhalifaApiClient) {
  const definition = tool(name, client);
  const parsed = z.object(definition.inputSchema).parse(args) as Record<string, unknown>;
  return definition.handler(parsed);
}

function text(result: Awaited<ReturnType<KhalifaTool['handler']>>): unknown {
  return JSON.parse(result.content[0].text);
}

describe('buildTools', () => {
  it('registers unique, read-only tools with descriptions', () => {
    const { client } = fakeClient();
    const tools = buildTools(client);

    expect(tools).toHaveLength(12);
    expect(new Set(tools.map((entry) => entry.name)).size).toBe(12);
    for (const entry of tools) {
      expect(entry.description.length).toBeGreaterThan(20);
      expect(Object.keys(entry.inputSchema).length).toBeGreaterThanOrEqual(0);
    }
  });

  it.each([
    ['list_issues', {}, '/issues', { limit: 25, order: 'desc' }],
    [
      'list_issues',
      { status: 'open', limit: 5 },
      '/issues',
      { status: 'open', limit: 5, order: 'desc' },
    ],
    ['get_issue', { id: 'RULE-001-v2-a' }, '/issues/RULE-001-v2-a', undefined],
    [
      'search_resources',
      { label: 'AiAgent' },
      '/resources/search',
      { label: 'AiAgent', limit: 50 },
    ],
    [
      'get_resource',
      { arn: 'arn:aws:bedrock:us-east-1:111122223333:agent/a' },
      '/resources/arn%3Aaws%3Abedrock%3Aus-east-1%3A111122223333%3Aagent%2Fa',
      undefined,
    ],
    [
      'get_attack_paths',
      {},
      '/attack-paths/search',
      { from: 'any', to: 'restricted', maxPathLength: 4, limit: 25 },
    ],
    ['compliance_status', {}, '/compliance/frameworks', undefined],
    [
      'compliance_control',
      { framework: 'ISO_42001', controlId: 'A.9.2' },
      '/compliance/frameworks/ISO_42001/controls/A.9.2',
      undefined,
    ],
    ['ai_inventory', { type: 'agents' }, '/ai/inventory', { type: 'agents', limit: 25 }],
    [
      'get_ai_agent',
      { arn: 'arn:aws:bedrock:us-east-1:111122223333:agent/a' },
      '/ai/agents/arn%3Aaws%3Abedrock%3Aus-east-1%3A111122223333%3Aagent%2Fa',
      undefined,
    ],
    ['ai_use_cases', {}, '/ai/use-cases', undefined],
    ['ai_use_case_coverage', {}, '/ai/use-cases/coverage', undefined],
    ['shadow_ai', {}, '/ai/shadow', { limit: 50 }],
  ])('%s calls %s with its bounded parameters', async (name, args, path, params) => {
    const { client, calls } = fakeClient({ items: [] });

    const result = await run(name, args as Record<string, unknown>, client);

    expect(result.isError).toBeUndefined();
    expect(calls).toEqual([{ path, params }]);
    expect(text(result)).toEqual({ items: [] });
  });

  it('rejects an out-of-range limit before any request', async () => {
    const { client, calls } = fakeClient();

    await expect(run('list_issues', { limit: 500 }, client)).rejects.toThrow();

    expect(calls).toHaveLength(0);
  });

  it('turns API failures into readable tool errors, not exceptions', async () => {
    const client = {
      get: jest.fn(async () => {
        throw new KhalifaApiError(403, 'Forbidden');
      }),
    } as unknown as KhalifaApiClient;

    const forbidden = await run('list_issues', {}, client);
    expect(forbidden.isError).toBe(true);
    expect(forbidden.content[0].text).toBe('Khalifa API error (403): Forbidden');

    const network = {
      get: jest.fn(async () => {
        throw new KhalifaApiError(0, 'Khalifa API unreachable');
      }),
    } as unknown as KhalifaApiClient;
    const unreachable = await run('list_issues', {}, network);
    expect(unreachable.content[0].text).toBe(
      'Khalifa API error (network): Khalifa API unreachable'
    );
  });

  it('never exposes write surfaces', () => {
    const { client } = fakeClient();
    const names = buildTools(client).map((entry) => entry.name);

    for (const name of names) {
      expect(name).not.toMatch(/suppress|reopen|create|update|delete|put|post/i);
    }
  });
});
