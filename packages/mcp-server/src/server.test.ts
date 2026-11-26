import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { KhalifaApiClient } from './client';
import { createServer } from './server';

const config = { apiUrl: 'http://api.test', token: 'test-token', timeoutMs: 5_000 };

async function connect(fetchImpl: typeof fetch) {
  global.fetch = fetchImpl;
  const server = createServer(new KhalifaApiClient(config));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'test-client', version: '1.0.0' });
  await client.connect(clientTransport);
  return { server, client };
}

const jsonResponse = (status: number, body: unknown): typeof fetch =>
  jest.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  })) as unknown as typeof fetch;

describe('MCP server over linked transports', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it('handshakes, lists the read-only tools, calls one, and audits the call', async () => {
    const { server, client } = await connect(jsonResponse(200, { items: [{ id: 'issue-1' }] }));

    const listed = await client.listTools();
    expect(listed.tools).toHaveLength(12);
    expect(listed.tools.map((entry) => entry.name)).toContain('list_issues');
    expect(listed.tools.every((entry) => entry.annotations?.readOnlyHint === true)).toBe(true);

    const logged = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const result = await client.callTool({ name: 'list_issues', arguments: {} });

    expect(result.isError).toBeFalsy();
    const content = result.content as Array<{ type: string; text: string }>;
    expect(JSON.parse(content[0].text)).toEqual({ items: [{ id: 'issue-1' }] });

    const auditLine = logged.mock.calls
      .map(([line]) => String(line))
      .find((line) => line.startsWith('{'));
    expect(JSON.parse(auditLine as string)).toMatchObject({
      context: 'khalifa-mcp',
      tool: 'list_issues',
      // Defaults are applied before the handler, so the audit line names the
      // parameters the call actually used.
      arguments: ['limit', 'order'],
      isError: false,
    });

    await client.close();
    await server.close();
  });

  it('returns an isError tool result for an API rejection, with the API message', async () => {
    const { server, client } = await connect(jsonResponse(403, { message: 'Forbidden' }));

    const result = await client.callTool({ name: 'compliance_status', arguments: {} });

    expect(result.isError).toBe(true);
    const content = result.content as Array<{ text: string }>;
    expect(content[0].text).toBe('Khalifa API error (403): Forbidden');

    await client.close();
    await server.close();
  });
});
