#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { KhalifaApiClient } from './client';
import { readConfig } from './config';
import { createServer } from './server';

// Human-readable output always goes to stderr: stdout is the MCP protocol
// channel and must carry nothing else once a client is attached.
const HELP = `Usage: khalifa-mcp [--check]

Read-only Model Context Protocol server for the Khalifa security graph.

Configuration comes from the environment:
  KHALIFA_API_URL        API origin (required), e.g. http://localhost:8080
  KHALIFA_TOKEN          Cognito access token, sent as Bearer — or —
  KHALIFA_ACCESS_JWT     Cloudflare Access JWT (cf-access-jwt-assertion)
  KHALIFA_TIMEOUT_MS     Request timeout, 1000-120000 (default 15000)

--check validates the configuration and reaches the API's /livez probe,
then exits without opening the protocol channel.
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes('--help')) {
    console.error(HELP);
    return;
  }

  const config = readConfig();
  const client = new KhalifaApiClient(config);

  if (args.includes('--check')) {
    await client.check();
    console.error('Khalifa MCP server configuration valid; API /livez reachable');
    return;
  }

  const server = createServer(client);
  await server.connect(new StdioServerTransport());
  console.error('Khalifa MCP server connected over stdio');
}

main().catch((error: unknown) => {
  console.error(
    `Khalifa MCP server failed: ${error instanceof Error ? error.message : String(error)}`
  );
  process.exitCode = 1;
});
