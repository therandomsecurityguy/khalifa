import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { KhalifaApiClient } from './client';
import { buildTools } from './tools';

export const SERVER_NAME = 'khalifa';
export const SERVER_VERSION = '1.0.0';

/**
 * The stdio MCP server: one tool per read-only API surface, every call
 * audited. Tools are registered with `readOnlyHint` so clients can tell they
 * never mutate anything.
 */
export function createServer(client: KhalifaApiClient): McpServer {
  const server = new McpServer({ name: SERVER_NAME, version: SERVER_VERSION });

  for (const tool of buildTools(client)) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        annotations: { readOnlyHint: true },
      },
      async (args) => {
        const started = Date.now();
        const result = await tool.handler((args ?? {}) as Record<string, unknown>);
        // Audit line on stderr (stdout is the protocol channel): which tool
        // ran, the argument names it used, and how it ended. Argument values
        // are deliberately omitted — they name customer resources.
        console.error(
          JSON.stringify({
            timestamp: new Date().toISOString(),
            context: 'khalifa-mcp',
            tool: tool.name,
            arguments: Object.keys(args ?? {}),
            isError: result.isError === true,
            durationMs: Date.now() - started,
          })
        );
        return result;
      }
    );
  }

  return server;
}
