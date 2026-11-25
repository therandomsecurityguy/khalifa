# Khalifa MCP server

Read-only [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes the Khalifa security graph to AI tools — Claude Code/Desktop, Cursor,
Windsurf, and anything else that speaks MCP over stdio.

It calls the same REST API the UI uses, with the operator's token. It holds no
state, exposes **no write operations** (issue lifecycle and the AI use-case
registry stay in the UI and API), and never mutates the graph. Every tool call
writes an audit line to stderr: tool name, argument **names**, outcome, and
duration — never argument values, which name customer resources.

## Tools

| Tool                   | What it returns                                                                                                                        |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `list_issues`          | Risk issues ranked by score, with severity, rule, team, and status                                                                     |
| `get_issue`            | One issue with its attack path, likelihood factors (including graph coverage), ATT&CK techniques, and remediation                      |
| `search_resources`     | Collected graph vertices by label, optionally filtered by a property value                                                             |
| `get_resource`         | One resource by ARN, with neighbors, edges, and open issues                                                                            |
| `get_attack_paths`     | Attack-path search between closed presets (internet/outside/resource → restricted/crown/secrets/admin/resource)                        |
| `compliance_status`    | Framework summaries: CIS, Khalifa baseline, and the mapped frameworks (SOC 2, ISO 27001, PCI DSS, NIST 800-53, ISO 42001, NIST AI RMF) |
| `compliance_control`   | One control or mapped requirement with its evidence and citation links                                                                 |
| `ai_inventory`         | The collected AI estate: agents, knowledge bases, guardrails, models, runtimes, endpoints, notebooks, domains                          |
| `get_ai_agent`         | One Bedrock agent or AgentCore runtime: role, knowledge bases, guardrail, tools, model, issues                                         |
| `ai_use_cases`         | The governance registry: owners, statuses, covered assets, and lite impact assessments                                                 |
| `ai_use_case_coverage` | Registry against the graph: assets no use case covers, and registrations missing from the graph                                        |

Results are the API's own payloads, including its honesty markers: coverage
statements on predictive surfaces and explicit truncation flags. Nothing here
is a certification.

## Configure

| Variable             | Default | Purpose                                                                                                                           |
| -------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `KHALIFA_API_URL`    | —       | API origin. With the reference deployment: `kubectl -n khalifa port-forward svc/khalifa-api 8080:80` then `http://localhost:8080` |
| `KHALIFA_TOKEN`      | —       | Cognito access token or a Khalifa service token (`khalifa_…`), sent as `Authorization: Bearer`                                    |
| `KHALIFA_ACCESS_JWT` | —       | Cloudflare Access JWT, sent as `cf-access-jwt-assertion` (used when no Bearer token is set)                                       |
| `KHALIFA_TIMEOUT_MS` | `15000` | Request timeout, 1000–120000                                                                                                      |

Every tool needs Viewer only — use the least-privileged identity that works.
One of `KHALIFA_TOKEN` / `KHALIFA_ACCESS_JWT` is required.

## Run

```bash
npm run build -w packages/mcp-server

# Validate configuration and reach the API's /livez probe:
KHALIFA_API_URL=http://localhost:8080 KHALIFA_TOKEN=... \
  npm run dev -w packages/mcp-server -- --check

# Attach a client (stdio; human output goes to stderr):
KHALIFA_API_URL=http://localhost:8080 KHALIFA_TOKEN=... \
  node packages/mcp-server/dist/cli.js
```

Example client configuration:

```json
{
  "mcpServers": {
    "khalifa": {
      "command": "node",
      "args": ["/path/to/khalifa/packages/mcp-server/dist/cli.js"],
      "env": {
        "KHALIFA_API_URL": "http://localhost:8080",
        "KHALIFA_TOKEN": "<cognito access token>"
      }
    }
  }
}
```

## Test

```bash
npx jest --selectProjects mcp-server
```
