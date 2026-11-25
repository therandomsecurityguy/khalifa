import { z } from 'zod';
import { KhalifaApiError, type KhalifaApiClient } from './client';

/**
 * Read-only tools over the Khalifa REST API. Every tool maps to a Viewer+
 * endpoint; writes (issue lifecycle, use-case registry) are deliberately not
 * exposed, so an agent holding these tools can never change the system.
 */
export interface ToolTextResult {
  // Index signature so the shape satisfies the SDK's CallToolResult type.
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export interface KhalifaTool {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, z.ZodType>;
  handler: (args: Record<string, unknown>) => Promise<ToolTextResult>;
}

function ok(value: unknown): ToolTextResult {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

function fail(error: unknown): ToolTextResult {
  if (error instanceof KhalifaApiError) {
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: `Khalifa API error (${error.status === 0 ? 'network' : error.status}): ${error.message}`,
        },
      ],
    };
  }
  return {
    isError: true,
    content: [
      {
        type: 'text',
        text: `Khalifa request failed: ${error instanceof Error ? error.message : String(error)}`,
      },
    ],
  };
}

export function buildTools(client: KhalifaApiClient): KhalifaTool[] {
  const read = (
    name: string,
    title: string,
    description: string,
    inputSchema: Record<string, z.ZodType>,
    request: (args: Record<string, unknown>) => { path: string; params?: Record<string, unknown> }
  ): KhalifaTool => ({
    name,
    title,
    description,
    inputSchema,
    handler: async (args) => {
      try {
        const { path, params } = request(args);
        return ok(await client.get(path, params));
      } catch (error) {
        return fail(error);
      }
    },
  });

  return [
    read(
      'list_issues',
      'List issues',
      'Risk issues (findings) ranked by risk score, with severity, rule, owning team, and status. Each issue carries its rule id; use get_issue for the attack path behind one.',
      {
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
        status: z.enum(['open', 'suppressed', 'resolved']).optional(),
        ruleId: z.string().max(32).optional(),
        team: z.string().max(64).optional(),
        limit: z.number().int().min(1).max(200).default(25),
        order: z.enum(['desc', 'asc']).default('desc'),
      },
      (args) => ({ path: '/issues', params: args })
    ),
    read(
      'get_issue',
      'Get issue',
      'One issue with its attack path, likelihood factors, ATT&CK techniques, and remediation hint. The likelihood includes a coverage factor: a stale graph reads as lower confidence, and the response says how fresh it was.',
      { id: z.string().min(1).max(200) },
      ({ id }) => ({ path: `/issues/${encodeURIComponent(String(id))}` })
    ),
    read(
      'search_resources',
      'Search resources',
      'Search collected graph vertices by label, optionally filtered by a property value. Labels are the graph types (IamRole, S3Bucket, Ec2Instance, AiAgent, ...); use list constants or the resource explorer in the UI when unsure.',
      {
        label: z.string().min(1).max(64),
        property: z.string().max(64).optional(),
        value: z.string().max(256).optional(),
        limit: z.number().int().min(1).max(200).default(50),
      },
      (args) => ({ path: '/resources/search', params: args })
    ),
    read(
      'get_resource',
      'Get resource',
      'One resource by ARN, with neighbors, edges, and open issues on it.',
      { arn: z.string().min(1) },
      ({ arn }) => ({ path: `/resources/${encodeURIComponent(String(arn))}` })
    ),
    read(
      'get_attack_paths',
      'Get attack paths',
      'Attack-path search between presets (internet, outside, a resource) and targets (restricted data, crown jewels, secrets, admin roles). Presets are closed on purpose; each returned path carries an explainable likelihood with its coverage statement.',
      {
        from: z.enum(['any', 'internet', 'outside', 'resource']).default('any'),
        to: z.enum(['restricted', 'crown', 'secrets', 'admin', 'resource']).default('restricted'),
        fromResource: z.string().optional(),
        toResource: z.string().optional(),
        account: z.string().max(64).optional(),
        maxPathLength: z.number().int().min(1).max(5).default(4),
        limit: z.number().int().min(1).max(100).default(25),
      },
      (args) => ({ path: '/attack-paths/search', params: args })
    ),
    read(
      'compliance_status',
      'Compliance status',
      'Framework summaries: CIS AWS Foundations, the Khalifa baseline, and the mapped frameworks (SOC 2, ISO 27001, PCI DSS, NIST 800-53, ISO 42001, NIST AI RMF), with control counts and coverage. Nothing here is a certification.',
      {},
      () => ({ path: '/compliance/frameworks' })
    ),
    read(
      'compliance_control',
      'Compliance control',
      'One control (or mapped requirement) with its evidence and citation links. Use the framework ids returned by compliance_status (CIS_AWS_FOUNDATIONS, KHALIFA_BASELINE, SOC2, ISO27001, PCI_DSS, NIST_800_53, ISO_42001, NIST_AI_RMF).',
      {
        framework: z.string().min(1).max(64),
        controlId: z.string().min(1).max(64),
      },
      ({ framework, controlId }) => ({
        path: `/compliance/frameworks/${encodeURIComponent(String(framework))}/controls/${encodeURIComponent(String(controlId))}`,
      })
    ),
    read(
      'ai_inventory',
      'AI inventory',
      'The collected AI estate: Bedrock agents (guardrail state, execution role, foundation model), knowledge bases with their S3 data sources, guardrails, custom models, AgentCore runtimes, and SageMaker endpoints/notebooks/Studio domains. Counts are null when the count query could not run, and truncation is explicit.',
      {
        type: z
          .enum([
            'agents',
            'knowledgeBases',
            'guardrails',
            'models',
            'endpoints',
            'notebooks',
            'domains',
          ])
          .optional(),
        limit: z.number().int().min(1).max(100).default(25),
      },
      (args) => ({ path: '/ai/inventory', params: args })
    ),
    read(
      'get_ai_agent',
      'Get AI agent',
      'One Bedrock agent or AgentCore runtime: execution role, knowledge bases, guardrail, action-group tools, custom model, and open issues.',
      { arn: z.string().min(1) },
      ({ arn }) => ({ path: `/ai/agents/${encodeURIComponent(String(arn))}` })
    ),
    read(
      'ai_use_cases',
      'AI use cases',
      'The governance registry: use cases with owner, status, covered asset ARNs, data classes, and their lite impact assessment.',
      {},
      () => ({ path: '/ai/use-cases' })
    ),
    read(
      'ai_use_case_coverage',
      'AI use-case coverage',
      'The registry joined against the collected estate: collected AI assets no use case covers, and registered assets missing from the graph. Both lists are bounded; truncation is flagged rather than hidden.',
      {},
      () => ({ path: '/ai/use-cases/coverage' })
    ),
  ];
}
