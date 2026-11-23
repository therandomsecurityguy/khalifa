import { BedrockClient } from '@aws-sdk/client-bedrock';
import { BedrockAgentClient } from '@aws-sdk/client-bedrock-agent';
import { BedrockAgentCoreControlClient } from '@aws-sdk/client-bedrock-agentcore-control';
import {
  collectAgentCoreRuntimes,
  collectBedrock,
  collectBedrockAgents,
  collectBedrockCustomModels,
  collectBedrockGuardrails,
  collectBedrockKnowledgeBases,
  type BedrockAgentReferences,
} from './ai';

const ACCOUNT = '111122223333';
const REGION = 'us-east-1';
const ARN_BASE = `arn:aws:bedrock:${REGION}:${ACCOUNT}`;

function createMockClient(responses: {
  [commandName: string]: (input: Record<string, unknown>) => unknown;
}): unknown {
  const send = jest.fn(async (command: { constructor: { name: string } }) => {
    const handler = responses[command.constructor.name];
    if (!handler) {
      throw new Error(`Unexpected command in test: ${command.constructor.name}`);
    }
    return handler((command as unknown as { input: Record<string, unknown> }).input || {});
  });
  return { send };
}

const emptyReferences: BedrockAgentReferences = {
  knowledgeBaseArns: new Map(),
  guardrailArns: new Map(),
  customModelArns: new Set(),
};

describe('collectBedrockGuardrails', () => {
  it('emits guardrail nodes and resolves ids to ARNs across pages', async () => {
    const client = createMockClient({
      ListGuardrailsCommand: (input) =>
        input.nextToken
          ? {
              guardrails: [
                {
                  id: 'gr-2',
                  arn: `${ARN_BASE}:guardrail/gr-2`,
                  name: 'second',
                  status: 'READY',
                  version: '2',
                },
              ],
            }
          : {
              guardrails: [
                {
                  id: 'gr-1',
                  arn: `${ARN_BASE}:guardrail/gr-1`,
                  name: 'first',
                  status: 'READY',
                  version: 'DRAFT',
                },
              ],
              nextToken: 'page-2',
            },
    });

    const { nodes, edges, arnsById } = await collectBedrockGuardrails(
      client as BedrockClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(2);
    expect(nodes[0]).toMatchObject({ label: 'AiGuardrail', id: `${ARN_BASE}:guardrail/gr-1` });
    expect(nodes[0].properties).toMatchObject({
      name: 'first',
      status: 'READY',
      version: 'DRAFT',
      account_id: ACCOUNT,
      region: REGION,
    });
    expect(arnsById.get('gr-2')).toBe(`${ARN_BASE}:guardrail/gr-2`);
    expect(edges).toHaveLength(0);
  });

  it('skips entries with no ARN instead of emitting an unusable vertex', async () => {
    const client = createMockClient({
      ListGuardrailsCommand: () => ({ guardrails: [{ id: 'gr-1', name: 'no-arn' }] }),
    });

    const { nodes, arnsById } = await collectBedrockGuardrails(
      client as BedrockClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(0);
    expect(arnsById.size).toBe(0);
  });

  it('treats an unsupported-region error as an empty collection', async () => {
    const client = createMockClient({
      ListGuardrailsCommand: () => {
        const error = new Error('unsupported in this region');
        error.name = 'UnsupportedOperationException';
        throw error;
      },
    });

    const { nodes, edges } = await collectBedrockGuardrails(
      client as BedrockClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(0);
    expect(edges).toHaveLength(0);
  });
});

describe('collectBedrockCustomModels', () => {
  it('emits custom model vertices and returns their ARNs', async () => {
    const modelArn = `${ARN_BASE}:custom-model/model-1`;
    const client = createMockClient({
      ListCustomModelsCommand: () => ({
        modelSummaries: [
          {
            modelArn,
            modelName: 'support-tuned',
            baseModelArn: 'arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite',
            baseModelName: 'nova-lite',
            customizationType: 'FINE_TUNING',
            modelStatus: 'ACTIVE',
          },
          { modelName: 'missing-arn' },
        ],
      }),
    });

    const { nodes, arns } = await collectBedrockCustomModels(
      client as BedrockClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ label: 'AiModel', id: modelArn });
    expect(nodes[0].properties).toMatchObject({
      name: 'support-tuned',
      base_model_name: 'nova-lite',
      customization_type: 'FINE_TUNING',
      status: 'ACTIVE',
    });
    expect(arns.has(modelArn)).toBe(true);
  });
});

describe('collectBedrockKnowledgeBases', () => {
  it('emits knowledge bases with roles and data-source bucket edges', async () => {
    const kbArn = `${ARN_BASE}:knowledge-base/kb-1`;
    const roleArn = `arn:aws:iam::${ACCOUNT}:role/kb-role`;
    const bucketArn = 'arn:aws:s3:::kb-data';
    const client = createMockClient({
      ListKnowledgeBasesCommand: () => ({
        knowledgeBaseSummaries: [{ knowledgeBaseId: 'kb-1', name: 'kb', status: 'ACTIVE' }],
      }),
      GetKnowledgeBaseCommand: () => ({
        knowledgeBase: {
          knowledgeBaseId: 'kb-1',
          name: 'kb',
          knowledgeBaseArn: kbArn,
          roleArn,
          status: 'ACTIVE',
          knowledgeBaseConfiguration: {
            type: 'VECTOR',
            vectorKnowledgeBaseConfiguration: {
              embeddingModelArn: 'arn:aws:bedrock:us-east-1::foundation-model/titan-embed',
            },
          },
          storageConfiguration: { type: 'OPENSEARCH_SERVERLESS' },
        },
      }),
      ListDataSourcesCommand: () => ({
        dataSourceSummaries: [
          { knowledgeBaseId: 'kb-1', dataSourceId: 'ds-1', name: 's3', status: 'AVAILABLE' },
          { knowledgeBaseId: 'kb-1', dataSourceId: 'ds-2', name: 'web', status: 'AVAILABLE' },
        ],
      }),
      GetDataSourceCommand: (input) =>
        input.dataSourceId === 'ds-1'
          ? {
              dataSource: {
                dataSourceConfiguration: { type: 'S3', s3Configuration: { bucketArn } },
              },
            }
          : {
              dataSource: {
                dataSourceConfiguration: { type: 'WEB', webConfiguration: {} },
              },
            },
    });

    const { nodes, edges, arnsById } = await collectBedrockKnowledgeBases(
      client as BedrockAgentClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ label: 'AiKnowledgeBase', id: kbArn });
    expect(nodes[0].properties).toMatchObject({
      role_arn: roleArn,
      storage_type: 'OPENSEARCH_SERVERLESS',
      embedding_model_arn: 'arn:aws:bedrock:us-east-1::foundation-model/titan-embed',
      data_source_count: 2,
      s3_bucket_arns: [bucketArn],
    });
    expect(edges).toEqual(
      expect.arrayContaining([
        { from: kbArn, to: roleArn, label: 'HAS_ROLE' },
        { from: kbArn, to: bucketArn, label: 'READS_FROM' },
      ])
    );
    expect(arnsById.get('kb-1')).toBe(kbArn);
  });

  it('tolerates a knowledge base that disappears between the list and the read', async () => {
    const client = createMockClient({
      ListKnowledgeBasesCommand: () => ({
        knowledgeBaseSummaries: [{ knowledgeBaseId: 'kb-gone' }, { knowledgeBaseId: 'kb-live' }],
      }),
      GetKnowledgeBaseCommand: (input) => {
        if (input.knowledgeBaseId === 'kb-gone') {
          const error = new Error('not found');
          error.name = 'ResourceNotFoundException';
          throw error;
        }
        return {
          knowledgeBase: {
            knowledgeBaseId: 'kb-live',
            name: 'live',
            knowledgeBaseArn: `${ARN_BASE}:knowledge-base/kb-live`,
            status: 'ACTIVE',
          },
        };
      },
      ListDataSourcesCommand: () => ({ dataSourceSummaries: [] }),
    });

    const { nodes } = await collectBedrockKnowledgeBases(
      client as BedrockAgentClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0].id).toBe(`${ARN_BASE}:knowledge-base/kb-live`);
  });
});

describe('collectBedrockAgents', () => {
  it('links knowledge bases, tools, guardrail, role, and custom model', async () => {
    const agentArn = `${ARN_BASE}:agent/agent-1`;
    const roleArn = `arn:aws:iam::${ACCOUNT}:role/agent-role`;
    const lambdaArn = `arn:aws:lambda:${REGION}:${ACCOUNT}:function:agent-tool`;
    const kbArn = `${ARN_BASE}:knowledge-base/kb-1`;
    const customModelArn = `${ARN_BASE}:custom-model/model-1`;
    const references: BedrockAgentReferences = {
      knowledgeBaseArns: new Map([['kb-1', kbArn]]),
      guardrailArns: new Map([['gr-1', `${ARN_BASE}:guardrail/gr-1`]]),
      customModelArns: new Set([customModelArn]),
    };
    const client = createMockClient({
      ListAgentsCommand: () => ({
        agentSummaries: [{ agentId: 'agent-1', agentName: 'assistant', agentStatus: 'PREPARED' }],
      }),
      GetAgentCommand: () => ({
        agent: {
          agentId: 'agent-1',
          agentArn,
          agentName: 'assistant',
          agentVersion: 'DRAFT',
          agentStatus: 'PREPARED',
          foundationModel: customModelArn,
          agentResourceRoleArn: roleArn,
          instruction: 'You are a helpful assistant.',
          guardrailConfiguration: { guardrailIdentifier: 'gr-1', guardrailVersion: '3' },
          memoryConfiguration: { sessionSummaryConfiguration: {} },
        },
      }),
      ListAgentKnowledgeBasesCommand: () => ({
        agentKnowledgeBaseSummaries: [
          { knowledgeBaseId: 'kb-1', knowledgeBaseState: 'ENABLED' },
          { knowledgeBaseId: 'kb-deleted', knowledgeBaseState: 'ENABLED' },
        ],
      }),
      ListAgentActionGroupsCommand: () => ({
        actionGroupSummaries: [
          { actionGroupId: 'ag-1', actionGroupName: 'lookup' },
          { actionGroupId: 'ag-2', actionGroupName: 'native' },
        ],
      }),
      GetAgentActionGroupCommand: (input) =>
        input.actionGroupId === 'ag-1'
          ? { agentActionGroup: { actionGroupExecutor: { lambda: lambdaArn } } }
          : { agentActionGroup: { actionGroupExecutor: { customControl: 'RETURN_CONTROL' } } },
    });

    const { nodes, edges } = await collectBedrockAgents(
      client as BedrockAgentClient,
      ACCOUNT,
      REGION,
      references
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ label: 'AiAgent', id: agentArn });
    expect(nodes[0].properties).toMatchObject({
      platform: 'bedrock',
      status: 'PREPARED',
      foundation_model: customModelArn,
      role_arn: roleArn,
      has_instruction: true,
      has_memory: true,
      guardrail_configured: true,
      guardrail_id: 'gr-1',
      guardrail_version: '3',
      knowledge_base_ids: ['kb-1', 'kb-deleted'],
      action_group_names: ['lookup', 'native'],
    });
    expect(edges).toEqual(
      expect.arrayContaining([
        { from: agentArn, to: roleArn, label: 'RUNS_AS' },
        { from: agentArn, to: kbArn, label: 'HAS_KB' },
        { from: agentArn, to: lambdaArn, label: 'HAS_ACTION_GROUP' },
        { from: agentArn, to: `${ARN_BASE}:guardrail/gr-1`, label: 'PROTECTED_BY' },
        { from: agentArn, to: customModelArn, label: 'USES_MODEL' },
      ])
    );
    // A knowledge base the run did not collect, and a non-Lambda executor,
    // produce no edges so nothing dangles.
    expect(edges.filter((edge) => edge.label === 'HAS_KB')).toHaveLength(1);
    expect(edges.filter((edge) => edge.label === 'HAS_ACTION_GROUP')).toHaveLength(1);
    // Instruction bodies are never copied into the graph.
    expect(nodes[0].properties.instruction).toBeUndefined();
  });

  it('constructs a guardrail ARN when the list did not supply one', async () => {
    const agentArn = `${ARN_BASE}:agent/agent-2`;
    const client = createMockClient({
      ListAgentsCommand: () => ({ agentSummaries: [{ agentId: 'agent-2' }] }),
      GetAgentCommand: () => ({
        agent: {
          agentId: 'agent-2',
          agentArn,
          agentVersion: 'DRAFT',
          agentStatus: 'PREPARED',
          guardrailConfiguration: { guardrailIdentifier: 'gr-unknown' },
        },
      }),
      ListAgentKnowledgeBasesCommand: () => ({ agentKnowledgeBaseSummaries: [] }),
      ListAgentActionGroupsCommand: () => ({ actionGroupSummaries: [] }),
    });

    const { edges } = await collectBedrockAgents(
      client as BedrockAgentClient,
      ACCOUNT,
      REGION,
      emptyReferences
    );

    expect(edges).toContainEqual({
      from: agentArn,
      to: `${ARN_BASE}:guardrail/gr-unknown`,
      label: 'PROTECTED_BY',
    });
  });

  it('records an unguarded agent without a PROTECTED_BY edge', async () => {
    const agentArn = `${ARN_BASE}:agent/agent-3`;
    const client = createMockClient({
      ListAgentsCommand: () => ({ agentSummaries: [{ agentId: 'agent-3' }] }),
      GetAgentCommand: () => ({
        agent: {
          agentId: 'agent-3',
          agentArn,
          agentVersion: 'DRAFT',
          agentStatus: 'PREPARED',
        },
      }),
      ListAgentKnowledgeBasesCommand: () => ({ agentKnowledgeBaseSummaries: [] }),
      ListAgentActionGroupsCommand: () => ({ actionGroupSummaries: [] }),
    });

    const { nodes, edges } = await collectBedrockAgents(
      client as BedrockAgentClient,
      ACCOUNT,
      REGION,
      emptyReferences
    );

    expect(nodes[0].properties.guardrail_configured).toBe(false);
    expect(edges.some((edge) => edge.label === 'PROTECTED_BY')).toBe(false);
  });

  it('rethrows non-NotFound failures so the stage records FAILED', async () => {
    const client = createMockClient({
      ListAgentsCommand: () => {
        throw new Error('boom');
      },
    });

    await expect(
      collectBedrockAgents(client as BedrockAgentClient, ACCOUNT, REGION, emptyReferences)
    ).rejects.toThrow('boom');
  });

  it('treats an unsupported-region error as an empty collection', async () => {
    const client = createMockClient({
      ListAgentsCommand: () => {
        const error = new Error('unknown operation');
        error.name = 'UnknownOperationException';
        throw error;
      },
    });

    const { nodes, edges } = await collectBedrockAgents(
      client as BedrockAgentClient,
      ACCOUNT,
      REGION,
      emptyReferences
    );

    expect(nodes).toHaveLength(0);
    expect(edges).toHaveLength(0);
  });
});

describe('collectAgentCoreRuntimes', () => {
  it('emits runtime agents with roles, network mode, and container links', async () => {
    const runtimeArn = `arn:aws:bedrock-agentcore:${REGION}:${ACCOUNT}:runtime/rt-1`;
    const roleArn = `arn:aws:iam::${ACCOUNT}:role/runtime-role`;
    const client = createMockClient({
      ListAgentRuntimesCommand: () => ({
        agentRuntimes: [
          {
            agentRuntimeId: 'rt-1',
            agentRuntimeArn: runtimeArn,
            agentRuntimeName: 'support',
            agentRuntimeVersion: '1',
            status: 'READY',
          },
        ],
      }),
      GetAgentRuntimeCommand: () => ({
        agentRuntimeArn: runtimeArn,
        agentRuntimeId: 'rt-1',
        agentRuntimeName: 'support',
        agentRuntimeVersion: '1',
        status: 'READY',
        roleArn,
        networkConfiguration: { networkMode: 'PUBLIC' },
        protocolConfiguration: { serverProtocol: 'HTTP' },
        workloadIdentityDetails: { workloadIdentityArn: `${runtimeArn}/identity` },
        agentRuntimeArtifact: {
          containerConfiguration: {
            containerUri: `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/agent:latest`,
          },
        },
      }),
    });

    const { nodes, edges } = await collectAgentCoreRuntimes(
      client as BedrockAgentCoreControlClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ label: 'AiAgent', id: runtimeArn });
    expect(nodes[0].properties).toMatchObject({
      platform: 'agentcore',
      name: 'support',
      status: 'READY',
      role_arn: roleArn,
      network_mode: 'PUBLIC',
      protocol: 'HTTP',
      workload_identity_arn: `${runtimeArn}/identity`,
      container_uri: `${ACCOUNT}.dkr.ecr.${REGION}.amazonaws.com/agent:latest`,
    });
    expect(edges).toEqual([{ from: runtimeArn, to: roleArn, label: 'RUNS_AS' }]);
  });

  it('omits the role edge when the runtime has no execution role', async () => {
    const runtimeArn = `arn:aws:bedrock-agentcore:${REGION}:${ACCOUNT}:runtime/rt-2`;
    const client = createMockClient({
      ListAgentRuntimesCommand: () => ({
        agentRuntimes: [{ agentRuntimeId: 'rt-2', agentRuntimeArn: runtimeArn }],
      }),
      GetAgentRuntimeCommand: () => ({ agentRuntimeArn: runtimeArn, agentRuntimeId: 'rt-2' }),
    });

    const { nodes, edges } = await collectAgentCoreRuntimes(
      client as BedrockAgentCoreControlClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(edges).toHaveLength(0);
  });

  it('tolerates a runtime that disappears between the list and the read', async () => {
    const client = createMockClient({
      ListAgentRuntimesCommand: () => ({
        agentRuntimes: [{ agentRuntimeId: 'rt-gone' }],
      }),
      GetAgentRuntimeCommand: () => {
        const error = new Error('not found');
        error.name = 'ResourceNotFoundException';
        throw error;
      },
    });

    const { nodes } = await collectAgentCoreRuntimes(
      client as BedrockAgentCoreControlClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(0);
  });

  it('treats an unsupported-region error as an empty collection', async () => {
    const client = createMockClient({
      ListAgentRuntimesCommand: () => {
        const error = new Error('unknown operation');
        error.name = 'UnknownOperationException';
        throw error;
      },
    });

    const { nodes, edges } = await collectAgentCoreRuntimes(
      client as BedrockAgentCoreControlClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(0);
    expect(edges).toHaveLength(0);
  });
});

describe('collectBedrock', () => {
  it('composes the sub-collections and links agents to the same run’s knowledge bases', async () => {
    const kbArn = `${ARN_BASE}:knowledge-base/kb-1`;
    const agentArn = `${ARN_BASE}:agent/agent-1`;
    const bedrockClient = createMockClient({
      ListGuardrailsCommand: () => ({ guardrails: [] }),
      ListCustomModelsCommand: () => ({ modelSummaries: [] }),
    });
    const agentClient = createMockClient({
      ListKnowledgeBasesCommand: () => ({
        knowledgeBaseSummaries: [{ knowledgeBaseId: 'kb-1' }],
      }),
      GetKnowledgeBaseCommand: () => ({
        knowledgeBase: {
          knowledgeBaseId: 'kb-1',
          name: 'kb',
          knowledgeBaseArn: kbArn,
          status: 'ACTIVE',
        },
      }),
      ListDataSourcesCommand: () => ({ dataSourceSummaries: [] }),
      ListAgentsCommand: () => ({ agentSummaries: [{ agentId: 'agent-1' }] }),
      GetAgentCommand: () => ({
        agent: {
          agentId: 'agent-1',
          agentArn,
          agentVersion: 'DRAFT',
          agentStatus: 'PREPARED',
        },
      }),
      ListAgentKnowledgeBasesCommand: () => ({
        agentKnowledgeBaseSummaries: [{ knowledgeBaseId: 'kb-1' }],
      }),
      ListAgentActionGroupsCommand: () => ({ actionGroupSummaries: [] }),
    });

    const { nodes, edges } = await collectBedrock(
      agentClient as BedrockAgentClient,
      bedrockClient as BedrockClient,
      ACCOUNT,
      REGION
    );

    expect(nodes.map((node) => node.label).sort()).toEqual(['AiAgent', 'AiKnowledgeBase']);
    expect(edges).toContainEqual({ from: agentArn, to: kbArn, label: 'HAS_KB' });
  });
});
