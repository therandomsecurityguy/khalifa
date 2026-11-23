import {
  BedrockClient,
  ListCustomModelsCommand,
  ListGuardrailsCommand,
} from '@aws-sdk/client-bedrock';
import {
  BedrockAgentClient,
  GetAgentActionGroupCommand,
  GetAgentCommand,
  GetDataSourceCommand,
  GetKnowledgeBaseCommand,
  ListAgentActionGroupsCommand,
  ListAgentKnowledgeBasesCommand,
  ListAgentsCommand,
  ListDataSourcesCommand,
  ListKnowledgeBasesCommand,
} from '@aws-sdk/client-bedrock-agent';
import {
  BedrockAgentCoreControlClient,
  GetAgentRuntimeCommand,
  ListAgentRuntimesCommand,
} from '@aws-sdk/client-bedrock-agentcore-control';
import { appendAll } from '../../shared/arrays';
import { collectPaginated } from '../../shared/pagination';
import type { GraphNode, GraphEdge } from '../../shared/types';

export interface CollectResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// AI/agent inventory, agentless and read-only.
//
// Vertices: AiAgent (Bedrock agents and AgentCore agent runtimes, split by the
// `platform` property), AiKnowledgeBase, AiGuardrail, AiModel (custom models).
// Edges: RUNS_AS (agent -> execution role), HAS_KB, HAS_ACTION_GROUP (the
// Lambda an action group invokes, i.e. a tool the agent can call), PROTECTED_BY
// (agent -> guardrail), READS_FROM (knowledge base -> source S3 buckets),
// HAS_ROLE (knowledge base -> service role), USES_MODEL (agent -> custom
// model).
//
// Prompt and instruction bodies are never stored: `has_instruction` records
// only whether one exists, because instruction text routinely carries
// sensitive configuration a posture graph has no reason to duplicate.
//
// Bedrock Flows, inference profiles, and AgentCore gateways/memories are not
// collected yet.

// A resource deleted between a list page and its detail read is a race, not a
// collection failure: the next run's reconcile removes it.
function isNotFound(error: unknown): boolean {
  return error instanceof Error && error.name === 'ResourceNotFoundException';
}

function isNamedError(error: unknown, name: string): boolean {
  return error instanceof Error && error.name === name;
}

// Bedrock and AgentCore are not available in every Region. Where the service
// itself is absent the list call fails with an unsupported-operation error
// instead of returning an empty page; that is "nothing to collect here", not a
// collection failure (the same treatment CloudTrail event selectors get in
// Regions that do not carry them).
function isUnsupportedInRegion(error: unknown): boolean {
  return (
    isNamedError(error, 'UnsupportedOperationException') ||
    isNamedError(error, 'UnknownOperationException')
  );
}

async function collectWhenSupported<T>(load: () => Promise<T>, empty: T): Promise<T> {
  try {
    return await load();
  } catch (error) {
    if (isUnsupportedInRegion(error)) return empty;
    throw error;
  }
}

export async function collectBedrockGuardrails(
  client: BedrockClient,
  accountId: string,
  region: string
): Promise<CollectResult & { arnsById: Map<string, string> }> {
  const nodes: GraphNode[] = [];
  const arnsById = new Map<string, string>();

  const guardrails = await collectWhenSupported(
    () =>
      collectPaginated(
        (token) => client.send(new ListGuardrailsCommand({ nextToken: token })),
        (page) => page.guardrails,
        (page) => page.nextToken
      ),
    []
  );

  for (const guardrail of guardrails) {
    if (!guardrail.arn || !guardrail.id) continue;
    arnsById.set(guardrail.id, guardrail.arn);
    nodes.push({
      id: guardrail.arn,
      label: 'AiGuardrail',
      properties: {
        id: guardrail.id,
        arn: guardrail.arn,
        account_id: accountId,
        region,
        name: guardrail.name,
        status: guardrail.status,
        version: guardrail.version,
        created_at: guardrail.createdAt,
        updated_at: guardrail.updatedAt,
      },
    });
  }

  return { nodes, edges: [], arnsById };
}

export async function collectBedrockCustomModels(
  client: BedrockClient,
  accountId: string,
  region: string
): Promise<CollectResult & { arns: Set<string> }> {
  const nodes: GraphNode[] = [];
  const arns = new Set<string>();

  const models = await collectWhenSupported(
    () =>
      collectPaginated(
        (token) => client.send(new ListCustomModelsCommand({ nextToken: token })),
        (page) => page.modelSummaries,
        (page) => page.nextToken
      ),
    []
  );

  for (const model of models) {
    if (!model.modelArn) continue;
    arns.add(model.modelArn);
    nodes.push({
      id: model.modelArn,
      label: 'AiModel',
      properties: {
        id: model.modelArn,
        arn: model.modelArn,
        account_id: accountId,
        region,
        name: model.modelName,
        base_model_arn: model.baseModelArn,
        base_model_name: model.baseModelName,
        customization_type: model.customizationType,
        status: model.modelStatus,
        owner_account_id: model.ownerAccountId,
        created_at: model.creationTime,
      },
    });
  }

  return { nodes, edges: [], arns };
}

export async function collectBedrockKnowledgeBases(
  client: BedrockAgentClient,
  accountId: string,
  region: string
): Promise<CollectResult & { arnsById: Map<string, string> }> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const arnsById = new Map<string, string>();

  const summaries = await collectWhenSupported(
    () =>
      collectPaginated(
        (token) => client.send(new ListKnowledgeBasesCommand({ nextToken: token })),
        (page) => page.knowledgeBaseSummaries,
        (page) => page.nextToken
      ),
    []
  );

  for (const summary of summaries) {
    if (!summary.knowledgeBaseId) continue;

    let knowledgeBase;
    try {
      knowledgeBase = (
        await client.send(new GetKnowledgeBaseCommand({ knowledgeBaseId: summary.knowledgeBaseId }))
      ).knowledgeBase;
    } catch (error) {
      if (isNotFound(error)) continue;
      throw error;
    }
    if (!knowledgeBase?.knowledgeBaseArn) continue;

    // The data source's S3 bucket is the definitive statement of what content
    // the knowledge base grounds on; the vector store holds the embeddings.
    const dataSources = await collectPaginated(
      (token) =>
        client.send(
          new ListDataSourcesCommand({ knowledgeBaseId: summary.knowledgeBaseId, nextToken: token })
        ),
      (page) => page.dataSourceSummaries,
      (page) => page.nextToken
    );

    const buckets = new Set<string>();
    for (const dataSource of dataSources) {
      if (!dataSource.dataSourceId) continue;
      let full;
      try {
        full = (
          await client.send(
            new GetDataSourceCommand({
              knowledgeBaseId: summary.knowledgeBaseId,
              dataSourceId: dataSource.dataSourceId,
            })
          )
        ).dataSource;
      } catch (error) {
        if (isNotFound(error)) continue;
        throw error;
      }
      const bucketArn = full?.dataSourceConfiguration?.s3Configuration?.bucketArn;
      if (bucketArn) buckets.add(bucketArn);
    }

    const arn = knowledgeBase.knowledgeBaseArn;
    arnsById.set(summary.knowledgeBaseId, arn);
    nodes.push({
      id: arn,
      label: 'AiKnowledgeBase',
      properties: {
        id: summary.knowledgeBaseId,
        arn,
        account_id: accountId,
        region,
        name: knowledgeBase.name,
        status: knowledgeBase.status,
        role_arn: knowledgeBase.roleArn,
        storage_type: knowledgeBase.storageConfiguration?.type,
        embedding_model_arn:
          knowledgeBase.knowledgeBaseConfiguration?.vectorKnowledgeBaseConfiguration
            ?.embeddingModelArn,
        kms_key_arn:
          knowledgeBase.knowledgeBaseConfiguration?.managedKnowledgeBaseConfiguration
            ?.serverSideEncryptionConfiguration?.kmsKeyArn,
        data_source_count: dataSources.length,
        s3_bucket_arns: [...buckets],
        created_at: knowledgeBase.createdAt,
        updated_at: knowledgeBase.updatedAt,
      },
    });

    if (knowledgeBase.roleArn) {
      edges.push({ from: arn, to: knowledgeBase.roleArn, label: 'HAS_ROLE' });
    }
    for (const bucketArn of buckets) {
      edges.push({ from: arn, to: bucketArn, label: 'READS_FROM' });
    }
  }

  return { nodes, edges, arnsById };
}

export interface BedrockAgentReferences {
  // Knowledge base id -> ARN, from the same run's knowledge base collection.
  knowledgeBaseArns: ReadonlyMap<string, string>;
  // Guardrail id -> ARN; identifiers already shaped as ARNs are used as-is.
  guardrailArns: ReadonlyMap<string, string>;
  // Custom model ARNs, so an agent's foundation model can be linked.
  customModelArns: ReadonlySet<string>;
}

export async function collectBedrockAgents(
  client: BedrockAgentClient,
  accountId: string,
  region: string,
  references: BedrockAgentReferences
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const summaries = await collectWhenSupported(
    () =>
      collectPaginated(
        (token) => client.send(new ListAgentsCommand({ nextToken: token })),
        (page) => page.agentSummaries,
        (page) => page.nextToken
      ),
    []
  );

  for (const summary of summaries) {
    if (!summary.agentId) continue;

    let agent;
    try {
      agent = (await client.send(new GetAgentCommand({ agentId: summary.agentId }))).agent;
    } catch (error) {
      if (isNotFound(error)) continue;
      throw error;
    }
    if (!agent?.agentArn) continue;

    const agentArn = agent.agentArn;
    const version = agent.agentVersion;

    // Knowledge bases the agent retrieves from. The edge is only emitted when
    // the same run collected the knowledge base, so it never dangles.
    const links = await collectPaginated(
      (token) =>
        client.send(
          new ListAgentKnowledgeBasesCommand({
            agentId: summary.agentId,
            agentVersion: version,
            nextToken: token,
          })
        ),
      (page) => page.agentKnowledgeBaseSummaries,
      (page) => page.nextToken
    );
    const knowledgeBaseIds: string[] = [];
    for (const link of links) {
      if (!link.knowledgeBaseId) continue;
      knowledgeBaseIds.push(link.knowledgeBaseId);
      const knowledgeBaseArn = references.knowledgeBaseArns.get(link.knowledgeBaseId);
      if (knowledgeBaseArn) {
        edges.push({ from: agentArn, to: knowledgeBaseArn, label: 'HAS_KB' });
      }
    }

    // Action groups are the agent's tools. A Lambda-backed group is a link the
    // agent can invoke, and the Lambda's own role decides what that can reach.
    const groups = await collectPaginated(
      (token) =>
        client.send(
          new ListAgentActionGroupsCommand({
            agentId: summary.agentId,
            agentVersion: version,
            nextToken: token,
          })
        ),
      (page) => page.actionGroupSummaries,
      (page) => page.nextToken
    );
    const actionGroupNames: string[] = [];
    for (const group of groups) {
      if (group.actionGroupName) actionGroupNames.push(group.actionGroupName);
      if (!group.actionGroupId) continue;
      let full;
      try {
        full = (
          await client.send(
            new GetAgentActionGroupCommand({
              agentId: summary.agentId,
              agentVersion: version,
              actionGroupId: group.actionGroupId,
            })
          )
        ).agentActionGroup;
      } catch (error) {
        if (isNotFound(error)) continue;
        throw error;
      }
      const executor = full?.actionGroupExecutor;
      const lambdaArn = executor && 'lambda' in executor ? executor.lambda : undefined;
      if (lambdaArn) {
        edges.push({ from: agentArn, to: lambdaArn, label: 'HAS_ACTION_GROUP' });
      }
    }

    // guardrail_configured is the authoritative signal (the edge target can be
    // missed if the guardrail list was incomplete); the edge is for traversal.
    const guardrailIdentifier = agent.guardrailConfiguration?.guardrailIdentifier;
    if (guardrailIdentifier) {
      const guardrailArn = guardrailIdentifier.startsWith('arn:')
        ? guardrailIdentifier
        : (references.guardrailArns.get(guardrailIdentifier) ??
          `arn:aws:bedrock:${region}:${accountId}:guardrail/${guardrailIdentifier}`);
      edges.push({ from: agentArn, to: guardrailArn, label: 'PROTECTED_BY' });
    }

    const foundationModel = agent.foundationModel;
    if (foundationModel && references.customModelArns.has(foundationModel)) {
      edges.push({ from: agentArn, to: foundationModel, label: 'USES_MODEL' });
    }

    nodes.push({
      id: agentArn,
      label: 'AiAgent',
      properties: {
        id: agent.agentId,
        arn: agentArn,
        account_id: accountId,
        region,
        platform: 'bedrock',
        name: agent.agentName,
        status: agent.agentStatus,
        version,
        foundation_model: foundationModel,
        orchestration_type: agent.orchestrationType,
        role_arn: agent.agentResourceRoleArn,
        has_instruction: Boolean(agent.instruction),
        has_memory: Boolean(agent.memoryConfiguration),
        guardrail_configured: Boolean(guardrailIdentifier),
        guardrail_id: guardrailIdentifier,
        guardrail_version: agent.guardrailConfiguration?.guardrailVersion,
        knowledge_base_ids: knowledgeBaseIds,
        action_group_names: actionGroupNames,
        created_at: agent.createdAt,
        updated_at: agent.updatedAt,
      },
    });

    if (agent.agentResourceRoleArn) {
      edges.push({ from: agentArn, to: agent.agentResourceRoleArn, label: 'RUNS_AS' });
    }
  }

  return { nodes, edges };
}

export async function collectAgentCoreRuntimes(
  client: BedrockAgentCoreControlClient,
  accountId: string,
  region: string
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const runtimes = await collectWhenSupported(
    () =>
      collectPaginated(
        (token) => client.send(new ListAgentRuntimesCommand({ nextToken: token })),
        (page) => page.agentRuntimes,
        (page) => page.nextToken
      ),
    []
  );

  for (const summary of runtimes) {
    if (!summary.agentRuntimeId) continue;

    let detail;
    try {
      detail = await client.send(
        new GetAgentRuntimeCommand({ agentRuntimeId: summary.agentRuntimeId })
      );
    } catch (error) {
      if (isNotFound(error)) continue;
      throw error;
    }
    const arn = detail.agentRuntimeArn ?? summary.agentRuntimeArn;
    if (!arn) continue;

    const artifact = detail.agentRuntimeArtifact;
    const containerUri =
      artifact && 'containerConfiguration' in artifact
        ? artifact.containerConfiguration?.containerUri
        : undefined;

    nodes.push({
      id: arn,
      label: 'AiAgent',
      properties: {
        id: summary.agentRuntimeId,
        arn,
        account_id: accountId,
        region,
        platform: 'agentcore',
        name: detail.agentRuntimeName ?? summary.agentRuntimeName,
        status: detail.status ?? summary.status,
        version: detail.agentRuntimeVersion ?? summary.agentRuntimeVersion,
        role_arn: detail.roleArn,
        network_mode: detail.networkConfiguration?.networkMode,
        workload_identity_arn: detail.workloadIdentityDetails?.workloadIdentityArn,
        protocol: detail.protocolConfiguration?.serverProtocol,
        container_uri: containerUri,
        created_at: detail.createdAt,
        updated_at: detail.lastUpdatedAt ?? summary.lastUpdatedAt,
      },
    });

    if (detail.roleArn) {
      edges.push({ from: arn, to: detail.roleArn, label: 'RUNS_AS' });
    }
  }

  return { nodes, edges };
}

// One Bedrock stage: agents reference knowledge bases and guardrails collected
// in the same pass, so the sub-collections run in dependency order.
export async function collectBedrock(
  agentClient: BedrockAgentClient,
  bedrockClient: BedrockClient,
  accountId: string,
  region: string
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const merge = (result: CollectResult): void => {
    appendAll(nodes, result.nodes);
    appendAll(edges, result.edges);
  };

  const guardrails = await collectBedrockGuardrails(bedrockClient, accountId, region);
  merge(guardrails);

  const models = await collectBedrockCustomModels(bedrockClient, accountId, region);
  merge(models);

  const knowledgeBases = await collectBedrockKnowledgeBases(agentClient, accountId, region);
  merge(knowledgeBases);

  const agents = await collectBedrockAgents(agentClient, accountId, region, {
    knowledgeBaseArns: knowledgeBases.arnsById,
    guardrailArns: guardrails.arnsById,
    customModelArns: models.arns,
  });
  merge(agents);

  return { nodes, edges };
}
