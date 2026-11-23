import {
  SageMakerClient,
  DescribeDomainCommand,
  DescribeEndpointCommand,
  DescribeEndpointConfigCommand,
  DescribeNotebookInstanceCommand,
  ListDomainsCommand,
  ListEndpointsCommand,
  ListNotebookInstancesCommand,
} from '@aws-sdk/client-sagemaker';
import { appendAll } from '../../shared/arrays';
import { collectPaginated } from '../../shared/pagination';
import type { GraphNode, GraphEdge } from '../../shared/types';

export interface CollectResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// SageMaker AI inventory, agentless and read-only.
//
// Vertices: AiEndpoint (plus its endpoint configuration's execution role, KMS
// key, VPC and network-isolation facts), AiNotebook (direct internet access,
// root access, volume KMS, instance metadata service version), AiDomain
// (Studio domain: auth mode, app network access type, KMS, VPC, execution
// role).
// Edges: RUNS_AS (endpoint/notebook/domain -> execution role).
//
// Studio apps, models, training jobs, and pipelines are not collected yet.

// A resource deleted between a list page and its detail read is a race, not a
// collection failure: the next run's reconcile removes it.
function isNotFound(error: unknown): boolean {
  return error instanceof Error && error.name === 'ResourceNotFoundException';
}

export async function collectSageMakerEndpoints(
  client: SageMakerClient,
  accountId: string,
  region: string
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const summaries = await collectPaginated(
    (token) => client.send(new ListEndpointsCommand({ NextToken: token })),
    (page) => page.Endpoints,
    (page) => page.NextToken
  );

  for (const summary of summaries) {
    if (!summary.EndpointName) continue;

    let endpoint;
    try {
      endpoint = await client.send(
        new DescribeEndpointCommand({ EndpointName: summary.EndpointName })
      );
    } catch (error) {
      if (isNotFound(error)) continue;
      throw error;
    }
    if (!endpoint.EndpointArn) continue;

    // The execution role, KMS key, and network placement live on the endpoint
    // configuration, not the endpoint itself. A config deleted out from under
    // a live endpoint leaves those facts unknown, not the collection broken.
    let config;
    if (endpoint.EndpointConfigName) {
      try {
        config = await client.send(
          new DescribeEndpointConfigCommand({ EndpointConfigName: endpoint.EndpointConfigName })
        );
      } catch (error) {
        if (!isNotFound(error)) throw error;
      }
    }

    const arn = endpoint.EndpointArn;
    nodes.push({
      id: arn,
      label: 'AiEndpoint',
      properties: {
        id: summary.EndpointName,
        arn,
        account_id: accountId,
        region,
        name: endpoint.EndpointName,
        status: endpoint.EndpointStatus,
        endpoint_config_name: endpoint.EndpointConfigName,
        role_arn: config?.ExecutionRoleArn,
        kms_key_id: config?.KmsKeyId,
        network_isolation: config?.EnableNetworkIsolation,
        in_vpc: Boolean(config?.VpcConfig),
        subnet_ids: config?.VpcConfig?.Subnets,
        data_capture_enabled: endpoint.DataCaptureConfig?.EnableCapture,
        data_capture_destination: endpoint.DataCaptureConfig?.DestinationS3Uri,
        data_capture_kms_key_id: endpoint.DataCaptureConfig?.KmsKeyId,
        variant_names: (endpoint.ProductionVariants ?? [])
          .map((variant) => variant.VariantName)
          .filter(Boolean),
        created_at: endpoint.CreationTime,
        updated_at: endpoint.LastModifiedTime,
      },
    });

    if (config?.ExecutionRoleArn) {
      edges.push({ from: arn, to: config.ExecutionRoleArn, label: 'RUNS_AS' });
    }
  }

  return { nodes, edges };
}

export async function collectSageMakerNotebooks(
  client: SageMakerClient,
  accountId: string,
  region: string
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const summaries = await collectPaginated(
    (token) => client.send(new ListNotebookInstancesCommand({ NextToken: token })),
    (page) => page.NotebookInstances,
    (page) => page.NextToken
  );

  for (const summary of summaries) {
    if (!summary.NotebookInstanceName) continue;

    let notebook;
    try {
      notebook = await client.send(
        new DescribeNotebookInstanceCommand({ NotebookInstanceName: summary.NotebookInstanceName })
      );
    } catch (error) {
      if (isNotFound(error)) continue;
      throw error;
    }
    if (!notebook.NotebookInstanceArn) continue;

    const arn = notebook.NotebookInstanceArn;
    nodes.push({
      id: arn,
      label: 'AiNotebook',
      properties: {
        id: summary.NotebookInstanceName,
        arn,
        account_id: accountId,
        region,
        name: notebook.NotebookInstanceName,
        status: notebook.NotebookInstanceStatus,
        instance_type: notebook.InstanceType,
        role_arn: notebook.RoleArn,
        direct_internet_access: notebook.DirectInternetAccess,
        root_access: notebook.RootAccess,
        volume_kms_key_id: notebook.KmsKeyId,
        subnet_id: notebook.SubnetId,
        security_group_ids: notebook.SecurityGroups,
        platform_identifier: notebook.PlatformIdentifier,
        minimum_instance_metadata_service_version:
          notebook.InstanceMetadataServiceConfiguration?.MinimumInstanceMetadataServiceVersion,
        created_at: notebook.CreationTime,
        updated_at: notebook.LastModifiedTime,
      },
    });

    if (notebook.RoleArn) {
      edges.push({ from: arn, to: notebook.RoleArn, label: 'RUNS_AS' });
    }
  }

  return { nodes, edges };
}

export async function collectSageMakerDomains(
  client: SageMakerClient,
  accountId: string,
  region: string
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const summaries = await collectPaginated(
    (token) => client.send(new ListDomainsCommand({ NextToken: token })),
    (page) => page.Domains,
    (page) => page.NextToken
  );

  for (const summary of summaries) {
    if (!summary.DomainId) continue;

    let domain;
    try {
      domain = await client.send(new DescribeDomainCommand({ DomainId: summary.DomainId }));
    } catch (error) {
      if (isNotFound(error)) continue;
      throw error;
    }
    const arn = domain.DomainArn ?? summary.DomainArn;
    if (!arn) continue;

    // The execution role Studio sessions assume; the domain itself decides
    // whether apps are reachable from the public internet (AppNetworkAccessType).
    const executionRole = domain.DefaultUserSettings?.ExecutionRole;

    nodes.push({
      id: arn,
      label: 'AiDomain',
      properties: {
        id: summary.DomainId,
        arn,
        account_id: accountId,
        region,
        name: domain.DomainName ?? summary.DomainName,
        status: domain.Status ?? summary.Status,
        auth_mode: domain.AuthMode,
        app_network_access_type: domain.AppNetworkAccessType,
        role_arn: executionRole,
        kms_key_id: domain.KmsKeyId,
        home_efs_kms_key_id: domain.HomeEfsFileSystemKmsKeyId,
        vpc_id: domain.VpcId,
        subnet_ids: domain.SubnetIds,
        created_at: domain.CreationTime,
        updated_at: domain.LastModifiedTime,
      },
    });

    if (executionRole) {
      edges.push({ from: arn, to: executionRole, label: 'RUNS_AS' });
    }
  }

  return { nodes, edges };
}

export async function collectSageMaker(
  client: SageMakerClient,
  accountId: string,
  region: string
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const parts = [collectSageMakerEndpoints, collectSageMakerNotebooks, collectSageMakerDomains];

  for (const collectPart of parts) {
    const result = await collectPart(client, accountId, region);
    appendAll(nodes, result.nodes);
    appendAll(edges, result.edges);
  }

  return { nodes, edges };
}
