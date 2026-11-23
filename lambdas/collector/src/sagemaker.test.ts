import { SageMakerClient } from '@aws-sdk/client-sagemaker';
import {
  collectSageMaker,
  collectSageMakerDomains,
  collectSageMakerEndpoints,
  collectSageMakerNotebooks,
} from './sagemaker';

const ACCOUNT = '111122223333';
const REGION = 'us-east-1';
const ARN_BASE = `arn:aws:sagemaker:${REGION}:${ACCOUNT}`;

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

describe('collectSageMakerEndpoints', () => {
  it('emits endpoints with config-derived role, KMS, network, and data capture facts', async () => {
    const endpointArn = `${ARN_BASE}:endpoint/support-llm`;
    const roleArn = `arn:aws:iam::${ACCOUNT}:role/sagemaker-execution`;
    const client = createMockClient({
      ListEndpointsCommand: (input) =>
        input.NextToken
          ? {
              Endpoints: [{ EndpointName: 'second', EndpointArn: `${ARN_BASE}:endpoint/second` }],
            }
          : {
              Endpoints: [
                {
                  EndpointName: 'support-llm',
                  EndpointArn: endpointArn,
                  EndpointStatus: 'InService',
                },
              ],
              NextToken: 'page-2',
            },
      DescribeEndpointCommand: (input) =>
        input.EndpointName === 'second'
          ? {
              EndpointName: 'second',
              EndpointArn: `${ARN_BASE}:endpoint/second`,
              EndpointStatus: 'Creating',
            }
          : {
              EndpointName: 'support-llm',
              EndpointArn: endpointArn,
              EndpointConfigName: 'support-llm-config',
              EndpointStatus: 'InService',
              ProductionVariants: [{ VariantName: 'AllTraffic' }],
              DataCaptureConfig: {
                EnableCapture: true,
                DestinationS3Uri: 's3://capture-bucket/prefix',
                KmsKeyId: 'kms-capture',
              },
            },
      DescribeEndpointConfigCommand: (input) =>
        input.EndpointConfigName === 'support-llm-config'
          ? {
              EndpointConfigName: 'support-llm-config',
              ExecutionRoleArn: roleArn,
              KmsKeyId: 'kms-endpoint',
              EnableNetworkIsolation: true,
              VpcConfig: { Subnets: [`subnet-12345678`] },
            }
          : { EndpointConfigName: 'second-config' },
    });

    const { nodes, edges } = await collectSageMakerEndpoints(
      client as SageMakerClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(2);
    expect(nodes[0]).toMatchObject({ label: 'AiEndpoint', id: endpointArn });
    expect(nodes[0].properties).toMatchObject({
      role_arn: roleArn,
      kms_key_id: 'kms-endpoint',
      network_isolation: true,
      in_vpc: true,
      subnet_ids: ['subnet-12345678'],
      data_capture_enabled: true,
      data_capture_destination: 's3://capture-bucket/prefix',
      data_capture_kms_key_id: 'kms-capture',
      variant_names: ['AllTraffic'],
    });
    expect(edges).toEqual([{ from: endpointArn, to: roleArn, label: 'RUNS_AS' }]);
  });

  it('keeps an endpoint whose configuration read fails but the endpoint read does not', async () => {
    const endpointArn = `${ARN_BASE}:endpoint/orphan`;
    const client = createMockClient({
      ListEndpointsCommand: () => ({
        Endpoints: [{ EndpointName: 'orphan', EndpointArn: endpointArn }],
      }),
      DescribeEndpointCommand: () => ({
        EndpointName: 'orphan',
        EndpointArn: endpointArn,
        EndpointConfigName: 'gone-config',
        EndpointStatus: 'InService',
      }),
      DescribeEndpointConfigCommand: () => {
        const error = new Error('not found');
        error.name = 'ResourceNotFoundException';
        throw error;
      },
    });

    const { nodes, edges } = await collectSageMakerEndpoints(
      client as SageMakerClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0].properties.role_arn).toBeUndefined();
    expect(edges).toHaveLength(0);
  });

  it('tolerates an endpoint that disappears between the list and the read', async () => {
    const client = createMockClient({
      ListEndpointsCommand: () => ({
        Endpoints: [{ EndpointName: 'gone' }],
      }),
      DescribeEndpointCommand: () => {
        const error = new Error('not found');
        error.name = 'ResourceNotFoundException';
        throw error;
      },
    });

    const { nodes } = await collectSageMakerEndpoints(client as SageMakerClient, ACCOUNT, REGION);

    expect(nodes).toHaveLength(0);
  });

  it('rethrows non-NotFound failures so the stage records FAILED', async () => {
    const client = createMockClient({
      ListEndpointsCommand: () => {
        throw new Error('boom');
      },
    });

    await expect(
      collectSageMakerEndpoints(client as SageMakerClient, ACCOUNT, REGION)
    ).rejects.toThrow('boom');
  });
});

describe('collectSageMakerNotebooks', () => {
  it('emits notebooks with internet, root, KMS, and role facts', async () => {
    const notebookArn = `${ARN_BASE}:notebook-instance/experiments`;
    const roleArn = `arn:aws:iam::${ACCOUNT}:role/notebook-execution`;
    const client = createMockClient({
      ListNotebookInstancesCommand: () => ({
        NotebookInstances: [
          { NotebookInstanceName: 'experiments', NotebookInstanceArn: notebookArn },
        ],
      }),
      DescribeNotebookInstanceCommand: () => ({
        NotebookInstanceName: 'experiments',
        NotebookInstanceArn: notebookArn,
        NotebookInstanceStatus: 'InService',
        InstanceType: 'ml.t3.medium',
        RoleArn: roleArn,
        DirectInternetAccess: 'Enabled',
        RootAccess: 'Disabled',
        KmsKeyId: 'kms-volume',
        SubnetId: 'subnet-12345678',
        SecurityGroups: ['sg-12345678'],
        PlatformIdentifier: 'notebook-al2-v2',
        InstanceMetadataServiceConfiguration: { MinimumInstanceMetadataServiceVersion: '2' },
        CreationTime: new Date('2026-01-01T00:00:00Z'),
        LastModifiedTime: new Date('2026-02-01T00:00:00Z'),
      }),
    });

    const { nodes, edges } = await collectSageMakerNotebooks(
      client as SageMakerClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ label: 'AiNotebook', id: notebookArn });
    expect(nodes[0].properties).toMatchObject({
      status: 'InService',
      instance_type: 'ml.t3.medium',
      role_arn: roleArn,
      direct_internet_access: 'Enabled',
      root_access: 'Disabled',
      volume_kms_key_id: 'kms-volume',
      subnet_id: 'subnet-12345678',
      platform_identifier: 'notebook-al2-v2',
      minimum_instance_metadata_service_version: '2',
    });
    expect(edges).toEqual([{ from: notebookArn, to: roleArn, label: 'RUNS_AS' }]);
  });

  it('omits the role edge when the notebook has no execution role', async () => {
    const notebookArn = `${ARN_BASE}:notebook-instance/no-role`;
    const client = createMockClient({
      ListNotebookInstancesCommand: () => ({
        NotebookInstances: [{ NotebookInstanceName: 'no-role' }],
      }),
      DescribeNotebookInstanceCommand: () => ({
        NotebookInstanceName: 'no-role',
        NotebookInstanceArn: notebookArn,
        NotebookInstanceStatus: 'Stopped',
      }),
    });

    const { nodes, edges } = await collectSageMakerNotebooks(
      client as SageMakerClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(edges).toHaveLength(0);
  });

  it('tolerates a notebook that disappears between the list and the read', async () => {
    const client = createMockClient({
      ListNotebookInstancesCommand: () => ({
        NotebookInstances: [{ NotebookInstanceName: 'gone' }],
      }),
      DescribeNotebookInstanceCommand: () => {
        const error = new Error('not found');
        error.name = 'ResourceNotFoundException';
        throw error;
      },
    });

    const { nodes } = await collectSageMakerNotebooks(client as SageMakerClient, ACCOUNT, REGION);

    expect(nodes).toHaveLength(0);
  });
});

describe('collectSageMakerDomains', () => {
  it('emits domains with auth, network, KMS, and execution role facts', async () => {
    const domainArn = `${ARN_BASE}:domain/d-abc123`;
    const roleArn = `arn:aws:iam::${ACCOUNT}:role/studio-execution`;
    const client = createMockClient({
      ListDomainsCommand: () => ({
        Domains: [{ DomainId: 'd-abc123', DomainArn: domainArn, DomainName: 'analytics' }],
      }),
      DescribeDomainCommand: () => ({
        DomainId: 'd-abc123',
        DomainArn: domainArn,
        DomainName: 'analytics',
        Status: 'InService',
        AuthMode: 'IAM',
        AppNetworkAccessType: 'VpcOnly',
        KmsKeyId: 'kms-domain',
        HomeEfsFileSystemKmsKeyId: 'kms-efs',
        VpcId: 'vpc-12345678',
        SubnetIds: ['subnet-12345678'],
        DefaultUserSettings: { ExecutionRole: roleArn },
      }),
    });

    const { nodes, edges } = await collectSageMakerDomains(
      client as SageMakerClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(nodes[0]).toMatchObject({ label: 'AiDomain', id: domainArn });
    expect(nodes[0].properties).toMatchObject({
      name: 'analytics',
      status: 'InService',
      auth_mode: 'IAM',
      app_network_access_type: 'VpcOnly',
      role_arn: roleArn,
      kms_key_id: 'kms-domain',
      home_efs_kms_key_id: 'kms-efs',
      vpc_id: 'vpc-12345678',
      subnet_ids: ['subnet-12345678'],
    });
    expect(edges).toEqual([{ from: domainArn, to: roleArn, label: 'RUNS_AS' }]);
  });

  it('omits the role edge when the domain has no execution role', async () => {
    const domainArn = `${ARN_BASE}:domain/d-no-role`;
    const client = createMockClient({
      ListDomainsCommand: () => ({
        Domains: [{ DomainId: 'd-no-role', DomainArn: domainArn }],
      }),
      DescribeDomainCommand: () => ({ DomainId: 'd-no-role', DomainArn: domainArn }),
    });

    const { nodes, edges } = await collectSageMakerDomains(
      client as SageMakerClient,
      ACCOUNT,
      REGION
    );

    expect(nodes).toHaveLength(1);
    expect(edges).toHaveLength(0);
  });
});

describe('collectSageMaker', () => {
  it('composes endpoints, notebooks, and domains into one result', async () => {
    const endpointArn = `${ARN_BASE}:endpoint/support-llm`;
    const notebookArn = `${ARN_BASE}:notebook-instance/experiments`;
    const domainArn = `${ARN_BASE}:domain/d-abc123`;
    const client = createMockClient({
      ListEndpointsCommand: () => ({
        Endpoints: [{ EndpointName: 'support-llm', EndpointArn: endpointArn }],
      }),
      DescribeEndpointCommand: () => ({
        EndpointName: 'support-llm',
        EndpointArn: endpointArn,
        EndpointStatus: 'InService',
      }),
      ListNotebookInstancesCommand: () => ({
        NotebookInstances: [
          { NotebookInstanceName: 'experiments', NotebookInstanceArn: notebookArn },
        ],
      }),
      DescribeNotebookInstanceCommand: () => ({
        NotebookInstanceName: 'experiments',
        NotebookInstanceArn: notebookArn,
        NotebookInstanceStatus: 'InService',
      }),
      ListDomainsCommand: () => ({
        Domains: [{ DomainId: 'd-abc123', DomainArn: domainArn }],
      }),
      DescribeDomainCommand: () => ({ DomainId: 'd-abc123', DomainArn: domainArn }),
    });

    const { nodes } = await collectSageMaker(client as SageMakerClient, ACCOUNT, REGION);

    expect(nodes.map((node) => node.label).sort()).toEqual([
      'AiDomain',
      'AiEndpoint',
      'AiNotebook',
    ]);
  });
});
