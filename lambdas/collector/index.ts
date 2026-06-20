import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { fromTemporaryCredentials } from '@aws-sdk/credential-providers';
import {
  EC2Client,
  paginateDescribeInstances,
  DescribeSecurityGroupsCommand,
  DescribeVpcsCommand,
  DescribeVpcEndpointsCommand,
  DescribeNetworkAclsCommand,
  DescribeRouteTablesCommand,
  DescribeTransitGatewaysCommand,
  DescribeInternetGatewaysCommand,
  DescribeNatGatewaysCommand,
  DescribeSubnetsCommand,
} from '@aws-sdk/client-ec2';
import { ResourceGroupsTaggingAPIClient } from '@aws-sdk/client-resource-groups-tagging-api';
import { ElasticLoadBalancingV2Client } from '@aws-sdk/client-elastic-load-balancing-v2';
import { ECRClient, DescribeRepositoriesCommand, ListImagesCommand } from '@aws-sdk/client-ecr';
import {
  S3Client,
  ListBucketsCommand,
  GetBucketVersioningCommand,
  GetBucketEncryptionCommand,
  GetBucketLoggingCommand,
  GetBucketPolicyCommand,
  GetPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import {
  IAMClient,
  ListUsersCommand,
  ListRolesCommand,
  ListPoliciesCommand,
  GetAccountPasswordPolicyCommand,
  GetCredentialReportCommand,
  ListGroupsCommand,
  ListGroupPoliciesCommand,
  GetGroupPolicyCommand,
  ListAttachedRolePoliciesCommand,
  ListAttachedUserPoliciesCommand,
  ListAttachedGroupPoliciesCommand,
  GetPolicyVersionCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
  ListUserPoliciesCommand,
  GetUserPolicyCommand,
} from '@aws-sdk/client-iam';
import { KMSClient, ListKeysCommand, DescribeKeyCommand } from '@aws-sdk/client-kms';
import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { EKSClient, ListClustersCommand, DescribeClusterCommand } from '@aws-sdk/client-eks';
import { SecurityHubClient, GetFindingsCommand } from '@aws-sdk/client-securityhub';
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetTrailStatusCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeDeliveryChannelsCommand,
  DescribeConfigRulesCommand,
} from '@aws-sdk/client-config-service';
import {
  GuardDutyClient,
  ListDetectorsCommand,
  GetDetectorCommand,
} from '@aws-sdk/client-guardduty';
import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
  ListFindingsCommand,
} from '@aws-sdk/client-accessanalyzer';
import { Route53Client, ListHostedZonesCommand } from '@aws-sdk/client-route-53';
import {
  APIGatewayClient,
  GetRestApisCommand,
  GetStagesCommand,
} from '@aws-sdk/client-api-gateway';
import {
  LambdaClient,
  ListFunctionsCommand,
  ListAliasesCommand,
  ListEventSourceMappingsCommand,
} from '@aws-sdk/client-lambda';
import { SFNClient, ListStateMachinesCommand } from '@aws-sdk/client-sfn';
import {
  EventBridgeClient,
  ListEventBusesCommand,
  ListRulesCommand,
} from '@aws-sdk/client-eventbridge';
import { DynamoDBClient, ListTablesCommand, DescribeTableCommand } from '@aws-sdk/client-dynamodb';
import { ElastiCacheClient, DescribeCacheClustersCommand } from '@aws-sdk/client-elasticache';
import {
  OpenSearchClient,
  ListDomainNamesCommand,
  DescribeDomainCommand,
} from '@aws-sdk/client-opensearch';
import { RedshiftClient, DescribeClustersCommand } from '@aws-sdk/client-redshift';
import {
  SecretsManagerClient,
  ListSecretsCommand,
  DescribeSecretCommand,
} from '@aws-sdk/client-secrets-manager';
import { SSMClient, DescribeParametersCommand } from '@aws-sdk/client-ssm';
import {
  BackupClient,
  ListBackupVaultsCommand,
  ListBackupPlansCommand,
} from '@aws-sdk/client-backup';
import type { GraphNode, GraphEdge } from '../shared/types';
import { Logger } from '../shared/types';
import { fetchTagsForArns, extractCommonProperties, type TagMap } from './src/tags';
import {
  collectSecurityGroups,
  collectInternetGateways,
  collectNatGateways,
  collectSubnets,
  buildInternetNode,
  INTERNET_NODE_ID,
} from './src/network';
import { collectLoadBalancers } from './src/load-balancers';
import { collectContainerImages } from './src/containers';
import { collectCrossAccountTrust } from './src/cross-account';
import { buildExposureContext, applyExposureToNodes, type ExposureContext } from './src/exposure';

const logger = new Logger('collector');
const stsClient = new STSClient({ region: process.env.AWS_REGION || 'us-east-1' });

const INTERNET_EXPOSED_LABELS = new Set([
  'Ec2Instance',
  'LambdaFunction',
  'RdsInstance',
  'RedshiftCluster',
  'OpenSearchDomain',
  'ApiGateway',
  'LoadBalancer',
]);

interface CollectorEvent {
  accountId: string;
}

function createClients(region: string, credentials?: any) {
  const baseConfig = { region };
  const credConfig = credentials
    ? {
        credentials: {
          accessKeyId: credentials.AccessKeyId!,
          secretAccessKey: credentials.SecretAccessKey!,
          sessionToken: credentials.SessionToken!,
          expiration: credentials.Expiration,
        },
      }
    : {};

  return {
    ec2Client: new EC2Client({ ...baseConfig, ...credConfig }),
    s3Client: new S3Client({ ...baseConfig, ...credConfig }),
    iamClient: new IAMClient({ ...baseConfig, ...credConfig }),
    kmsClient: new KMSClient({ ...baseConfig, ...credConfig }),
    rdsClient: new RDSClient({ ...baseConfig, ...credConfig }),
    eksClient: new EKSClient({ ...baseConfig, ...credConfig }),
    securityHubClient: new SecurityHubClient({ ...baseConfig, ...credConfig }),
    cloudTrailClient: new CloudTrailClient({ ...baseConfig, ...credConfig }),
    configClient: new ConfigServiceClient({ ...baseConfig, ...credConfig }),
    guardDutyClient: new GuardDutyClient({ ...baseConfig, ...credConfig }),
    accessAnalyzerClient: new AccessAnalyzerClient({ ...baseConfig, ...credConfig }),
    route53Client: new Route53Client({ ...baseConfig, ...credConfig }),
    apiGatewayClient: new APIGatewayClient({ ...baseConfig, ...credConfig }),
    lambdaClient: new LambdaClient({ ...baseConfig, ...credConfig }),
    sfnClient: new SFNClient({ ...baseConfig, ...credConfig }),
    eventBridgeClient: new EventBridgeClient({ ...baseConfig, ...credConfig }),
    dynamoDBClient: new DynamoDBClient({ ...baseConfig, ...credConfig }),
    elasticacheClient: new ElastiCacheClient({ ...baseConfig, ...credConfig }),
    opensearchClient: new OpenSearchClient({ ...baseConfig, ...credConfig }),
    redshiftClient: new RedshiftClient({ ...baseConfig, ...credConfig }),
    secretsManagerClient: new SecretsManagerClient({ ...baseConfig, ...credConfig }),
    ssmClient: new SSMClient({ ...baseConfig, ...credConfig }),
    backupClient: new BackupClient({ ...baseConfig, ...credConfig }),
    elbV2Client: new ElasticLoadBalancingV2Client({ ...baseConfig, ...credConfig }),
    ecrClient: new ECRClient({ ...baseConfig, ...credConfig }),
    taggingClient: new ResourceGroupsTaggingAPIClient({ ...baseConfig, ...credConfig }),
  };
}

export const handler = async (
  event: CollectorEvent
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> => {
  const { accountId } = event;
  logger.info(`Starting collection for account: ${accountId}`);

  const mockMode = process.env.MOCK_MODE === 'true';
  const masterAccountId = process.env.MASTER_ACCOUNT_ID;
  const region = process.env.AWS_REGION || 'us-east-1';

  let clients: ReturnType<typeof createClients>;

  if (mockMode || accountId === masterAccountId) {
    clients = createClients(region);
  } else {
    const roleArn = `arn:aws:iam::${accountId}:role/SecurityGraphCollectorRole`;
    const assumedRole = await stsClient.send(
      new AssumeRoleCommand({
        RoleArn: roleArn,
        RoleSessionName: `SecurityGraphIngestion-${Date.now()}`,
        DurationSeconds: 3600,
      })
    );

    if (!assumedRole.Credentials) throw new Error('Failed to assume role');

    clients = createClients(region, assumedRole.Credentials);
  }

  const {
    ec2Client,
    s3Client,
    iamClient,
    kmsClient,
    rdsClient,
    eksClient,
    securityHubClient,
    cloudTrailClient,
    configClient,
    guardDutyClient,
    accessAnalyzerClient,
    route53Client,
    apiGatewayClient,
    lambdaClient,
    sfnClient,
    eventBridgeClient,
    dynamoDBClient,
    elasticacheClient,
    opensearchClient,
    redshiftClient,
    secretsManagerClient,
    ssmClient,
    backupClient,
    elbV2Client,
    ecrClient,
    taggingClient,
  } = clients;

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  nodes.push(buildInternetNode(accountId));

  const ec2Data = await collectEc2(ec2Client, accountId, region);
  nodes.push(...ec2Data.nodes);
  edges.push(...ec2Data.edges);

  const s3Data = await collectS3(s3Client, accountId);
  nodes.push(...s3Data.nodes);
  edges.push(...s3Data.edges);

  const iamData = await collectIam(iamClient, accountId);
  nodes.push(...iamData.nodes);
  edges.push(...iamData.edges);

  const kmsData = await collectKms(kmsClient, accountId);
  nodes.push(...kmsData.nodes);
  edges.push(...kmsData.edges);

  const rdsData = await collectRds(rdsClient, accountId, region);
  nodes.push(...rdsData.nodes);
  edges.push(...rdsData.edges);

  const eksData = await collectEks(eksClient, accountId, region);
  nodes.push(...eksData.nodes);
  edges.push(...eksData.edges);

  const shData = await collectSecurityHub(securityHubClient, accountId, region);
  nodes.push(...shData.nodes);
  edges.push(...shData.edges);

  const cloudTrailData = await collectCloudTrail(cloudTrailClient, accountId, region);
  nodes.push(...cloudTrailData.nodes);
  edges.push(...cloudTrailData.edges);

  const configData = await collectConfig(configClient, accountId, region);
  nodes.push(...configData.nodes);
  edges.push(...configData.edges);

  const guardDutyData = await collectGuardDuty(guardDutyClient, accountId, region);
  nodes.push(...guardDutyData.nodes);
  edges.push(...guardDutyData.edges);

  const accessAnalyzerData = await collectAccessAnalyzer(accessAnalyzerClient, accountId, region);
  nodes.push(...accessAnalyzerData.nodes);
  edges.push(...accessAnalyzerData.edges);

  const networkData = await collectNetwork(ec2Client, route53Client, accountId, region);
  nodes.push(...networkData.nodes);
  edges.push(...networkData.edges);

  const serverlessData = await collectServerless(
    apiGatewayClient,
    lambdaClient,
    sfnClient,
    eventBridgeClient,
    accountId,
    region
  );
  nodes.push(...serverlessData.nodes);
  edges.push(...serverlessData.edges);

  const datastoreData = await collectDataStores(
    dynamoDBClient,
    elasticacheClient,
    opensearchClient,
    redshiftClient,
    accountId,
    region
  );
  nodes.push(...datastoreData.nodes);
  edges.push(...datastoreData.edges);

  const secretsData = await collectSecrets(secretsManagerClient, ssmClient, accountId, region);
  nodes.push(...secretsData.nodes);
  edges.push(...secretsData.edges);

  const backupData = await collectBackup(backupClient, accountId, region);
  nodes.push(...backupData.nodes);
  edges.push(...backupData.edges);

  const subnetData = await collectSubnets(ec2Client, accountId, region);
  nodes.push(...subnetData.nodes);
  edges.push(...subnetData.edges);

  const sgData = await collectSecurityGroups(ec2Client, accountId, region, new Map());
  nodes.push(...sgData.nodes);
  edges.push(...sgData.edges);

  const igwData = await collectInternetGateways(ec2Client, accountId, region, new Map());
  nodes.push(...igwData.nodes);
  edges.push(...igwData.edges);

  const natData = await collectNatGateways(ec2Client, accountId, region, new Map());
  nodes.push(...natData.nodes);
  edges.push(...natData.edges);

  const lbData = await collectLoadBalancers(elbV2Client, accountId, region, new Map());
  nodes.push(...lbData.nodes);
  edges.push(...lbData.edges);

  const ecrData = await collectContainerImages(ecrClient, accountId, region, new Map());
  nodes.push(...ecrData.nodes);
  edges.push(...ecrData.edges);

  const crossAcctData = await collectCrossAccountTrust(iamClient, accountId, new Map());
  nodes.push(...crossAcctData.nodes);
  edges.push(...crossAcctData.edges);

  const exposureCtx: ExposureContext = buildExposureContext(nodes);
  const exposedNodes = applyExposureToNodes(nodes, exposureCtx);

  const tagArns = exposedNodes
    .filter(
      (n) =>
        n.id &&
        !n.id.startsWith(INTERNET_NODE_ID) &&
        !n.id.startsWith('arn:aws:khalifa:external-account:')
    )
    .map((n) => n.id);
  let tagsByArn = new Map<string, TagMap>();
  try {
    tagsByArn = await fetchTagsForArns(taggingClient, tagArns);
  } catch (e) {
    logger.warn(`Tag fetch failed, continuing without tags: ${e}`);
  }

  const finalNodes: GraphNode[] = exposedNodes.map((node) => {
    if (!INTERNET_EXPOSED_LABELS.has(node.label) && node.label !== 'Ec2Instance') {
      const tags = tagsByArn.get(node.id);
      if (!tags) return node;
      const tagProps = extractCommonProperties(tags);
      return {
        ...node,
        properties: {
          ...node.properties,
          ...tagProps,
        },
      };
    }
    const tags = tagsByArn.get(node.id);
    const tagProps = extractCommonProperties(tags);
    return {
      ...node,
      properties: {
        ...node.properties,
        ...tagProps,
      },
    };
  });

  logger.info(`Collection complete: ${finalNodes.length} nodes, ${edges.length} edges`);
  return { nodes: finalNodes, edges };
};

async function collectEc2(client: EC2Client, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const paginator = paginateDescribeInstances({ client }, {});
  for await (const page of paginator) {
    for (const reservation of page.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        const instanceArn = `arn:aws:ec2:${region}:${accountId}:instance/${instance.InstanceId}`;

        nodes.push({
          id: instanceArn,
          label: 'Ec2Instance',
          properties: {
            id: instance.InstanceId,
            arn: instanceArn,
            account_id: accountId,
            instance_type: instance.InstanceType,
            state: instance.State?.Name,
            public_ip: instance.PublicIpAddress,
            private_ip: instance.PrivateIpAddress,
            image_id: instance.ImageId,
            launch_time: instance.LaunchTime?.toISOString(),
            subnet_id: instance.SubnetId,
            vpc_id: instance.VpcId,
            region,
          },
        });

        if (instance.VpcId) {
          edges.push({
            from: `arn:aws:ec2:${region}:${accountId}:vpc/${instance.VpcId}`,
            to: instanceArn,
            label: 'CONTAINS',
          });
        }

        for (const ni of instance.NetworkInterfaces || []) {
          const niArn = `arn:aws:ec2:${region}:${accountId}:network-interface/${ni.NetworkInterfaceId}`;
          nodes.push({
            id: niArn,
            label: 'NetworkInterface',
            properties: {
              id: ni.NetworkInterfaceId,
              arn: niArn,
              account_id: accountId,
              mac_address: ni.MacAddress,
              private_ip: ni.PrivateIpAddress,
              subnet_id: ni.SubnetId,
              vpc_id: ni.VpcId,
              attachment_status: ni.Status,
              instance_id: instance.InstanceId,
            },
          });

          edges.push({ from: niArn, to: instanceArn, label: 'ATTACHED_TO' });

          for (const sg of ni.Groups || []) {
            edges.push({
              from: `arn:aws:ec2:${sg.GroupId}:${sg.GroupId}`,
              to: niArn,
              label: 'PROTECTS',
            });
          }
        }
      }
    }
  }

  return { nodes, edges };
}

async function collectS3(client: S3Client, accountId: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const buckets = await client.send(new ListBucketsCommand({}));
    for (const bucket of buckets.Buckets || []) {
      const bucketArn = `arn:aws:s3:::${bucket.Name}`;
      const versioning = await client
        .send(new GetBucketVersioningCommand({ Bucket: bucket.Name }))
        .catch(() => ({ Status: 'Suspended' }));
      const encryption = await client
        .send(new GetBucketEncryptionCommand({ Bucket: bucket.Name }))
        .catch(() => ({ ServerSideEncryptionConfiguration: null }));
      const logging = await client
        .send(new GetBucketLoggingCommand({ Bucket: bucket.Name }))
        .catch(() => ({ LoggingEnabled: null }));
      const policy = await client
        .send(new GetBucketPolicyCommand({ Bucket: bucket.Name }))
        .catch(() => ({ Policy: null }));
      const publicAccess = await client
        .send(new GetPublicAccessBlockCommand({ Bucket: bucket.Name }))
        .catch(() => ({
          PublicAccessBlockConfiguration: { BlockPublicAcls: false, BlockPublicPolicy: false },
        }));

      const isPublic =
        policy.Policy ||
        !publicAccess.PublicAccessBlockConfiguration?.BlockPublicAcls ||
        !publicAccess.PublicAccessBlockConfiguration?.BlockPublicPolicy;

      nodes.push({
        id: bucketArn,
        label: 'S3Bucket',
        properties: {
          id: bucket.Name,
          arn: bucketArn,
          account_id: accountId,
          name: bucket.Name,
          creation_date: bucket.CreationDate?.toISOString(),
          versioning_enabled: versioning.Status === 'Enabled',
          default_encryption: !!encryption.ServerSideEncryptionConfiguration,
          logging_enabled: !!logging.LoggingEnabled,
          is_publicly_accessible: isPublic,
          data_classification: '',
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: bucketArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('S3 collection error:', e);
  }

  return { nodes, edges };
}

async function collectIam(client: IAMClient, accountId: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const policyDocumentCache = new Map<string, string>();

  const users = await client.send(new ListUsersCommand({}));
  const userPolicies = new Map<string, string[]>();
  for (const user of users.Users || []) {
    const userArn = `arn:aws:iam::${accountId}:user/${user.UserName}`;
    nodes.push({
      id: userArn,
      label: 'IamUser',
      properties: {
        id: user.UserName,
        arn: userArn,
        account_id: accountId,
        path: user.Path,
        create_date: user.CreateDate?.toISOString(),
      },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: userArn, label: 'OWNS' });

    try {
      const inlinePolicies = await client.send(
        new ListUserPoliciesCommand({ UserName: user.UserName! })
      );
      for (const policyName of inlinePolicies.PolicyNames || []) {
        const policyDoc = await client.send(
          new GetUserPolicyCommand({ UserName: user.UserName!, PolicyName: policyName })
        );
        const policyArn = `${userArn}/inline-policy/${policyName}`;
        const documentJson = policyDoc.PolicyDocument
          ? decodeURIComponent(policyDoc.PolicyDocument)
          : '{}';
        nodes.push({
          id: policyArn,
          label: 'IamPolicyDocument',
          properties: {
            id: policyName,
            arn: policyArn,
            policy_arn: policyArn,
            default_version_id: 'inline',
            document_json: documentJson,
            policy_type: 'inline',
            account_id: accountId,
          },
        });
        edges.push({ from: userArn, to: policyArn, label: 'ATTACHED_TO' });
        addStatementNodeAndEdges(nodes, edges, policyArn, documentJson, accountId);
      }
    } catch (e) {}

    try {
      const attached = await client.send(
        new ListAttachedUserPoliciesCommand({ UserName: user.UserName! })
      );
      for (const policy of attached.AttachedPolicies || []) {
        edges.push({ from: userArn, to: policy.PolicyArn!, label: 'ATTACHED_TO' });
        if (!policyDocumentCache.has(policy.PolicyArn!)) {
          await cacheManagedPolicyDocument(
            client,
            policy.PolicyArn!,
            policyDocumentCache,
            nodes,
            edges,
            accountId
          );
        }
      }
    } catch (e) {}

    try {
      const groups = await client.send(
        new (await import('@aws-sdk/client-iam')).ListGroupsForUserCommand({
          UserName: user.UserName!,
        })
      );
      for (const group of groups.Groups || []) {
        const groupArn = `arn:aws:iam::${accountId}:group/${group.GroupName}`;
        edges.push({ from: userArn, to: groupArn, label: 'MEMBER_OF' });
      }
    } catch (e) {}
  }

  const roles = await client.send(new ListRolesCommand({}));
  for (const role of roles.Roles || []) {
    const roleArn = `arn:aws:iam::${accountId}:role/${role.RoleName}`;
    nodes.push({
      id: roleArn,
      label: 'IamRole',
      properties: {
        id: role.RoleName,
        arn: roleArn,
        account_id: accountId,
        path: role.Path,
        create_date: role.CreateDate?.toISOString(),
        assume_role_policy_document: role.AssumeRolePolicyDocument
          ? decodeURIComponent(role.AssumeRolePolicyDocument)
          : undefined,
      },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: roleArn, label: 'OWNS' });

    if (role.AssumeRolePolicyDocument) {
      parseTrustPolicy(
        nodes,
        edges,
        roleArn,
        decodeURIComponent(role.AssumeRolePolicyDocument),
        accountId
      );
    }

    try {
      const inlinePolicies = await client.send(
        new ListRolePoliciesCommand({ RoleName: role.RoleName! })
      );
      for (const policyName of inlinePolicies.PolicyNames || []) {
        const policyDoc = await client.send(
          new GetRolePolicyCommand({ RoleName: role.RoleName!, PolicyName: policyName })
        );
        const policyArn = `${roleArn}/inline-policy/${policyName}`;
        const documentJson = policyDoc.PolicyDocument
          ? decodeURIComponent(policyDoc.PolicyDocument)
          : '{}';
        nodes.push({
          id: policyArn,
          label: 'IamPolicyDocument',
          properties: {
            id: policyName,
            arn: policyArn,
            policy_arn: policyArn,
            default_version_id: 'inline',
            document_json: documentJson,
            policy_type: 'inline',
            account_id: accountId,
          },
        });
        edges.push({ from: roleArn, to: policyArn, label: 'ATTACHED_TO' });
        addStatementNodeAndEdges(nodes, edges, policyArn, documentJson, accountId);
      }
    } catch (e) {}

    try {
      const attached = await client.send(
        new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName! })
      );
      for (const policy of attached.AttachedPolicies || []) {
        edges.push({ from: roleArn, to: policy.PolicyArn!, label: 'ATTACHED_TO' });
        if (!policyDocumentCache.has(policy.PolicyArn!)) {
          await cacheManagedPolicyDocument(
            client,
            policy.PolicyArn!,
            policyDocumentCache,
            nodes,
            edges,
            accountId
          );
        }
      }
    } catch (e) {}

    if (role.PermissionsBoundary?.PermissionsBoundaryArn) {
      edges.push({
        from: roleArn,
        to: role.PermissionsBoundary.PermissionsBoundaryArn,
        label: 'HAS_PERMISSION_BOUNDARY',
      });
    }
  }

  const groups = await client.send(new ListGroupsCommand({}));
  for (const group of groups.Groups || []) {
    const groupArn = `arn:aws:iam::${accountId}:group/${group.GroupName}`;
    nodes.push({
      id: groupArn,
      label: 'IamGroup',
      properties: {
        id: group.GroupName,
        arn: groupArn,
        account_id: accountId,
        path: group.Path,
        create_date: group.CreateDate?.toISOString(),
      },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: groupArn, label: 'OWNS' });

    try {
      const inlinePolicies = await client.send(
        new ListGroupPoliciesCommand({ GroupName: group.GroupName! })
      );
      for (const policyName of inlinePolicies.PolicyNames || []) {
        const policyDoc = await client.send(
          new GetGroupPolicyCommand({ GroupName: group.GroupName!, PolicyName: policyName })
        );
        const policyArn = `${groupArn}/inline-policy/${policyName}`;
        const documentJson = policyDoc.PolicyDocument
          ? decodeURIComponent(policyDoc.PolicyDocument)
          : '{}';
        nodes.push({
          id: policyArn,
          label: 'IamPolicyDocument',
          properties: {
            id: policyName,
            arn: policyArn,
            policy_arn: policyArn,
            default_version_id: 'inline',
            document_json: documentJson,
            policy_type: 'inline',
            account_id: accountId,
          },
        });
        edges.push({ from: groupArn, to: policyArn, label: 'ATTACHED_TO' });
        addStatementNodeAndEdges(nodes, edges, policyArn, documentJson, accountId);
      }
    } catch (e) {}

    try {
      const attached = await client.send(
        new ListAttachedGroupPoliciesCommand({ GroupName: group.GroupName! })
      );
      for (const policy of attached.AttachedPolicies || []) {
        edges.push({ from: groupArn, to: policy.PolicyArn!, label: 'ATTACHED_TO' });
        if (!policyDocumentCache.has(policy.PolicyArn!)) {
          await cacheManagedPolicyDocument(
            client,
            policy.PolicyArn!,
            policyDocumentCache,
            nodes,
            edges,
            accountId
          );
        }
      }
    } catch (e) {}
  }

  const policies = await client.send(new ListPoliciesCommand({ Scope: 'Local' }));
  for (const policy of policies.Policies || []) {
    const policyArn = `arn:aws:iam::${accountId}:policy/${policy.PolicyName}`;
    nodes.push({
      id: policyArn,
      label: 'IamPolicy',
      properties: {
        id: policy.PolicyName,
        arn: policyArn,
        account_id: accountId,
        policy_name: policy.PolicyName,
        policy_type: (policy as any).Type || 'Managed',
      },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: policyArn, label: 'OWNS' });

    if (!policyDocumentCache.has(policyArn)) {
      await cacheManagedPolicyDocument(
        client,
        policyArn,
        policyDocumentCache,
        nodes,
        edges,
        accountId
      );
    }
  }

  const awsManagedPolicies = await client.send(
    new ListPoliciesCommand({ Scope: 'AWS', OnlyAttached: true })
  );
  for (const policy of awsManagedPolicies.Policies || []) {
    if (!policyDocumentCache.has(policy.Arn!)) {
      await cacheManagedPolicyDocument(
        client,
        policy.Arn!,
        policyDocumentCache,
        nodes,
        edges,
        accountId
      );
    }
  }

  try {
    const passwordPolicy = await client.send(new GetAccountPasswordPolicyCommand({}));
    if (passwordPolicy.PasswordPolicy) {
      const pp = passwordPolicy.PasswordPolicy;
      nodes.push({
        id: `arn:aws:iam::${accountId}:password-policy`,
        label: 'AccountPasswordPolicy',
        properties: {
          id: 'account-password-policy',
          arn: `arn:aws:iam::${accountId}:password-policy`,
          account_id: accountId,
          min_password_length: pp.MinimumPasswordLength,
          require_symbols: pp.RequireSymbols,
          require_numbers: pp.RequireNumbers,
          require_uppercase: pp.RequireUppercaseCharacters,
          require_lowercase: pp.RequireLowercaseCharacters,
          max_password_age: pp.MaxPasswordAge,
          password_reuse_prevention: pp.PasswordReusePrevention,
        },
      });
      edges.push({
        from: `arn:aws:iam::${accountId}:root`,
        to: `arn:aws:iam::${accountId}:password-policy`,
        label: 'HAS_POLICY',
      });
    }
  } catch (e) {}

  return { nodes, edges };
}

async function cacheManagedPolicyDocument(
  client: IAMClient,
  policyArn: string,
  cache: Map<string, string>,
  nodes: GraphNode[],
  edges: GraphEdge[],
  accountId: string
): Promise<void> {
  if (cache.has(policyArn)) return;

  try {
    const versions = await client.send(
      new (await import('@aws-sdk/client-iam')).ListPolicyVersionsCommand({ PolicyArn: policyArn })
    );
    const defaultVersion = versions.Versions?.find((v) => v.IsDefaultVersion);
    if (!defaultVersion?.VersionId) return;

    const versionDoc = await client.send(
      new GetPolicyVersionCommand({ PolicyArn: policyArn, VersionId: defaultVersion.VersionId })
    );
    const documentJson = versionDoc.PolicyVersion?.Document
      ? decodeURIComponent(versionDoc.PolicyVersion.Document)
      : '{}';

    const docNodeArn = `${policyArn}/version/${defaultVersion.VersionId}`;
    nodes.push({
      id: docNodeArn,
      label: 'IamPolicyDocument',
      properties: {
        id: `${policyArn}/version/${defaultVersion.VersionId}`,
        arn: docNodeArn,
        policy_arn: policyArn,
        default_version_id: defaultVersion.VersionId,
        document_json: documentJson,
        policy_type: policyArn.startsWith('arn:aws:iam::aws:') ? 'aws-managed' : 'managed',
        account_id: accountId,
      },
    });
    edges.push({ from: policyArn, to: docNodeArn, label: 'CONTAINS' });

    addStatementNodeAndEdges(nodes, edges, docNodeArn, documentJson, accountId);
    cache.set(policyArn, documentJson);
  } catch (e) {}
}

function addStatementNodeAndEdges(
  nodes: GraphNode[],
  edges: GraphEdge[],
  policyDocArn: string,
  documentJson: string,
  accountId: string
): void {
  try {
    const doc = JSON.parse(documentJson);
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
    statements.forEach((stmt: any, index: number) => {
      const stmtId = stmt.Sid || `stmt-${index}`;
      const stmtArn = `${policyDocArn}/statement/${stmtId}`;
      const actions = Array.isArray(stmt.Action) ? stmt.Action : stmt.Action ? [stmt.Action] : [];
      const resources = Array.isArray(stmt.Resource)
        ? stmt.Resource
        : stmt.Resource
          ? [stmt.Resource]
          : [];
      const conditions = stmt.Condition || undefined;
      const notActions = Array.isArray(stmt.NotAction)
        ? stmt.NotAction
        : stmt.NotAction
          ? [stmt.NotAction]
          : undefined;
      const notResources = Array.isArray(stmt.NotResource)
        ? stmt.NotResource
        : stmt.NotResource
          ? [stmt.NotResource]
          : undefined;

      nodes.push({
        id: stmtArn,
        label: 'IamPolicyStatement',
        properties: {
          id: stmtId,
          arn: stmtArn,
          effect: stmt.Effect,
          actions,
          resources,
          conditions_json: conditions ? JSON.stringify(conditions) : undefined,
          not_actions: notActions,
          not_resources: notResources,
          account_id: accountId,
        },
      });
      edges.push({ from: policyDocArn, to: stmtArn, label: 'CONTAINS' });

      for (const resource of resources) {
        if (resource !== '*') {
          edges.push({ from: stmtArn, to: resource, label: 'GRANTS' });
        }
      }
    });
  } catch (e) {}
}

function parseTrustPolicy(
  nodes: GraphNode[],
  edges: GraphEdge[],
  roleArn: string,
  trustPolicyJson: string,
  accountId: string
): void {
  try {
    const doc = JSON.parse(trustPolicyJson);
    const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
    statements.forEach((stmt: any, index: number) => {
      if (stmt.Effect !== 'Allow') return;
      const principals = stmt.Principal || {};
      const principalEntries = Object.entries(principals) as [string, string | string[]][];

      for (const [principalType, principalValues] of principalEntries) {
        const values = Array.isArray(principalValues) ? principalValues : [principalValues];
        for (const principal of values) {
          const normalizedPrincipal = principal === '*' ? '*' : principal;
          const isCrossAccount = isCrossAccountPrincipal(normalizedPrincipal, accountId);

          edges.push({
            from: normalizedPrincipal,
            to: roleArn,
            label: 'TRUSTS',
            properties: {
              trusted_principal: normalizedPrincipal,
              principal_type:
                principalType === 'AWS'
                  ? 'AWS'
                  : principalType === 'Service'
                    ? 'Service'
                    : 'Federated',
              is_cross_account: isCrossAccount,
              conditions_json: stmt.Condition ? JSON.stringify(stmt.Condition) : undefined,
              allows_assume_role: true,
            },
          });
        }
      }
    });
  } catch (e) {}
}

function isCrossAccountPrincipal(principal: string, accountId: string): boolean {
  if (principal === '*') return true;
  const match = principal.match(/^arn:aws:iam::(\d+)/);
  if (match) return match[1] !== accountId;
  return false;
}

async function collectKms(client: KMSClient, accountId: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const keys = await client.send(new ListKeysCommand({}));
  for (const key of keys.Keys || []) {
    try {
      const km = await client.send(new DescribeKeyCommand({ KeyId: key.KeyId }));
      if (km.KeyMetadata) {
        const kmd = km.KeyMetadata;
        nodes.push({
          id: kmd.Arn!,
          label: 'KmsKey',
          properties: {
            id: kmd.KeyId,
            arn: kmd.Arn,
            account_id: accountId,
            key_state: kmd.KeyState,
            key_usage: kmd.KeyUsage,
          },
        });
        edges.push({ from: `arn:aws:iam::${accountId}:root`, to: kmd.Arn!, label: 'OWNS' });
      }
    } catch (e) {}
  }

  return { nodes, edges };
}

async function collectRds(client: RDSClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const dbs = await client.send(new DescribeDBInstancesCommand({}));
  for (const db of dbs.DBInstances || []) {
    const dbArn = `arn:aws:rds:${region}:${accountId}:db:${db.DBInstanceIdentifier}`;
    nodes.push({
      id: dbArn,
      label: 'RdsInstance',
      properties: {
        id: db.DBInstanceIdentifier,
        arn: dbArn,
        account_id: accountId,
        engine: db.Engine,
        instance_class: db.DBInstanceClass,
        publicly_accessible: db.PubliclyAccessible,
        storage_encrypted: db.StorageEncrypted,
        backup_retention_period: db.BackupRetentionPeriod,
        deletion_protection: db.DeletionProtection,
      },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: dbArn, label: 'OWNS' });
  }

  return { nodes, edges };
}

async function collectEks(client: EKSClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const clusters = await client.send(new ListClustersCommand({}));
  for (const name of clusters.clusters || []) {
    try {
      const c = await client.send(new DescribeClusterCommand({ name }));
      if (c.cluster) {
        const region = c.cluster.arn?.split(':')[3] || 'us-east-1';
        const clusterArn = `arn:aws:eks:${region}:${accountId}:cluster/${c.cluster.name}`;
        nodes.push({
          id: clusterArn,
          label: 'EksCluster',
          properties: {
            id: c.cluster.name,
            arn: clusterArn,
            account_id: accountId,
            name: c.cluster.name,
            version: c.cluster.version,
          },
        });
        edges.push({ from: `arn:aws:iam::${accountId}:root`, to: clusterArn, label: 'OWNS' });
      }
    } catch (e) {}
  }

  return { nodes, edges };
}

async function collectSecurityHub(client: SecurityHubClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const findings = await client.send(
      new GetFindingsCommand({
        Filters: { RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }] },
        MaxResults: 100,
      })
    );
    for (const f of findings.Findings || []) {
      const findingArn = `arn:aws:securityhub:${f.Region || 'us-east-1'}:${accountId}:finding/${f.Id}`;
      nodes.push({
        id: findingArn,
        label: 'Finding',
        properties: {
          id: f.Id,
          arn: findingArn,
          account_id: accountId,
          title: f.Title,
          severity: f.Severity?.Label,
          status: f.RecordState,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: findingArn, label: 'HAS_FINDING' });
    }
  } catch (e) {
    console.error('SecurityHub collection error:', e);
  }

  return { nodes, edges };
}

async function collectCloudTrail(client: CloudTrailClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const trails = await client.send(new DescribeTrailsCommand({}));
    for (const trail of trails.trailList || []) {
      const trailArn =
        trail.TrailARN || `arn:aws:cloudtrail:${region}:${accountId}:trail/${trail.Name}`;
      nodes.push({
        id: trailArn,
        label: 'CloudTrail',
        properties: {
          id: trail.Name,
          arn: trailArn,
          account_id: accountId,
          name: trail.Name,
          is_multi_region_trail: trail.IsMultiRegionTrail,
          log_file_validation_enabled: trail.LogFileValidationEnabled,
          kms_key_id: trail.KmsKeyId,
          cloudwatch_logs_log_group_arn: trail.CloudWatchLogsLogGroupArn,
          s3_bucket_name: trail.S3BucketName,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: trailArn, label: 'OWNS' });

      try {
        const status = await client.send(new GetTrailStatusCommand({ Name: trailArn }));
        nodes.push({
          id: `${trailArn}/status`,
          label: 'CloudTrailStatus',
          properties: {
            id: `${trail.Name}-status`,
            arn: `${trailArn}/status`,
            account_id: accountId,
            is_logging: status.IsLogging,
            latest_delivery_time: status.LatestDeliveryTime?.toISOString(),
            latest_delivery_attempt: (status as any).LatestDeliveryAttemptTime,
          },
        });
        edges.push({ from: trailArn, to: `${trailArn}/status`, label: 'HAS_STATUS' });
      } catch (e) {}
    }
  } catch (e) {
    console.error('CloudTrail collection error:', e);
  }

  return { nodes, edges };
}

async function collectConfig(client: ConfigServiceClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const recorders = await client.send(new DescribeConfigurationRecordersCommand({}));
    for (const recorder of recorders.ConfigurationRecorders || []) {
      const recorderArn = `arn:aws:config:${region}:${accountId}:config-recorder/${recorder.name}`;
      nodes.push({
        id: recorderArn,
        label: 'ConfigRecorder',
        properties: {
          id: recorder.name,
          arn: recorderArn,
          account_id: accountId,
          name: recorder.name,
          role_arn: recorder.roleARN,
          recording_group: recorder.recordingGroup,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: recorderArn, label: 'OWNS' });
    }

    const rules = await client.send(new DescribeConfigRulesCommand({}));
    for (const rule of rules.ConfigRules || []) {
      const ruleArn =
        rule.ConfigRuleArn ||
        `arn:aws:config:${region}:${accountId}:config-rule/${rule.ConfigRuleName}`;
      nodes.push({
        id: ruleArn,
        label: 'ConfigRule',
        properties: {
          id: rule.ConfigRuleName,
          arn: ruleArn,
          account_id: accountId,
          name: rule.ConfigRuleName,
          description: rule.Description,
          source: rule.Source,
          scope: rule.Scope,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: ruleArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('Config collection error:', e);
  }

  return { nodes, edges };
}

async function collectGuardDuty(client: GuardDutyClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const detectors = await client.send(new ListDetectorsCommand({}));
    for (const detectorId of detectors.DetectorIds || []) {
      const detector = await client.send(new GetDetectorCommand({ DetectorId: detectorId }));
      const detectorArn = `arn:aws:guardduty:${region}:${accountId}:detector/${detectorId}`;
      nodes.push({
        id: detectorArn,
        label: 'GuardDutyDetector',
        properties: {
          id: detectorId,
          arn: detectorArn,
          account_id: accountId,
          status: detector.Status,
          finding_publishing_frequency: detector.FindingPublishingFrequency,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: detectorArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('GuardDuty collection error:', e);
  }

  return { nodes, edges };
}

async function collectAccessAnalyzer(
  client: AccessAnalyzerClient,
  accountId: string,
  region: string
) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const analyzers = await client.send(new ListAnalyzersCommand({ type: 'ACCOUNT' }));
    for (const analyzer of analyzers.analyzers || []) {
      const analyzerArn =
        analyzer.arn || `arn:aws:access-analyzer:${region}:${accountId}:analyzer/${analyzer.name}`;
      nodes.push({
        id: analyzerArn,
        label: 'AccessAnalyzer',
        properties: {
          id: analyzer.name,
          arn: analyzerArn,
          account_id: accountId,
          name: analyzer.name,
          status: analyzer.status,
          type: analyzer.type,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: analyzerArn, label: 'OWNS' });

      try {
        const findings = await client.send(
          new ListFindingsCommand({ analyzerArn: analyzerArn, maxResults: 50 })
        );
        for (const finding of findings.findings || []) {
          const findingArn = finding.id
            ? `arn:aws:access-analyzer:${region}:${accountId}:finding/${finding.id}`
            : `${analyzerArn}/finding/${Date.now()}`;
          nodes.push({
            id: findingArn,
            label: 'AccessAnalyzerFinding',
            properties: {
              id: finding.id,
              arn: findingArn,
              account_id: accountId,
              resource: finding.resource,
              resource_type: finding.resourceType,
              status: finding.status,
              finding_type: (finding as any).findingType || 'ExternalAccess',
            },
          });
          edges.push({ from: analyzerArn, to: findingArn, label: 'HAS_FINDING' });
        }
      } catch (e) {}
    }
  } catch (e) {
    console.error('Access Analyzer collection error:', e);
  }

  return { nodes, edges };
}

async function collectNetwork(
  ec2Client: EC2Client,
  route53Client: Route53Client,
  accountId: string,
  region: string
) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const vpcs = await ec2Client.send(new DescribeVpcsCommand({}));
    for (const vpc of vpcs.Vpcs || []) {
      const vpcArn = `arn:aws:ec2:${region}:${accountId}:vpc/${vpc.VpcId}`;
      nodes.push({
        id: vpcArn,
        label: 'Vpc',
        properties: {
          id: vpc.VpcId,
          arn: vpcArn,
          account_id: accountId,
          cidr_block: vpc.CidrBlock,
          state: vpc.State,
          is_default: vpc.IsDefault,
          flow_logs_enabled: false,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: vpcArn, label: 'OWNS' });

      try {
        const endpoints = await ec2Client.send(
          new DescribeVpcEndpointsCommand({
            Filters: [{ Name: 'vpc-id', Values: [vpc.VpcId!] }],
          })
        );
        for (const ep of endpoints.VpcEndpoints || []) {
          const epArn = `arn:aws:ec2:${region}:${accountId}:vpc-endpoint/${ep.VpcEndpointId}`;
          nodes.push({
            id: epArn,
            label: 'VpcEndpoint',
            properties: {
              id: ep.VpcEndpointId,
              arn: epArn,
              account_id: accountId,
              vpc_id: ep.VpcId,
              service_name: ep.ServiceName,
              state: ep.State,
              type: ep.VpcEndpointType,
            },
          });
          edges.push({ from: vpcArn, to: epArn, label: 'HAS_ENDPOINT' });
        }
      } catch (e) {}

      try {
        const acls = await ec2Client.send(
          new DescribeNetworkAclsCommand({
            Filters: [{ Name: 'vpc-id', Values: [vpc.VpcId!] }],
          })
        );
        for (const acl of acls.NetworkAcls || []) {
          const aclArn = `arn:aws:ec2:${region}:${accountId}:network-acl/${acl.NetworkAclId}`;
          nodes.push({
            id: aclArn,
            label: 'NetworkAcl',
            properties: {
              id: acl.NetworkAclId,
              arn: aclArn,
              account_id: accountId,
              vpc_id: acl.VpcId,
              is_default: acl.IsDefault,
              entries: acl.Entries,
            },
          });
          edges.push({ from: vpcArn, to: aclArn, label: 'HAS_NACL' });
        }
      } catch (e) {}

      try {
        const rtbs = await ec2Client.send(
          new DescribeRouteTablesCommand({
            Filters: [{ Name: 'vpc-id', Values: [vpc.VpcId!] }],
          })
        );
        for (const rtb of rtbs.RouteTables || []) {
          const rtbArn = `arn:aws:ec2:${region}:${accountId}:route-table/${rtb.RouteTableId}`;
          nodes.push({
            id: rtbArn,
            label: 'RouteTable',
            properties: {
              id: rtb.RouteTableId,
              arn: rtbArn,
              account_id: accountId,
              vpc_id: rtb.VpcId,
              routes: rtb.Routes,
              associations: rtb.Associations,
            },
          });
          edges.push({ from: vpcArn, to: rtbArn, label: 'HAS_ROUTE_TABLE' });
        }
      } catch (e) {}
    }

    const tgws = await ec2Client.send(new DescribeTransitGatewaysCommand({}));
    for (const tgw of tgws.TransitGateways || []) {
      const tgwArn = `arn:aws:ec2:${region}:${accountId}:transit-gateway/${tgw.TransitGatewayId}`;
      nodes.push({
        id: tgwArn,
        label: 'TransitGateway',
        properties: {
          id: tgw.TransitGatewayId,
          arn: tgwArn,
          account_id: accountId,
          state: tgw.State,
          description: tgw.Description,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: tgwArn, label: 'OWNS' });
    }

    const zones = await route53Client.send(new ListHostedZonesCommand({}));
    for (const zone of zones.HostedZones || []) {
      const zoneArn = `arn:aws:route53:::hostedzone/${zone.Id?.split('/').pop()}`;
      nodes.push({
        id: zoneArn,
        label: 'HostedZone',
        properties: {
          id: zone.Id,
          arn: zoneArn,
          account_id: accountId,
          name: zone.Name,
          private_zone: zone.Config?.PrivateZone,
          resource_record_set_count: zone.ResourceRecordSetCount,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: zoneArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('Network collection error:', e);
  }

  return { nodes, edges };
}

async function collectServerless(
  apiGatewayClient: APIGatewayClient,
  lambdaClient: LambdaClient,
  sfnClient: SFNClient,
  eventBridgeClient: EventBridgeClient,
  accountId: string,
  region: string
) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const apis = await apiGatewayClient.send(new GetRestApisCommand({}));
    for (const api of apis.items || []) {
      const apiArn = `arn:aws:apigateway:${region}::/restapis/${api.id}`;
      nodes.push({
        id: apiArn,
        label: 'ApiGateway',
        properties: {
          id: api.id,
          arn: apiArn,
          account_id: accountId,
          name: api.name,
          description: api.description,
          endpoint_type: api.endpointConfiguration?.types?.[0],
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: apiArn, label: 'OWNS' });

      try {
        const stages = await apiGatewayClient.send(new GetStagesCommand({ restApiId: api.id! }));
        for (const stage of stages.item || []) {
          const stageArn = `${apiArn}/stages/${stage.stageName}`;
          nodes.push({
            id: stageArn,
            label: 'ApiGatewayStage',
            properties: {
              id: stage.stageName,
              arn: stageArn,
              account_id: accountId,
              name: stage.stageName,
              deployment_id: stage.deploymentId,
              description: stage.description,
            },
          });
          edges.push({ from: apiArn, to: stageArn, label: 'HAS_STAGE' });
        }
      } catch (e) {}
    }
  } catch (e) {
    console.error('API Gateway collection error:', e);
  }

  try {
    const functions = await lambdaClient.send(new ListFunctionsCommand({}));
    for (const fn of functions.Functions || []) {
      const fnArn =
        fn.FunctionArn || `arn:aws:lambda:${region}:${accountId}:function:${fn.FunctionName}`;
      nodes.push({
        id: fnArn,
        label: 'LambdaFunction',
        properties: {
          id: fn.FunctionName,
          arn: fnArn,
          account_id: accountId,
          name: fn.FunctionName,
          runtime: fn.Runtime,
          handler: fn.Handler,
          role: fn.Role,
          code_size: fn.CodeSize,
          timeout: fn.Timeout,
          memory_size: fn.MemorySize,
          vpc_config: fn.VpcConfig,
          last_modified: fn.LastModified,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: fnArn, label: 'OWNS' });

      try {
        const aliases = await lambdaClient.send(
          new ListAliasesCommand({ FunctionName: fn.FunctionName! })
        );
        for (const alias of aliases.Aliases || []) {
          const aliasArn = `${fnArn}:${alias.Name}`;
          nodes.push({
            id: aliasArn,
            label: 'LambdaAlias',
            properties: {
              id: alias.Name,
              arn: aliasArn,
              account_id: accountId,
              name: alias.Name,
              function_version: alias.FunctionVersion,
              description: alias.Description,
            },
          });
          edges.push({ from: fnArn, to: aliasArn, label: 'HAS_ALIAS' });
        }
      } catch (e) {}
    }
  } catch (e) {
    console.error('Lambda collection error:', e);
  }

  try {
    const stateMachines = await sfnClient.send(new ListStateMachinesCommand({}));
    for (const sm of stateMachines.stateMachines || []) {
      const smArn =
        sm.stateMachineArn || `arn:aws:states:${region}:${accountId}:stateMachine:${sm.name}`;
      nodes.push({
        id: smArn,
        label: 'StateMachine',
        properties: {
          id: sm.name,
          arn: smArn,
          account_id: accountId,
          name: sm.name,
          type: sm.type,
          creation_date: sm.creationDate?.toISOString(),
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: smArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('Step Functions collection error:', e);
  }

  try {
    const buses = await eventBridgeClient.send(new ListEventBusesCommand({}));
    for (const bus of buses.EventBuses || []) {
      const busArn = bus.Arn || `arn:aws:events:${region}:${accountId}:event-bus/${bus.Name}`;
      nodes.push({
        id: busArn,
        label: 'EventBus',
        properties: {
          id: bus.Name,
          arn: busArn,
          account_id: accountId,
          name: bus.Name,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: busArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('EventBridge collection error:', e);
  }

  return { nodes, edges };
}

async function collectDataStores(
  dynamoDBClient: DynamoDBClient,
  elasticacheClient: ElastiCacheClient,
  opensearchClient: OpenSearchClient,
  redshiftClient: RedshiftClient,
  accountId: string,
  region: string
) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const tables = await dynamoDBClient.send(new ListTablesCommand({}));
    for (const tableName of tables.TableNames || []) {
      try {
        const table = await dynamoDBClient.send(new DescribeTableCommand({ TableName: tableName }));
        if (table.Table) {
          const t = table.Table;
          const tableArn = `arn:aws:dynamodb:${region}:${accountId}:table/${t.TableName}`;
          nodes.push({
            id: tableArn,
            label: 'DynamoDBTable',
            properties: {
              id: t.TableName,
              arn: tableArn,
              account_id: accountId,
              name: t.TableName,
              status: t.TableStatus,
              item_count: t.ItemCount,
              size_bytes: t.TableSizeBytes,
              billing_mode: t.BillingModeSummary?.BillingMode,
              encryption: t.SSEDescription?.Status,
              point_in_time_recovery: (t as any).PointInTimeRecoveryDescription
                ?.PointInTimeRecoveryStatus,
              ttl: (t as any).TimeToLiveDescription?.TimeToLiveStatus,
            },
          });
          edges.push({ from: `arn:aws:iam::${accountId}:root`, to: tableArn, label: 'OWNS' });
        }
      } catch (e) {}
    }
  } catch (e) {
    console.error('DynamoDB collection error:', e);
  }

  try {
    const clusters = await elasticacheClient.send(
      new DescribeCacheClustersCommand({ ShowCacheNodeInfo: true })
    );
    for (const cluster of clusters.CacheClusters || []) {
      const clusterArn = `arn:aws:elasticache:${region}:${accountId}:cluster:${cluster.CacheClusterId}`;
      nodes.push({
        id: clusterArn,
        label: 'ElastiCacheCluster',
        properties: {
          id: cluster.CacheClusterId,
          arn: clusterArn,
          account_id: accountId,
          engine: cluster.Engine,
          engine_version: cluster.EngineVersion,
          node_type: cluster.CacheNodeType,
          num_nodes: cluster.NumCacheNodes,
          status: cluster.CacheClusterStatus,
          transit_encryption: cluster.TransitEncryptionEnabled,
          at_rest_encryption: cluster.AtRestEncryptionEnabled,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: clusterArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('ElastiCache collection error:', e);
  }

  try {
    const domains = await opensearchClient.send(new ListDomainNamesCommand({}));
    for (const domain of domains.DomainNames || []) {
      try {
        const desc = await opensearchClient.send(
          new DescribeDomainCommand({ DomainName: domain.DomainName! })
        );
        if (desc.DomainStatus) {
          const d = desc.DomainStatus;
          const domainArn = d.ARN || `arn:aws:es:${region}:${accountId}:domain/${d.DomainName}`;
          nodes.push({
            id: domainArn,
            label: 'OpenSearchDomain',
            properties: {
              id: d.DomainName,
              arn: domainArn,
              account_id: accountId,
              name: d.DomainName,
              version: d.EngineVersion,
              status: d.Processing ? 'Processing' : 'Active',
              endpoint: d.Endpoint,
              vpc_options: d.VPCOptions,
              encryption_at_rest: d.EncryptionAtRestOptions?.Enabled,
              node_to_node_encryption: d.NodeToNodeEncryptionOptions?.Enabled,
              enforce_https: d.DomainEndpointOptions?.EnforceHTTPS,
            },
          });
          edges.push({ from: `arn:aws:iam::${accountId}:root`, to: domainArn, label: 'OWNS' });
        }
      } catch (e) {}
    }
  } catch (e) {
    console.error('OpenSearch collection error:', e);
  }

  try {
    const clusters = await redshiftClient.send(new DescribeClustersCommand({}));
    for (const cluster of clusters.Clusters || []) {
      const clusterArn = cluster.ClusterIdentifier
        ? `arn:aws:redshift:${region}:${accountId}:cluster:${cluster.ClusterIdentifier}`
        : '';
      nodes.push({
        id: clusterArn,
        label: 'RedshiftCluster',
        properties: {
          id: cluster.ClusterIdentifier,
          arn: clusterArn,
          account_id: accountId,
          node_type: cluster.NodeType,
          number_of_nodes: cluster.NumberOfNodes,
          status: cluster.ClusterStatus,
          encrypted: cluster.Encrypted,
          publicly_accessible: cluster.PubliclyAccessible,
          vpc_id: cluster.VpcId,
          master_username: cluster.MasterUsername,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: clusterArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('Redshift collection error:', e);
  }

  return { nodes, edges };
}

async function collectSecrets(
  secretsManagerClient: SecretsManagerClient,
  ssmClient: SSMClient,
  accountId: string,
  region: string
) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const secrets = await secretsManagerClient.send(new ListSecretsCommand({}));
    for (const secret of secrets.SecretList || []) {
      try {
        const desc = await secretsManagerClient.send(
          new DescribeSecretCommand({ SecretId: secret.ARN || secret.Name })
        );
        const secretArn =
          desc.ARN || `arn:aws:secretsmanager:${region}:${accountId}:secret:${secret.Name}`;
        nodes.push({
          id: secretArn,
          label: 'Secret',
          properties: {
            id: secret.Name,
            arn: secretArn,
            account_id: accountId,
            name: secret.Name,
            description: desc.Description,
            rotation_enabled: desc.RotationEnabled,
            rotation_rules: desc.RotationRules,
            last_rotated: desc.LastRotatedDate?.toISOString(),
            kms_key_id: desc.KmsKeyId,
            secret_type: secret.Name?.includes('rds') ? 'database' : 'other',
          },
        });
        edges.push({ from: `arn:aws:iam::${accountId}:root`, to: secretArn, label: 'OWNS' });
      } catch (e) {}
    }
  } catch (e) {
    console.error('Secrets Manager collection error:', e);
  }

  try {
    const params = await ssmClient.send(new DescribeParametersCommand({}));
    for (const param of params.Parameters || []) {
      const paramArn = `arn:aws:ssm:${region}:${accountId}:parameter${param.Name}`;
      nodes.push({
        id: paramArn,
        label: 'Parameter',
        properties: {
          id: param.Name,
          arn: paramArn,
          account_id: accountId,
          name: param.Name,
          type: param.Type,
          key_id: param.KeyId,
          last_modified: param.LastModifiedDate?.toISOString(),
          tier: param.Tier,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: paramArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('Parameter Store collection error:', e);
  }

  return { nodes, edges };
}

async function collectBackup(backupClient: BackupClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const vaults = await backupClient.send(new ListBackupVaultsCommand({}));
    for (const vault of vaults.BackupVaultList || []) {
      const vaultArn =
        vault.BackupVaultArn ||
        `arn:aws:backup:${region}:${accountId}:backup-vault:${vault.BackupVaultName}`;
      nodes.push({
        id: vaultArn,
        label: 'BackupVault',
        properties: {
          id: vault.BackupVaultName,
          arn: vaultArn,
          account_id: accountId,
          name: vault.BackupVaultName,
          creation_date: vault.CreationDate?.toISOString(),
          encryption_key_arn: vault.EncryptionKeyArn,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: vaultArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('Backup vaults collection error:', e);
  }

  try {
    const plans = await backupClient.send(new ListBackupPlansCommand({}));
    for (const plan of plans.BackupPlansList || []) {
      const planArn =
        plan.BackupPlanArn ||
        `arn:aws:backup:${region}:${accountId}:backup-plan:${plan.BackupPlanId}`;
      nodes.push({
        id: planArn,
        label: 'BackupPlan',
        properties: {
          id: plan.BackupPlanId,
          arn: planArn,
          account_id: accountId,
          name: plan.BackupPlanName,
          version_id: plan.VersionId,
          creation_date: plan.CreationDate?.toISOString(),
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: planArn, label: 'OWNS' });
    }
  } catch (e) {
    console.error('Backup plans collection error:', e);
  }

  return { nodes, edges };
}
