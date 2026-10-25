import { randomUUID } from 'crypto';
import {
  EC2Client,
  paginateDescribeInstances,
  DescribeVpcsCommand,
  DescribeVpcEndpointsCommand,
  DescribeNetworkAclsCommand,
  DescribeRouteTablesCommand,
  DescribeTransitGatewaysCommand,
  DescribeFlowLogsCommand,
} from '@aws-sdk/client-ec2';
import { ResourceGroupsTaggingAPIClient } from '@aws-sdk/client-resource-groups-tagging-api';
import { ElasticLoadBalancingV2Client } from '@aws-sdk/client-elastic-load-balancing-v2';
import { ECRClient } from '@aws-sdk/client-ecr';
import {
  S3Client,
  ListBucketsCommand,
  GetBucketVersioningCommand,
  GetBucketEncryptionCommand,
  GetBucketLoggingCommand,
  GetBucketPolicyStatusCommand,
  GetPublicAccessBlockCommand,
} from '@aws-sdk/client-s3';
import {
  IAMClient,
  ListUsersCommand,
  ListRolesCommand,
  ListPoliciesCommand,
  GetAccountPasswordPolicyCommand,
  ListGroupsCommand,
  ListGroupsForUserCommand,
  ListGroupPoliciesCommand,
  GetGroupPolicyCommand,
  ListAttachedRolePoliciesCommand,
  ListAttachedGroupPoliciesCommand,
  ListRolePoliciesCommand,
  GetRolePolicyCommand,
  ListPolicyVersionsCommand,
  GetPolicyVersionCommand,
  ListUserPoliciesCommand,
  GetUserPolicyCommand,
  ListAttachedUserPoliciesCommand,
} from '@aws-sdk/client-iam';
import {
  KMSClient,
  ListKeysCommand,
  DescribeKeyCommand,
  GetKeyRotationStatusCommand,
} from '@aws-sdk/client-kms';
import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { EKSClient, ListClustersCommand, DescribeClusterCommand } from '@aws-sdk/client-eks';
import {
  CloudTrailClient,
  DescribeTrailsCommand,
  GetEventSelectorsCommand,
  GetTrailStatusCommand,
} from '@aws-sdk/client-cloudtrail';
import {
  ConfigServiceClient,
  DescribeConfigurationRecordersCommand,
  DescribeConfigurationRecorderStatusCommand,
  DescribeConfigRulesCommand,
  DescribeDeliveryChannelsCommand,
} from '@aws-sdk/client-config-service';
import {
  AccessAnalyzerClient,
  ListAnalyzersCommand,
  ListFindingsCommand,
} from '@aws-sdk/client-accessanalyzer';
import { GuardDutyClient } from '@aws-sdk/client-guardduty';
import { Inspector2Client } from '@aws-sdk/client-inspector2';
import { SecurityHubClient } from '@aws-sdk/client-securityhub';
import { Route53Client, ListHostedZonesCommand } from '@aws-sdk/client-route-53';
import {
  APIGatewayClient,
  GetRestApisCommand,
  GetStagesCommand,
} from '@aws-sdk/client-api-gateway';
import { LambdaClient, ListFunctionsCommand, ListAliasesCommand } from '@aws-sdk/client-lambda';
import { SFNClient, ListStateMachinesCommand } from '@aws-sdk/client-sfn';
import { EventBridgeClient, ListEventBusesCommand } from '@aws-sdk/client-eventbridge';
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
  GetResourcePolicyCommand,
} from '@aws-sdk/client-secrets-manager';
import { SSMClient, DescribeParametersCommand } from '@aws-sdk/client-ssm';
import {
  BackupClient,
  ListBackupVaultsCommand,
  ListBackupPlansCommand,
} from '@aws-sdk/client-backup';
import { appendAll } from '../shared/arrays';
import type { GraphNode, GraphEdge } from '../shared/types';
import { Logger } from '../shared/types';
import { getTargetCredentials } from '../shared/aws-credentials';
import { writeGraphInBatches, type GraphWriter } from '../shared/graph-batch-writer';
import { invokeGraphWriter } from '../shared/graph-writer-client';
import { collectPaginated } from '../shared/pagination';
import { mapBounded } from '../shared/concurrency';
import {
  fetchTagsForArns,
  extractCommonProperties,
  isTaggableArn,
  staleTagProperties,
  type TagMap,
} from './src/tags';
import {
  collectSecurityGroups,
  collectInternetGateways,
  collectNatGateways,
  collectSubnets,
  buildInternetNode,
  buildNetworkAclEntries,
  INTERNET_NODE_ID,
} from './src/network';
import { collectLoadBalancers } from './src/load-balancers';
import { buildAwsManagedPolicyNode, isAwsManagedPolicyArn } from './src/iam-managed-policies';
import { summarizeEventSelectors } from './src/cloudtrail-selectors';
import { summarizePublicAccessBlock } from './src/bucket-public-access';
import { collectContainerImages } from './src/containers';
import { collectCrossAccountTrust } from './src/cross-account';
import { collectIamAccessKeys, collectIamCredentialReport } from './src/iam-posture';
import { secretAgeProperties } from './src/secret-ages';
import { instanceRoleEdges, listInstanceProfileRoles } from './src/instance-profiles';
import {
  deriveStatementPrincipalProperties,
  deriveStatementSecretProperties,
  grantTarget,
} from './src/policy-statements';
import { collectGuardDuty, collectSecurityHub } from './src/security-services';
import { collectInspectorFindings, INSPECTOR_MAX_FINDINGS } from './src/inspector';
import { collectLambdaExposure } from './src/lambda-exposure';
import { buildExposureContext, applyExposureToNodes, type ExposureContext } from './src/exposure';
import { isRoleArn, roleVertexId } from './src/iam-ids';

const logger = new Logger('collector');

function collectionFailure(scope: string, error: unknown): Error {
  const message = error instanceof Error ? error.message : String(error);
  const failure = new Error(`${scope} failed: ${message}`) as Error & { cause?: unknown };
  failure.cause = error;
  failure.name = error instanceof Error ? error.name : 'CollectionError';
  return failure;
}

function isNamedError(error: unknown, name: string): boolean {
  return error instanceof Error && error.name === name;
}

export interface CollectorEvent {
  accountId: string;
  region: string;
  collectGlobal: boolean;
}

interface CollectionData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CoverageRecord {
  service: string;
  status: 'SUCCEEDED' | 'FAILED' | 'SKIPPED';
  completedAt: string;
  nodes: number;
  edges: number;
  error?: string;
  failureType?: string;
}

// Only failures that can change between attempts justify re-scanning the
// account. Denied APIs and collector-side errors are recorded as coverage
// gaps instead.
const RETRYABLE_FAILURE_TYPES = new Set(['THROTTLED', 'TIMEOUT', 'TRANSIENT']);

export function summarizeCoverage(coverage: readonly CoverageRecord[]): {
  failedServices: string[];
  retryableServices: string[];
} {
  const failed = coverage.filter((record) => record.status === 'FAILED');
  return {
    failedServices: failed.map((record) => record.service),
    retryableServices: failed
      .filter((record) => RETRYABLE_FAILURE_TYPES.has(record.failureType || ''))
      .map((record) => record.service),
  };
}

// Precedence is explicit rather than spread-order dependent: a later stage
// wins for a key only when it supplies a defined value, so a later undefined
// or null never erases a property an earlier stage collected. Merging can only
// ever add information (a later stage with reduced permissions cannot blank
// out what a privileged stage already saw).
function preferDefined<T extends Record<string, any>>(earlier: T, later: T): T {
  const merged: Record<string, any> = { ...earlier };
  for (const [key, value] of Object.entries(later)) {
    if (value !== undefined && value !== null) merged[key] = value;
  }
  return merged as T;
}

// Some resources are emitted by more than one stage (IAM users by the IAM and
// credential stages, for example). Merge them so each vertex is upserted once
// per batch and the Tagging API never sees the same ARN twice in one request.
export function mergeDuplicateNodes(nodes: readonly GraphNode[]): GraphNode[] {
  const byId = new Map<string, GraphNode>();
  for (const node of nodes) {
    const existing = byId.get(node.id);
    byId.set(
      node.id,
      existing
        ? {
            ...preferDefined(existing, node),
            id: node.id,
            properties: preferDefined(existing.properties, node.properties),
          }
        : node
    );
  }
  return [...byId.values()];
}

function rootError(error: unknown): unknown {
  let current = error;
  const visited = new Set<unknown>();
  while (current && typeof current === 'object' && 'cause' in current && !visited.has(current)) {
    visited.add(current);
    current = (current as { cause?: unknown }).cause;
  }
  return current;
}

function classifyFailure(error: unknown): string {
  const root = rootError(error);
  const name = root instanceof Error ? root.name : '';
  const message = root instanceof Error ? root.message : String(root);
  const status =
    root && typeof root === 'object' && '$metadata' in root
      ? (root as { $metadata?: { httpStatusCode?: number } }).$metadata?.httpStatusCode
      : undefined;
  if (status === 401 || status === 403 || /AccessDenied|Unauthorized|Forbidden/.test(name)) {
    return 'ACCESS_DENIED';
  }
  if (status === 429 || /Throttl|TooManyRequests/.test(name)) return 'THROTTLED';
  if (/Timeout|TimedOut|Abort/.test(name) || /timed? out/i.test(message)) return 'TIMEOUT';
  if (
    (status && status >= 500) ||
    /ECONN|Networking|ServiceUnavailable/.test(`${name} ${message}`)
  ) {
    return 'TRANSIENT';
  }
  return 'ERROR';
}

function readPositiveInteger(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  maximum: number
): number {
  const value = environment[name];
  if (value === undefined || !value.trim()) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return parsed;
}

function groupBy<T, K>(items: T[], key: (item: T) => K | undefined): Map<K, T[]> {
  const grouped = new Map<K, T[]>();
  for (const item of items) {
    const group = key(item);
    if (group === undefined || group === null) continue;
    const existing = grouped.get(group);
    if (existing) existing.push(item);
    else grouped.set(group, [item]);
  }
  return grouped;
}

function coverageNode(accountId: string, region: string, record: CoverageRecord): GraphNode {
  const id = `arn:aws:khalifa:${region}:${accountId}:collection-coverage/${record.service}`;
  return {
    id,
    label: 'CollectionCoverage',
    observedAt: record.completedAt,
    properties: {
      id: record.service,
      arn: id,
      account_id: accountId,
      region,
      service: record.service,
      status: record.status,
      complete: record.status !== 'FAILED',
      completed_at: record.completedAt,
      last_attempt_at: record.completedAt,
      last_success_at: record.status === 'SUCCEEDED' ? record.completedAt : undefined,
      failure_type: record.failureType || '',
      error: record.error || '',
      node_count: record.nodes,
      edge_count: record.edges,
    },
  };
}

// The five slowest stages, slowest first, so a log line stays short.
export function slowestStages(durations: Record<string, number>): Record<string, number> {
  return Object.fromEntries(
    Object.entries(durations)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
  );
}

export async function collectServiceStage(
  service: string,
  enabled: boolean,
  operation: () => Promise<CollectionData>
): Promise<{ data: CollectionData; coverage: CoverageRecord }> {
  if (!enabled) {
    return {
      data: { nodes: [], edges: [] },
      coverage: {
        service,
        status: 'SKIPPED',
        completedAt: new Date().toISOString(),
        nodes: 0,
        edges: 0,
      },
    };
  }
  try {
    const data = await operation();
    return {
      data,
      coverage: {
        service,
        status: 'SUCCEEDED',
        completedAt: new Date().toISOString(),
        nodes: data.nodes.length,
        edges: data.edges.length,
      },
    };
  } catch (error) {
    return {
      data: { nodes: [], edges: [] },
      coverage: {
        service,
        status: 'FAILED',
        completedAt: new Date().toISOString(),
        nodes: 0,
        edges: 0,
        error: error instanceof Error ? error.message : String(error),
        failureType: classifyFailure(error),
      },
    };
  }
}

interface ClientCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration?: Date;
}

function createClients(region: string, credentials?: ClientCredentials) {
  const baseConfig = { region, maxAttempts: 3, retryMode: 'standard' as const };
  const credConfig = credentials ? { credentials } : {};

  return {
    ec2Client: new EC2Client({ ...baseConfig, ...credConfig }),
    s3Client: new S3Client({ ...baseConfig, ...credConfig, followRegionRedirects: true }),
    iamClient: new IAMClient({ ...baseConfig, ...credConfig }),
    kmsClient: new KMSClient({ ...baseConfig, ...credConfig }),
    rdsClient: new RDSClient({ ...baseConfig, ...credConfig }),
    eksClient: new EKSClient({ ...baseConfig, ...credConfig }),
    cloudTrailClient: new CloudTrailClient({ ...baseConfig, ...credConfig }),
    configClient: new ConfigServiceClient({ ...baseConfig, ...credConfig }),
    accessAnalyzerClient: new AccessAnalyzerClient({ ...baseConfig, ...credConfig }),
    guardDutyClient: new GuardDutyClient({ ...baseConfig, ...credConfig }),
    inspector2Client: new Inspector2Client({ ...baseConfig, ...credConfig }),
    securityHubClient: new SecurityHubClient({ ...baseConfig, ...credConfig }),
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

export const collect = async (
  event: CollectorEvent,
  writeGraph: GraphWriter = invokeGraphWriter
): Promise<{
  accountId: string;
  region: string;
  status: 'SUCCEEDED' | 'INCOMPLETE';
  failedServices: string[];
  retryableServices: string[];
  nodes: number;
  edges: number;
  skippedEdges: number;
  tombstoned: number;
  batches: number;
}> => {
  const { accountId, region, collectGlobal } = event;
  if (!region?.trim() || typeof collectGlobal !== 'boolean') {
    throw new Error('Collector requires region and collectGlobal');
  }
  const runId = randomUUID();
  const collectionScope = `resource-inventory:${region}`;
  const startedAt = Date.now();
  logger.info('Starting collection', { accountId, region });

  let credentials: Awaited<ReturnType<typeof getTargetCredentials>>;
  try {
    credentials = await getTargetCredentials({ accountId, region });
  } catch (error) {
    const completedAt = new Date().toISOString();
    const failure: CoverageRecord = {
      service: 'credentials',
      status: 'FAILED',
      completedAt,
      nodes: 0,
      edges: 0,
      error: error instanceof Error ? error.message : String(error),
      failureType: classifyFailure(error),
    };
    const writeResult = await writeGraphInBatches(
      { nodes: [coverageNode(accountId, region, failure)], edges: [] },
      completedAt,
      { write: writeGraph }
    );
    logger.error('Account collection unavailable', {
      accountId,
      region,
      failureType: failure.failureType,
      error: failure.error,
    });
    return {
      accountId,
      region,
      status: 'INCOMPLETE',
      ...summarizeCoverage([failure]),
      nodes: 0,
      edges: 0,
      skippedEdges: writeResult.skipped,
      tombstoned: 0,
      batches: writeResult.batches,
    };
  }
  const clients = createClients(region, credentials);

  const {
    ec2Client,
    s3Client,
    iamClient,
    kmsClient,
    rdsClient,
    eksClient,
    cloudTrailClient,
    configClient,
    accessAnalyzerClient,
    guardDutyClient,
    inspector2Client,
    securityHubClient,
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
  const coverage: CoverageRecord[] = [];

  const stageConcurrency = readPositiveInteger(process.env, 'COLLECTION_STAGE_CONCURRENCY', 4, 20);
  const resourceConcurrency = readPositiveInteger(
    process.env,
    'COLLECTION_RESOURCE_CONCURRENCY',
    5,
    20
  );

  interface StageDefinition {
    service: string;
    enabled: boolean;
    run: () => Promise<CollectionData>;
  }

  const runStage = async (definition: StageDefinition) => {
    const result = await collectServiceStage(
      definition.service,
      definition.enabled,
      definition.run
    );
    if (result.coverage.status === 'FAILED') {
      logger.error('Service collection incomplete', {
        accountId,
        region,
        service: definition.service,
        failureType: result.coverage.failureType,
        error: result.coverage.error,
      });
    }
    return result;
  };

  // Milliseconds per stage, logged with the result: the organization run stops
  // at its deadline, and these show which accounts and stages use the time.
  const stageDurations: Record<string, number> = {};
  const collectStage = async (
    service: string,
    enabled: boolean,
    operation: () => Promise<CollectionData>
  ): Promise<void> => {
    const stageStart = Date.now();
    const result = await runStage({ service, enabled, run: operation });
    if (enabled) stageDurations[service] = Date.now() - stageStart;
    appendAll(nodes, result.data.nodes);
    appendAll(edges, result.data.edges);
    coverage.push(result.coverage);
  };

  nodes.push(buildInternetNode(accountId));

  // The stages are independent of each other (separate services, separate
  // clients), so they run with bounded concurrency instead of strictly
  // sequentially: the old pass paid the SUM of every service's latency, which
  // exceeds the collector timeout on large accounts. Results are appended in
  // stage order, so coverage and node ordering stay deterministic.
  const independentStages: StageDefinition[] = [
    {
      service: 'ec2-instances',
      enabled: true,
      run: () => collectEc2(ec2Client, iamClient, accountId, region),
    },
    {
      service: 's3',
      enabled: collectGlobal,
      run: () => collectS3(s3Client, accountId, resourceConcurrency),
    },
    { service: 'iam', enabled: collectGlobal, run: () => collectIam(iamClient, accountId) },
    {
      service: 'iam-access-keys',
      enabled: collectGlobal,
      run: () => collectIamAccessKeys(iamClient, accountId),
    },
    {
      service: 'iam-credential-report',
      enabled: collectGlobal,
      run: () => collectIamCredentialReport(iamClient, accountId),
    },
    { service: 'kms', enabled: true, run: () => collectKms(kmsClient, accountId) },
    { service: 'rds', enabled: true, run: () => collectRds(rdsClient, accountId, region) },
    { service: 'eks', enabled: true, run: () => collectEks(eksClient, accountId, region) },
    {
      service: 'cloudtrail',
      enabled: true,
      run: () => collectCloudTrail(cloudTrailClient, accountId, region),
    },
    {
      service: 'config',
      enabled: true,
      run: () => collectConfig(configClient, accountId, region),
    },
    {
      service: 'access-analyzer',
      enabled: true,
      run: () => collectAccessAnalyzer(accessAnalyzerClient, accountId, region),
    },
    {
      service: 'guardduty',
      enabled: true,
      run: () => collectGuardDuty(guardDutyClient, accountId, region),
    },
    {
      service: 'network',
      enabled: true,
      run: () => collectNetwork(ec2Client, route53Client, accountId, region, collectGlobal),
    },
    {
      service: 'serverless',
      enabled: true,
      run: () =>
        collectServerless(
          apiGatewayClient,
          lambdaClient,
          sfnClient,
          eventBridgeClient,
          accountId,
          region
        ),
    },
    {
      service: 'datastores',
      enabled: true,
      run: () =>
        collectDataStores(
          dynamoDBClient,
          elasticacheClient,
          opensearchClient,
          redshiftClient,
          accountId,
          region
        ),
    },
    {
      service: 'secrets',
      enabled: true,
      run: () => collectSecrets(secretsManagerClient, ssmClient, accountId, region),
    },
    {
      service: 'backup',
      enabled: true,
      run: () => collectBackup(backupClient, accountId, region),
    },
    { service: 'subnets', enabled: true, run: () => collectSubnets(ec2Client, accountId, region) },
    {
      service: 'security-groups',
      enabled: true,
      run: () => collectSecurityGroups(ec2Client, accountId, region, new Map()),
    },
    {
      service: 'internet-gateways',
      enabled: true,
      run: () => collectInternetGateways(ec2Client, accountId, region, new Map()),
    },
    {
      service: 'nat-gateways',
      enabled: true,
      run: () => collectNatGateways(ec2Client, accountId, region, new Map()),
    },
    {
      service: 'load-balancers',
      enabled: true,
      run: () => collectLoadBalancers(elbV2Client, accountId, region, new Map()),
    },
    {
      service: 'ecr',
      enabled: true,
      run: () => collectContainerImages(ecrClient, accountId, region, new Map()),
    },
    {
      service: 'cross-account-trust',
      enabled: collectGlobal,
      run: () => collectCrossAccountTrust(iamClient, accountId, new Map()),
    },
  ];

  const stageResults = await mapBounded(independentStages, stageConcurrency, runStage);
  for (const result of stageResults) {
    appendAll(nodes, result.data.nodes);
    appendAll(edges, result.data.edges);
    coverage.push(result.coverage);
  }

  // Security Hub findings link to resource vertices by ARN, so it runs after
  // the resource stages above have contributed their nodes.
  await collectStage('securityhub', true, () =>
    collectSecurityHub(
      securityHubClient,
      accountId,
      region,
      new Set(nodes.map((node) => node.id)),
      {
        excludeGuardDuty: Boolean(process.env.GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID?.trim()),
      }
    )
  );

  // Inspector findings attach HAS_CVE to resource vertices by ARN, so like
  // Security Hub they run after the resource stages have contributed their
  // nodes. Inspector not being enabled is recorded as SKIPPED, not an empty
  // success: nothing was read, and the CVE data does not exist.
  const inspectorStart = Date.now();
  try {
    const result = await collectInspectorFindings(
      inspector2Client,
      accountId,
      region,
      new Set(nodes.map((node) => node.id))
    );
    appendAll(nodes, result.nodes);
    appendAll(edges, result.edges);
    coverage.push({
      service: 'inspector',
      status: result.notEnabled ? 'SKIPPED' : 'SUCCEEDED',
      completedAt: new Date().toISOString(),
      nodes: result.nodes.length,
      edges: result.edges.length,
      error: result.notEnabled
        ? 'Amazon Inspector is not enabled in this account/region'
        : result.truncated
          ? `Findings truncated at ${INSPECTOR_MAX_FINDINGS}`
          : undefined,
    });
  } catch (error) {
    const failure: CoverageRecord = {
      service: 'inspector',
      status: 'FAILED',
      completedAt: new Date().toISOString(),
      nodes: 0,
      edges: 0,
      error: error instanceof Error ? error.message : String(error),
      failureType: classifyFailure(error),
    };
    coverage.push(failure);
    logger.error('Inspector collection incomplete', {
      accountId,
      region,
      failureType: failure.failureType,
      error: failure.error,
    });
  }
  stageDurations.inspector = Date.now() - inspectorStart;

  const uniqueNodes = mergeDuplicateNodes(nodes);
  const exposureCtx: ExposureContext = buildExposureContext(uniqueNodes);
  const stageSucceeded = (service: string) =>
    coverage.some((c) => c.service === service && c.status === 'SUCCEEDED');
  const exposedNodes = applyExposureToNodes(
    uniqueNodes,
    exposureCtx,
    stageSucceeded('subnets') && stageSucceeded('internet-gateways')
  );

  const tagArns = exposedNodes.map((n) => n.id).filter(isTaggableArn);
  let tagsByArn = new Map<string, TagMap>();
  let tagsCollected = false;
  const tagsStart = Date.now();
  try {
    tagsByArn = await fetchTagsForArns(taggingClient, tagArns);
    tagsCollected = true;
    coverage.push({
      service: 'tags',
      status: 'SUCCEEDED',
      completedAt: new Date().toISOString(),
      nodes: tagsByArn.size,
      edges: 0,
    });
  } catch (error) {
    const failure = {
      service: 'tags',
      status: 'FAILED' as const,
      completedAt: new Date().toISOString(),
      nodes: 0,
      edges: 0,
      error: error instanceof Error ? error.message : String(error),
      failureType: classifyFailure(error),
    };
    coverage.push(failure);
    logger.error('Tag collection incomplete', {
      accountId,
      region,
      failureType: failure.failureType,
      error: failure.error,
    });
  }
  stageDurations.tags = Date.now() - tagsStart;

  const completedAt = new Date().toISOString();
  const { failedServices, retryableServices } = summarizeCoverage(coverage);
  coverage.push({
    service: 'resource-inventory',
    status: failedServices.length === 0 ? 'SUCCEEDED' : 'FAILED',
    completedAt,
    nodes: exposedNodes.length,
    edges: edges.length,
    error: failedServices.length > 0 ? `Incomplete: ${failedServices.join(', ')}` : undefined,
    failureType: failedServices.length > 0 ? 'PARTIAL' : undefined,
  });

  // One pass merges tags and collection scope. The previous shape copied the
  // whole node graph twice (finalNodes, then scopedNodes); the tag branch was
  // also duplicated for INTERNET_EXPOSED_LABELS with identical bodies.
  const scopedNodes: GraphNode[] = [];
  for (const node of exposedNodes) {
    // Shared vertices every account writes under one global id are left
    // unscoped, so no single account's reconcile can tombstone them. Scoped, an
    // AWS-managed policy would be stamped with whichever account wrote it last;
    // if that account then detached the policy, its reconcile would drop the
    // vertex and every other account's ATTACHED_TO edge with it until their
    // next run. The per-account edges stay scoped and reconcile normally.
    // ExternalAccount is shared the same way, and scoping would also overwrite
    // its account_id (the trusted account) with the collecting account.
    if (
      node.id === INTERNET_NODE_ID ||
      isAwsManagedPolicyArn(node.id) ||
      node.label === 'ExternalAccount'
    ) {
      scopedNodes.push(node);
      continue;
    }
    const tagProps = extractCommonProperties(tagsByArn.get(node.id));
    const properties: Record<string, unknown> = {
      ...node.properties,
      ...tagProps,
      account_id: accountId,
      collection_region: region,
      collection_scope: collectionScope,
      collection_run_id: runId,
      active: true,
    };
    // A duplicate of the node from another stage may still set a key one stage
    // cleared; the set value wins.
    const clearProperties = [
      ...(node.clearProperties ?? []),
      ...staleTagProperties(node.id, tagProps, node.properties, tagsCollected),
    ].filter((key) => properties[key] === undefined || properties[key] === null);
    scopedNodes.push({
      ...node,
      ...(clearProperties.length > 0 ? { clearProperties } : {}),
      properties,
    });
  }
  for (const record of coverage) {
    const node = coverageNode(accountId, region, record);
    scopedNodes.push({
      ...node,
      properties: {
        ...node.properties,
        account_id: accountId,
        collection_region: region,
        collection_scope: collectionScope,
        collection_run_id: runId,
        active: true,
      },
    });
  }

  const scopedEdges = edges.map((edge) => ({
    ...edge,
    properties: {
      ...edge.properties,
      account_id: accountId,
      collection_region: region,
      collection_scope: collectionScope,
      collection_run_id: runId,
      active: true,
    },
  }));
  const writeStart = Date.now();
  const writeResult = await writeGraphInBatches(
    {
      nodes: scopedNodes,
      edges: scopedEdges,
      reconcile:
        failedServices.length === 0
          ? {
              scope: collectionScope,
              runId,
              observedAt: completedAt,
              accountId,
              region,
            }
          : undefined,
    },
    completedAt,
    { write: writeGraph }
  );

  const writeMs = Date.now() - writeStart;
  logger.info(failedServices.length === 0 ? 'Collection complete' : 'Collection incomplete', {
    accountId,
    region,
    durationMs: Date.now() - startedAt,
    writeMs,
    slowestStages: slowestStages(stageDurations),
    failedServices,
    retryableServices,
    nodes: scopedNodes.length,
    edges: scopedEdges.length,
    skippedEdges: writeResult.skipped,
    tombstoned: writeResult.tombstoned,
    batches: writeResult.batches,
  });
  return {
    accountId,
    region,
    status: failedServices.length === 0 ? 'SUCCEEDED' : 'INCOMPLETE',
    failedServices,
    retryableServices,
    nodes: scopedNodes.length,
    edges: scopedEdges.length,
    skippedEdges: writeResult.skipped,
    tombstoned: writeResult.tombstoned,
    batches: writeResult.batches,
  };
};

export const handler = (event: CollectorEvent) => collect(event);

export { collectGuardDutyFindings } from './src/guardduty-sweep';

async function collectEc2(
  client: EC2Client,
  iamClient: IAMClient,
  accountId: string,
  region: string
) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const instanceProfiles: { instanceArn: string; profileArn: string }[] = [];

  const paginator = paginateDescribeInstances({ client }, {});
  for await (const page of paginator) {
    for (const reservation of page.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        const instanceArn = `arn:aws:ec2:${region}:${accountId}:instance/${instance.InstanceId}`;

        nodes.push({
          id: instanceArn,
          label: 'Ec2Instance',
          // A released public IP must not keep the instance looking reachable.
          ...(instance.PublicIpAddress ? {} : { clearProperties: ['public_ip'] }),
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
            metadata_http_tokens: instance.MetadataOptions?.HttpTokens,
            metadata_http_endpoint: instance.MetadataOptions?.HttpEndpoint,
            metadata_http_limit_hop: instance.MetadataOptions?.HttpPutResponseHopLimit,
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

        if (instance.IamInstanceProfile?.Arn) {
          instanceProfiles.push({ instanceArn, profileArn: instance.IamInstanceProfile.Arn });
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
              from: `arn:aws:ec2:${region}:${accountId}:security-group/${sg.GroupId}`,
              to: niArn,
              label: 'PROTECTS',
            });
          }
        }
      }
    }
  }

  if (instanceProfiles.length > 0) {
    const profileRoles = await listInstanceProfileRoles(iamClient);
    if (!profileRoles) {
      logger.warn('iam:ListInstanceProfiles denied; EC2 instances not linked to their roles', {
        accountId,
        region,
      });
    } else {
      for (const { instanceArn, profileArn } of instanceProfiles) {
        appendAll(edges, instanceRoleEdges(instanceArn, profileArn, profileRoles, accountId));
      }
    }
  }

  return { nodes, edges };
}

async function collectS3(client: S3Client, accountId: string, resourceConcurrency = 5) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const buckets = await collectPaginated(
      (token) =>
        client.send(new ListBucketsCommand({ ContinuationToken: token, MaxBuckets: 1000 })),
      (page) => page.Buckets,
      (page) => page.ContinuationToken
    );

    // Bucket configuration is independent per bucket (five API calls each);
    // fanning out with bounded concurrency replaces 5 sequential round trips
    // per bucket, in order, with far fewer wall-clock calls.
    const bucketNodes = await mapBounded(buckets, resourceConcurrency, async (bucket) => {
      if (!bucket.Name) return null;
      const bucketArn = `arn:aws:s3:::${bucket.Name}`;
      let configuration: Record<string, unknown>;
      try {
        configuration = await describeBucket(client, bucket.Name);
      } catch (error) {
        // A bucket policy can deny the collector even though IAM allows the
        // call. Keep the bucket without its configuration rather than losing
        // every bucket in the account.
        if (classifyFailure(error) !== 'ACCESS_DENIED') throw error;
        configuration = { configuration_access_denied: true };
      }

      return {
        id: bucketArn,
        label: 'S3Bucket',
        properties: {
          id: bucket.Name,
          arn: bucketArn,
          account_id: accountId,
          name: bucket.Name,
          creation_date: bucket.CreationDate?.toISOString(),
          data_classification: '',
          ...configuration,
        },
      } satisfies GraphNode;
    });

    for (const node of bucketNodes) {
      if (!node) continue;
      nodes.push(node);
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: node.id, label: 'OWNS' });
    }
  } catch (e) {
    throw collectionFailure('S3 collection', e);
  }

  return { nodes, edges };
}

async function describeBucket(client: S3Client, name: string): Promise<Record<string, unknown>> {
  // The five configuration reads are independent; run them together instead of
  // five sequential round trips per bucket.
  const [versioning, encryption, logging, policyStatus, publicAccess] = await Promise.all([
    client.send(new GetBucketVersioningCommand({ Bucket: name })),
    client.send(new GetBucketEncryptionCommand({ Bucket: name })).catch((error) => {
      if (isNamedError(error, 'ServerSideEncryptionConfigurationNotFoundError')) {
        return { ServerSideEncryptionConfiguration: undefined };
      }
      throw error;
    }),
    client.send(new GetBucketLoggingCommand({ Bucket: name })),
    client.send(new GetBucketPolicyStatusCommand({ Bucket: name })).catch((error) => {
      if (isNamedError(error, 'NoSuchBucketPolicy')) return { PolicyStatus: undefined };
      throw error;
    }),
    client.send(new GetPublicAccessBlockCommand({ Bucket: name })).catch((error) => {
      if (isNamedError(error, 'NoSuchPublicAccessBlockConfiguration')) {
        return { PublicAccessBlockConfiguration: undefined };
      }
      throw error;
    }),
  ]);

  return {
    versioning_enabled: versioning.Status === 'Enabled',
    // Already in the GetBucketVersioning response; previously discarded. CIS
    // 2.1.2 (S3.20) is exactly this field.
    mfa_delete_enabled: versioning.MFADelete === 'Enabled',
    default_encryption: !!encryption.ServerSideEncryptionConfiguration,
    logging_enabled: !!logging.LoggingEnabled,
    is_publicly_accessible: policyStatus.PolicyStatus?.IsPublic === true,
    ...summarizePublicAccessBlock(publicAccess.PublicAccessBlockConfiguration),
  };
}

async function collectIam(client: IAMClient, accountId: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const policyDocumentCache = new Map<string, string>();

  const users = await collectPaginated(
    (marker) => client.send(new ListUsersCommand({ Marker: marker })),
    (page) => page.Users,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );
  for (const user of users) {
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
      const inlinePolicies = await collectPaginated(
        (marker) =>
          client.send(new ListUserPoliciesCommand({ UserName: user.UserName!, Marker: marker })),
        (page) => page.PolicyNames,
        (page) => (page.IsTruncated ? page.Marker : undefined)
      );
      for (const policyName of inlinePolicies) {
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
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }

    try {
      const attached = await collectPaginated(
        (marker) =>
          client.send(
            new ListAttachedUserPoliciesCommand({ UserName: user.UserName!, Marker: marker })
          ),
        (page) => page.AttachedPolicies,
        (page) => (page.IsTruncated ? page.Marker : undefined)
      );
      for (const policy of attached) {
        if (isAwsManagedPolicyArn(policy.PolicyArn)) {
          nodes.push(buildAwsManagedPolicyNode(policy.PolicyArn, policy.PolicyName, accountId));
        }
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
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }

    try {
      const groups = await collectPaginated(
        (marker) =>
          client.send(new ListGroupsForUserCommand({ UserName: user.UserName!, Marker: marker })),
        (page) => page.Groups,
        (page) => (page.IsTruncated ? page.Marker : undefined)
      );
      for (const group of groups) {
        const groupArn = `arn:aws:iam::${accountId}:group/${group.GroupName}`;
        edges.push({ from: userArn, to: groupArn, label: 'MEMBER_OF' });
      }
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }
  }

  const roles = await collectPaginated(
    (marker) => client.send(new ListRolesCommand({ Marker: marker })),
    (page) => page.Roles,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );
  for (const role of roles) {
    const roleArn = roleVertexId(accountId, role.RoleName!);
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
      const inlinePolicies = await collectPaginated(
        (marker) =>
          client.send(new ListRolePoliciesCommand({ RoleName: role.RoleName!, Marker: marker })),
        (page) => page.PolicyNames,
        (page) => (page.IsTruncated ? page.Marker : undefined)
      );
      for (const policyName of inlinePolicies) {
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
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }

    try {
      const attached = await collectPaginated(
        (marker) =>
          client.send(
            new ListAttachedRolePoliciesCommand({ RoleName: role.RoleName!, Marker: marker })
          ),
        (page) => page.AttachedPolicies,
        (page) => (page.IsTruncated ? page.Marker : undefined)
      );
      for (const policy of attached) {
        if (isAwsManagedPolicyArn(policy.PolicyArn)) {
          nodes.push(buildAwsManagedPolicyNode(policy.PolicyArn, policy.PolicyName, accountId));
        }
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
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }

    if (role.PermissionsBoundary?.PermissionsBoundaryArn) {
      edges.push({
        from: roleArn,
        to: role.PermissionsBoundary.PermissionsBoundaryArn,
        label: 'HAS_PERMISSION_BOUNDARY',
      });
    }
  }

  const groups = await collectPaginated(
    (marker) => client.send(new ListGroupsCommand({ Marker: marker })),
    (page) => page.Groups,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );
  for (const group of groups) {
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
      const inlinePolicies = await collectPaginated(
        (marker) =>
          client.send(
            new ListGroupPoliciesCommand({ GroupName: group.GroupName!, Marker: marker })
          ),
        (page) => page.PolicyNames,
        (page) => (page.IsTruncated ? page.Marker : undefined)
      );
      for (const policyName of inlinePolicies) {
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
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }

    try {
      const attached = await collectPaginated(
        (marker) =>
          client.send(
            new ListAttachedGroupPoliciesCommand({ GroupName: group.GroupName!, Marker: marker })
          ),
        (page) => page.AttachedPolicies,
        (page) => (page.IsTruncated ? page.Marker : undefined)
      );
      for (const policy of attached) {
        if (isAwsManagedPolicyArn(policy.PolicyArn)) {
          nodes.push(buildAwsManagedPolicyNode(policy.PolicyArn, policy.PolicyName, accountId));
        }
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
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }
  }

  const policies = await collectPaginated(
    (marker) => client.send(new ListPoliciesCommand({ Scope: 'Local', Marker: marker })),
    (page) => page.Policies,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );
  for (const policy of policies) {
    const policyArn = policy.Arn;
    if (!policyArn) continue;
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

  const awsManagedPolicies = await collectPaginated(
    (marker) =>
      client.send(new ListPoliciesCommand({ Scope: 'AWS', OnlyAttached: true, Marker: marker })),
    (page) => page.Policies,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );
  for (const policy of awsManagedPolicies) {
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
  } catch (e) {
    if (!isNamedError(e, 'NoSuchEntityException')) {
      throw collectionFailure('IAM password policy collection', e);
    }
  }

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
    const versions = await collectPaginated(
      (marker) =>
        client.send(new ListPolicyVersionsCommand({ PolicyArn: policyArn, Marker: marker })),
      (page) => page.Versions,
      (page) => (page.IsTruncated ? page.Marker : undefined)
    );
    const defaultVersion = versions.find((version) => version.IsDefaultVersion);
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
  } catch (e) {
    throw collectionFailure('AWS resource collection', e);
  }
}

export function addStatementNodeAndEdges(
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

      const hasWildcardResource = resources.includes('*');
      const hasWildcardAction = actions.some((a: any) => a === '*' || a === '*:*');
      const secretProperties = deriveStatementSecretProperties(stmt, accountId);
      const principalProperties = deriveStatementPrincipalProperties(stmt, accountId);

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
          has_wildcard_resource: hasWildcardResource,
          has_wildcard_action: hasWildcardAction,
          ...secretProperties,
          ...principalProperties,
          account_id: accountId,
        },
      });
      edges.push({ from: policyDocArn, to: stmtArn, label: 'CONTAINS' });

      // Only collected accounts have an AwsAccount vertex, so the edge to any
      // other account is skipped; rules count the gap as an outside share.
      if (stmt.Effect === 'Allow') {
        for (const sharedAccount of principalProperties.principal_account_ids ?? []) {
          edges.push({
            from: stmtArn,
            to: `arn:aws:iam::${sharedAccount}:root`,
            label: 'SHARES_WITH',
          });
        }
      }

      const targets: string[] = resources
        .filter((r: unknown): r is string => typeof r === 'string' && r !== '*')
        .map(grantTarget);
      for (const target of new Set(targets)) {
        edges.push({ from: stmtArn, to: target, label: 'GRANTS' });
      }
    });
  } catch (e) {
    throw collectionFailure('AWS resource collection', e);
  }
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
    statements.forEach((stmt: any, _index: number) => {
      if (stmt.Effect !== 'Allow') return;
      const principals = stmt.Principal || {};
      const principalEntries = Object.entries(principals) as [string, string | string[]][];

      for (const [principalType, principalValues] of principalEntries) {
        const values = Array.isArray(principalValues) ? principalValues : [principalValues];
        for (const principal of values) {
          const normalizedPrincipal = principal === '*' ? '*' : principal;
          const isCrossAccount = isCrossAccountPrincipal(normalizedPrincipal, accountId);

          edges.push({
            // A role principal may carry a path (SSO roles are under
            // /aws-reserved/...); the role vertex never does.
            from: isRoleArn(normalizedPrincipal)
              ? roleVertexId(accountId, normalizedPrincipal)
              : normalizedPrincipal,
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
  } catch (e) {
    throw collectionFailure('AWS resource collection', e);
  }
}

function isCrossAccountPrincipal(principal: string, accountId: string): boolean {
  if (principal === '*') return true;
  const match = principal.match(/^arn:aws(?:-us-gov|-cn)?:iam::(\d+)/);
  if (match) return match[1] !== accountId;
  return false;
}

export async function collectKms(client: KMSClient, accountId: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const keys = await collectPaginated(
    (marker) => client.send(new ListKeysCommand({ Marker: marker })),
    (page) => page.Keys,
    (page) => (page.Truncated ? page.NextMarker : undefined)
  );
  // Key policies, not IAM, govern KMS reads, and a key policy that names only
  // specific roles denies ours. A key we can't describe is written as a stub with
  // `collection_restricted` so CIS 3.6 leaves its account/region unassessed rather than
  // passing it; a denied rotation status is left unknown. Neither fails the stage.
  for (const key of keys) {
    try {
      let km;
      try {
        km = await client.send(new DescribeKeyCommand({ KeyId: key.KeyId }));
      } catch (e) {
        if (!isNamedError(e, 'AccessDeniedException')) throw e;
        if (key.KeyArn) {
          nodes.push({
            id: key.KeyArn,
            label: 'KmsKey',
            properties: {
              id: key.KeyId,
              arn: key.KeyArn,
              account_id: accountId,
              collection_restricted: true,
            },
          });
        }
        continue;
      }
      if (km.KeyMetadata) {
        const kmd = km.KeyMetadata;
        let rotationEnabled: boolean | undefined;
        if (kmd.KeyId) {
          try {
            const rotation = await client.send(
              new GetKeyRotationStatusCommand({ KeyId: kmd.KeyId })
            );
            rotationEnabled = rotation.KeyRotationEnabled;
          } catch (e) {
            if (
              !isNamedError(e, 'AccessDeniedException') &&
              !isNamedError(e, 'KMSInvalidStateException') &&
              !isNamedError(e, 'NotFoundException')
            ) {
              throw e;
            }
          }
        }
        nodes.push({
          id: kmd.Arn!,
          label: 'KmsKey',
          properties: {
            id: kmd.KeyId,
            arn: kmd.Arn,
            account_id: accountId,
            key_state: kmd.KeyState,
            key_usage: kmd.KeyUsage,
            key_manager: kmd.KeyManager,
            // KMS.4 (CIS 3.6) applies only to keys that can rotate: not
            // asymmetric or HMAC keys, imported key material, or custom key
            // stores. All three come back on the DescribeKey already made.
            key_spec: kmd.KeySpec,
            origin: kmd.Origin,
            custom_key_store_id: kmd.CustomKeyStoreId,
            rotation_enabled: rotationEnabled,
            collection_restricted: false,
          },
        });
        edges.push({ from: `arn:aws:iam::${accountId}:root`, to: kmd.Arn!, label: 'OWNS' });
      }
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }
  }

  return { nodes, edges };
}

async function collectRds(client: RDSClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const dbs = await collectPaginated(
    (marker) => client.send(new DescribeDBInstancesCommand({ Marker: marker })),
    (page) => page.DBInstances,
    (page) => page.Marker
  );
  for (const db of dbs) {
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
        is_publicly_accessible: db.PubliclyAccessible,
        storage_encrypted: db.StorageEncrypted,
        backup_retention_period: db.BackupRetentionPeriod,
        deletion_protection: db.DeletionProtection,
        // Already in the DescribeDBInstances response; previously discarded.
        // CIS 2.3.2 (RDS.13).
        auto_minor_version_upgrade: db.AutoMinorVersionUpgrade,
      },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: dbArn, label: 'OWNS' });
  }

  return { nodes, edges };
}

async function collectEks(client: EKSClient, accountId: string, _region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const clusters = await collectPaginated(
    (token) => client.send(new ListClustersCommand({ nextToken: token })),
    (page) => page.clusters,
    (page) => page.nextToken
  );
  for (const name of clusters) {
    try {
      const c = await client.send(new DescribeClusterCommand({ name }));
      if (c.cluster) {
        const region = c.cluster.arn?.split(':')[3] || 'us-east-1';
        const clusterArn = `arn:aws:eks:${region}:${accountId}:cluster/${c.cluster.name}`;
        const vpcConfig = c.cluster.resourcesVpcConfig;
        const publicCidrs = vpcConfig?.publicAccessCidrs || [];
        const worldOpen =
          vpcConfig?.endpointPublicAccess === true &&
          (publicCidrs.length === 0 || publicCidrs.includes('0.0.0.0/0'));
        nodes.push({
          id: clusterArn,
          label: 'EksCluster',
          properties: {
            id: c.cluster.name,
            arn: clusterArn,
            account_id: accountId,
            name: c.cluster.name,
            version: c.cluster.version,
            endpoint_public_access: vpcConfig?.endpointPublicAccess === true,
            endpoint_private_access: vpcConfig?.endpointPrivateAccess === true,
            public_access_cidrs: publicCidrs,
            endpoint_world_open: worldOpen,
            vpc_id: vpcConfig?.vpcId,
          },
        });
        edges.push({ from: `arn:aws:iam::${accountId}:root`, to: clusterArn, label: 'OWNS' });
      }
    } catch (e) {
      throw collectionFailure('AWS resource collection', e);
    }
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
          is_organization_trail: trail.IsOrganizationTrail,
          log_file_validation_enabled: trail.LogFileValidationEnabled,
          kms_key_id: trail.KmsKeyId,
          cloudwatch_logs_log_group_arn: trail.CloudWatchLogsLogGroupArn,
          s3_bucket_name: trail.S3BucketName,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: trailArn, label: 'OWNS' });

      try {
        const selectors = await client.send(
          // The ARN, not the name. A name resolves in the caller's own account,
          // so for the shadow of an organization trail it throws
          // TrailNotFoundException -- which is caught below, leaving every
          // selector property unset. From a member account the org trail was
          // the only trail, so none of these properties had ever been written.
          // GetTrailStatus below already passes the ARN for the same reason.
          new GetEventSelectorsCommand({ TrailName: trailArn })
        );
        const summary = summarizeEventSelectors(
          selectors.EventSelectors,
          selectors.AdvancedEventSelectors
        );
        const trailNode = nodes[nodes.length - 1];
        trailNode.properties.include_management_events = summary.includeManagementEvents;
        trailNode.properties.logs_all_management_events = summary.logsAllManagementEvents;
        trailNode.properties.has_data_events = summary.hasDataEvents;
        trailNode.properties.logs_all_s3_object_writes = summary.logsAllS3ObjectWrites;
        trailNode.properties.logs_all_s3_object_reads = summary.logsAllS3ObjectReads;
      } catch (e) {
        if (
          !isNamedError(e, 'TrailNotFoundException') &&
          !isNamedError(e, 'UnsupportedOperationException')
        ) {
          throw collectionFailure('CloudTrail event selector collection', e);
        }
      }

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
      } catch (e) {
        throw collectionFailure('AWS resource collection', e);
      }
    }
  } catch (e) {
    throw collectionFailure('CloudTrail collection', e);
  }

  return { nodes, edges };
}

async function collectConfig(client: ConfigServiceClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const recorders = await client.send(new DescribeConfigurationRecordersCommand({}));
    const recorderStatuses = await client.send(new DescribeConfigurationRecorderStatusCommand({}));
    const statusByName = new Map(
      (recorderStatuses.ConfigurationRecordersStatus || []).map((status) => [status.name, status])
    );
    for (const recorder of recorders.ConfigurationRecorders || []) {
      const recorderArn = `arn:aws:config:${region}:${accountId}:config-recorder/${recorder.name}`;
      const status = statusByName.get(recorder.name);
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
          // recording_group is an object, so normalizeProperties stringifies it and
          // Gremlin cannot filter inside. The two flags KH-3.10 needs, as scalars.
          recording_all_supported: recorder.recordingGroup?.allSupported,
          include_global_resource_types: recorder.recordingGroup?.includeGlobalResourceTypes,
          recording: status?.recording === true,
          last_status: status?.lastStatus,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: recorderArn, label: 'OWNS' });
    }

    const channels = await client.send(new DescribeDeliveryChannelsCommand({}));
    for (const channel of channels.DeliveryChannels || []) {
      const channelArn = `arn:aws:config:${region}:${accountId}:delivery-channel/${channel.name}`;
      nodes.push({
        id: channelArn,
        label: 'ConfigDeliveryChannel',
        properties: {
          id: channel.name,
          arn: channelArn,
          account_id: accountId,
          name: channel.name,
          s3_bucket_name: channel.s3BucketName,
          sns_topic_arn: channel.snsTopicARN,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: channelArn, label: 'OWNS' });
    }

    const rules = await collectPaginated(
      (token) => client.send(new DescribeConfigRulesCommand({ NextToken: token })),
      (page) => page.ConfigRules,
      (page) => page.NextToken
    );
    for (const rule of rules) {
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
    throw collectionFailure('Config collection', e);
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
    const analyzers = await collectPaginated(
      (token) => client.send(new ListAnalyzersCommand({ type: 'ACCOUNT', nextToken: token })),
      (page) => page.analyzers,
      (page) => page.nextToken
    );
    // An account with no analyzer is exactly what CIS 1.20 forbids, but with no
    // vertex there is nothing for RULE-025 to report or 1.20 to count -- absence
    // read as compliance. GuardDuty already emits a synthetic MISSING detector
    // for the same reason (src/security-services.ts); this mirrors it.
    if (analyzers.length === 0) {
      const missingArn = `arn:aws:access-analyzer:${region}:${accountId}:analyzer/missing`;
      nodes.push({
        id: missingArn,
        label: 'AccessAnalyzer',
        properties: {
          id: 'missing',
          arn: missingArn,
          account_id: accountId,
          region,
          status: 'MISSING',
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: missingArn, label: 'OWNS' });
    }

    for (const analyzer of analyzers) {
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
        const findings = await collectPaginated(
          (token) =>
            client.send(
              new ListFindingsCommand({
                analyzerArn: analyzerArn,
                maxResults: 50,
                nextToken: token,
              })
            ),
          (page) => page.findings,
          (page) => page.nextToken
        );
        for (const finding of findings) {
          if (!finding.id) {
            logger.warn('Access Analyzer returned a finding without an ID', { accountId, region });
            continue;
          }
          const findingArn = `arn:aws:access-analyzer:${region}:${accountId}:finding/${finding.id}`;
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
      } catch (e) {
        throw collectionFailure('AWS resource collection', e);
      }
    }
  } catch (e) {
    throw collectionFailure('Access Analyzer collection', e);
  }

  return { nodes, edges };
}

async function collectNetwork(
  ec2Client: EC2Client,
  route53Client: Route53Client,
  accountId: string,
  region: string,
  collectGlobal: boolean
) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    // One region-wide listing per child type, grouped by VPC in memory. The
    // previous shape issued four paginated calls per VPC (flow logs with a
    // per-VPC filter), which dominated accounts with many VPCs.
    const [vpcs, flowLogs, endpoints, acls, routeTables] = await Promise.all([
      collectPaginated(
        (token) => ec2Client.send(new DescribeVpcsCommand({ NextToken: token })),
        (page) => page.Vpcs,
        (page) => page.NextToken
      ),
      collectPaginated(
        (token) => ec2Client.send(new DescribeFlowLogsCommand({ NextToken: token })),
        (page) => page.FlowLogs,
        (page) => page.NextToken
      ),
      collectPaginated(
        (token) => ec2Client.send(new DescribeVpcEndpointsCommand({ NextToken: token })),
        (page) => page.VpcEndpoints,
        (page) => page.NextToken
      ),
      collectPaginated(
        (token) => ec2Client.send(new DescribeNetworkAclsCommand({ NextToken: token })),
        (page) => page.NetworkAcls,
        (page) => page.NextToken
      ),
      collectPaginated(
        (token) => ec2Client.send(new DescribeRouteTablesCommand({ NextToken: token })),
        (page) => page.RouteTables,
        (page) => page.NextToken
      ),
    ]);

    // EC2.6 (CIS 3.7) checks for an active flow log capturing REJECT traffic;
    // an ACCEPT-only or failed flow log still counted in flowLogVpcIds.
    const rejectFlowLogVpcIds = new Set(
      flowLogs
        .filter(
          (flowLog) =>
            flowLog.FlowLogStatus === 'ACTIVE' &&
            (flowLog.TrafficType === 'REJECT' || flowLog.TrafficType === 'ALL')
        )
        .map((flowLog) => flowLog.ResourceId)
        .filter((id): id is string => !!id)
    );
    const flowLogVpcIds = new Set(
      flowLogs.map((flowLog) => flowLog.ResourceId).filter((id): id is string => !!id)
    );
    const endpointsByVpc = groupBy(endpoints, (endpoint) => endpoint.VpcId);
    const aclsByVpc = groupBy(acls, (acl) => acl.VpcId);
    const routeTablesByVpc = groupBy(routeTables, (routeTable) => routeTable.VpcId);

    for (const vpc of vpcs) {
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
          flow_logs_enabled: flowLogVpcIds.has(vpc.VpcId!),
          flow_logs_capture_rejects: rejectFlowLogVpcIds.has(vpc.VpcId!),
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: vpcArn, label: 'OWNS' });

      for (const endpoint of endpointsByVpc.get(vpc.VpcId!) ?? []) {
        const epArn = `arn:aws:ec2:${region}:${accountId}:vpc-endpoint/${endpoint.VpcEndpointId}`;
        nodes.push({
          id: epArn,
          label: 'VpcEndpoint',
          properties: {
            id: endpoint.VpcEndpointId,
            arn: epArn,
            account_id: accountId,
            vpc_id: endpoint.VpcId,
            service_name: endpoint.ServiceName,
            state: endpoint.State,
            type: endpoint.VpcEndpointType,
          },
        });
        edges.push({ from: vpcArn, to: epArn, label: 'HAS_ENDPOINT' });
      }

      for (const acl of aclsByVpc.get(vpc.VpcId!) ?? []) {
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

        const aclEntries = buildNetworkAclEntries(acl, aclArn, accountId, region);
        nodes.push(...aclEntries.nodes);
        edges.push(...aclEntries.edges);
      }

      for (const routeTable of routeTablesByVpc.get(vpc.VpcId!) ?? []) {
        const rtbArn = `arn:aws:ec2:${region}:${accountId}:route-table/${routeTable.RouteTableId}`;
        nodes.push({
          id: rtbArn,
          label: 'RouteTable',
          properties: {
            id: routeTable.RouteTableId,
            arn: rtbArn,
            account_id: accountId,
            vpc_id: routeTable.VpcId,
            routes: routeTable.Routes,
            associations: routeTable.Associations,
          },
        });
        edges.push({ from: vpcArn, to: rtbArn, label: 'HAS_ROUTE_TABLE' });
      }
    }

    const transitGateways = await collectPaginated(
      (token) => ec2Client.send(new DescribeTransitGatewaysCommand({ NextToken: token })),
      (page) => page.TransitGateways,
      (page) => page.NextToken
    );
    for (const tgw of transitGateways) {
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

    if (collectGlobal) {
      const zones = await collectPaginated(
        (marker) => route53Client.send(new ListHostedZonesCommand({ Marker: marker })),
        (page) => page.HostedZones,
        (page) => (page.IsTruncated ? page.NextMarker : undefined)
      );
      for (const zone of zones) {
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
    }
  } catch (e) {
    throw collectionFailure('Network collection', e);
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
    const apis = await collectPaginated(
      (position) => apiGatewayClient.send(new GetRestApisCommand({ position })),
      (page) => page.items,
      (page) => page.position
    );
    for (const api of apis) {
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
      } catch (e) {
        throw collectionFailure('AWS resource collection', e);
      }
    }
  } catch (e) {
    throw collectionFailure('API Gateway collection', e);
  }

  try {
    const functions = await collectPaginated(
      (marker) => lambdaClient.send(new ListFunctionsCommand({ Marker: marker })),
      (page) => page.Functions,
      (page) => page.NextMarker
    );
    for (const fn of functions) {
      const fnArn =
        fn.FunctionArn || `arn:aws:lambda:${region}:${accountId}:function:${fn.FunctionName}`;
      const exposure = await collectLambdaExposure(lambdaClient, fn.FunctionName!);
      if (exposure.lambda_exposure_restricted) {
        logger.warn('Lambda URL or policy read denied; exposure unknown', {
          accountId,
          region,
          functionName: fn.FunctionName,
        });
      }
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
          is_in_vpc: !!(fn.VpcConfig?.SubnetIds && fn.VpcConfig.SubnetIds.length > 0),
          has_internet_access: !(fn.VpcConfig?.SubnetIds && fn.VpcConfig.SubnetIds.length > 0),
          last_modified: fn.LastModified,
          ...exposure,
        },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: fnArn, label: 'OWNS' });

      if (fn.Role) {
        edges.push({ from: fnArn, to: roleVertexId(accountId, fn.Role), label: 'HAS_IAM_ROLE' });
      }

      try {
        const aliases = await collectPaginated(
          (marker) =>
            lambdaClient.send(
              new ListAliasesCommand({ FunctionName: fn.FunctionName!, Marker: marker })
            ),
          (page) => page.Aliases,
          (page) => page.NextMarker
        );
        for (const alias of aliases) {
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
      } catch (e) {
        throw collectionFailure('AWS resource collection', e);
      }
    }
  } catch (e) {
    throw collectionFailure('Lambda collection', e);
  }

  try {
    const stateMachines = await collectPaginated(
      (token) => sfnClient.send(new ListStateMachinesCommand({ nextToken: token })),
      (page) => page.stateMachines,
      (page) => page.nextToken
    );
    for (const sm of stateMachines) {
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
    throw collectionFailure('Step Functions collection', e);
  }

  try {
    const buses = await collectPaginated(
      (token) => eventBridgeClient.send(new ListEventBusesCommand({ NextToken: token })),
      (page) => page.EventBuses,
      (page) => page.NextToken
    );
    for (const bus of buses) {
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
    throw collectionFailure('EventBridge collection', e);
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
    const tables = await collectPaginated(
      (tableName) =>
        dynamoDBClient.send(new ListTablesCommand({ ExclusiveStartTableName: tableName })),
      (page) => page.TableNames,
      (page) => page.LastEvaluatedTableName
    );
    for (const tableName of tables) {
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
      } catch (e) {
        throw collectionFailure('AWS resource collection', e);
      }
    }
  } catch (e) {
    throw collectionFailure('DynamoDB collection', e);
  }

  try {
    const clusters = await collectPaginated(
      (marker) =>
        elasticacheClient.send(
          new DescribeCacheClustersCommand({ ShowCacheNodeInfo: true, Marker: marker })
        ),
      (page) => page.CacheClusters,
      (page) => page.Marker
    );
    for (const cluster of clusters) {
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
    throw collectionFailure('ElastiCache collection', e);
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
      } catch (e) {
        throw collectionFailure('AWS resource collection', e);
      }
    }
  } catch (e) {
    throw collectionFailure('OpenSearch collection', e);
  }

  try {
    const clusters = await collectPaginated(
      (marker) => redshiftClient.send(new DescribeClustersCommand({ Marker: marker })),
      (page) => page.Clusters,
      (page) => page.Marker
    );
    for (const cluster of clusters) {
      if (!cluster.ClusterIdentifier) continue;
      const clusterArn = `arn:aws:redshift:${region}:${accountId}:cluster:${cluster.ClusterIdentifier}`;
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
    throw collectionFailure('Redshift collection', e);
  }

  return { nodes, edges };
}

export async function collectSecrets(
  secretsManagerClient: SecretsManagerClient,
  ssmClient: SSMClient,
  accountId: string,
  region: string,
  now: Date = new Date()
) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const secrets = await collectPaginated(
      (token) => secretsManagerClient.send(new ListSecretsCommand({ NextToken: token })),
      (page) => page.SecretList,
      (page) => page.NextToken
    );
    for (const secret of secrets) {
      try {
        // A secret's resource policy can deny the collector. That secret is
        // recorded from its ListSecrets entry instead of failing the stage,
        // which would also stop cleanup for the whole account.
        let desc: typeof secret = secret;
        let restricted = false;
        try {
          desc = await secretsManagerClient.send(
            new DescribeSecretCommand({ SecretId: secret.ARN || secret.Name })
          );
        } catch (e) {
          if (!isNamedError(e, 'AccessDeniedException')) throw e;
          restricted = true;
        }
        const secretArn =
          desc.ARN || `arn:aws:secretsmanager:${region}:${accountId}:secret:${secret.Name}`;

        let policy: { ResourcePolicy?: string } = {};
        if (!restricted) {
          try {
            policy = await secretsManagerClient.send(
              new GetResourcePolicyCommand({ SecretId: desc.ARN || secret.Name })
            );
          } catch (e) {
            if (!isNamedError(e, 'AccessDeniedException')) throw e;
            restricted = true;
          }
        }
        if (restricted) {
          logger.warn('Secret access denied by its resource policy; recorded as restricted', {
            accountId,
            region,
            secretArn,
          });
        }

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
            ...secretAgeProperties(desc, now),
            kms_key_id: desc.KmsKeyId,
            secret_type: secret.Name?.includes('rds') ? 'database' : 'other',
            collection_restricted: restricted,
          },
        });
        edges.push({ from: `arn:aws:iam::${accountId}:root`, to: secretArn, label: 'OWNS' });

        if (policy.ResourcePolicy) {
          const documentJson = decodeURIComponent(policy.ResourcePolicy);
          const policyArn = `${secretArn}/resource-policy`;
          nodes.push({
            id: policyArn,
            label: 'IamPolicyDocument',
            properties: {
              id: 'resource-policy',
              arn: policyArn,
              policy_arn: policyArn,
              default_version_id: 'current',
              document_json: documentJson,
              policy_type: 'resource',
              account_id: accountId,
            },
          });
          edges.push({ from: secretArn, to: policyArn, label: 'HAS_RESOURCE_POLICY' });
          addStatementNodeAndEdges(nodes, edges, policyArn, documentJson, accountId);
        }
      } catch (e) {
        throw collectionFailure('AWS resource collection', e);
      }
    }
  } catch (e) {
    throw collectionFailure('Secrets Manager collection', e);
  }

  try {
    const parameters = await collectPaginated(
      (token) => ssmClient.send(new DescribeParametersCommand({ NextToken: token })),
      (page) => page.Parameters,
      (page) => page.NextToken
    );
    for (const param of parameters) {
      // A name without a leading slash still has one in its ARN: parameter/name.
      const name = param.Name ?? '';
      const paramArn =
        param.ARN ||
        `arn:aws:ssm:${region}:${accountId}:parameter${name.startsWith('/') ? '' : '/'}${name}`;
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
    throw collectionFailure('Parameter Store collection', e);
  }

  return { nodes, edges };
}

async function collectBackup(backupClient: BackupClient, accountId: string, region: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const vaults = await collectPaginated(
      (token) => backupClient.send(new ListBackupVaultsCommand({ NextToken: token })),
      (page) => page.BackupVaultList,
      (page) => page.NextToken
    );
    for (const vault of vaults) {
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
    throw collectionFailure('Backup vaults collection', e);
  }

  try {
    const plans = await collectPaginated(
      (token) => backupClient.send(new ListBackupPlansCommand({ NextToken: token })),
      (page) => page.BackupPlansList,
      (page) => page.NextToken
    );
    for (const plan of plans) {
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
    throw collectionFailure('Backup plans collection', e);
  }

  return { nodes, edges };
}
