import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';
import { EC2Client, DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import { IAMClient, GetUserCommand } from '@aws-sdk/client-iam';
import { OrganizationsClient } from '@aws-sdk/client-organizations';
import {
  discoverAccounts,
  parseCollectionConfig,
  type OrganizationsReader,
} from '../shared/account-inventory';
import type { GraphWriter } from '../shared/graph-batch-writer';
import type { GraphNode, GraphEdge } from '../shared/types';
import { Logger } from '../shared/types';
import { invokeGraphWriter } from '../shared/graph-writer-client';
import { getTargetCredentials } from '../shared/aws-credentials';

const logger = new Logger('incremental-processor');
interface CollectionScope {
  accountIds: ReadonlySet<string>;
  regions: ReadonlySet<string>;
}

const EVENT_SOURCES = new Set(['aws.ec2', 'aws.eks', 'aws.iam', 'aws.kms', 'aws.rds', 'aws.s3']);

export function requireApprovedEventTarget(
  event: unknown,
  scope: CollectionScope
): { accountId: string; region: string; detail: Record<string, any> } {
  if (!event || typeof event !== 'object') throw new Error('Invalid EventBridge event');
  const envelope = event as Record<string, any>;
  const accountId = envelope.account;
  const region = envelope.region;
  const source = envelope.source;
  const detail = envelope.detail;

  if (
    envelope['detail-type'] !== 'AWS API Call via CloudTrail' ||
    !EVENT_SOURCES.has(source) ||
    !detail ||
    typeof detail !== 'object'
  ) {
    throw new Error('Invalid EventBridge event');
  }
  if (typeof accountId !== 'string' || !scope.accountIds.has(accountId)) {
    throw new Error('Event account is outside the approved collection scope');
  }
  if (typeof region !== 'string' || !scope.regions.has(region)) {
    throw new Error('Event Region is outside the approved collection scope');
  }
  if (detail.eventSource !== `${source.slice(4)}.amazonaws.com`) {
    throw new Error('Event source does not match its CloudTrail detail');
  }
  if (detail.recipientAccountId && detail.recipientAccountId !== accountId) {
    throw new Error('Event account does not match its CloudTrail detail');
  }
  if (detail.awsRegion && detail.awsRegion !== region) {
    throw new Error('Event Region does not match its CloudTrail detail');
  }

  return { accountId, region, detail };
}

interface IncrementalDependencies {
  sqsClient?: SQSClient;
  organizationsClient?: OrganizationsReader;
  writeGraph?: GraphWriter;
  environment?: NodeJS.ProcessEnv;
  abortSignal?: AbortSignal;
}

export async function processBatch(
  dependencies: IncrementalDependencies = {}
): Promise<{ processed: number; failed: number }> {
  const environment = dependencies.environment || process.env;
  const queueUrl = environment.SQS_QUEUE_URL || '';
  if (!queueUrl.trim()) throw new Error('SQS_QUEUE_URL is required');
  const sqsClient =
    dependencies.sqsClient || new SQSClient({ region: environment.AWS_REGION || 'us-east-1' });
  const organizationsClient =
    dependencies.organizationsClient || new OrganizationsClient({ maxAttempts: 3 });
  const writeGraph = dependencies.writeGraph || invokeGraphWriter;

  const response = await sqsClient.send(
    new ReceiveMessageCommand({
      QueueUrl: queueUrl,
      MaxNumberOfMessages: 10,
      WaitTimeSeconds: 10,
    }),
    dependencies.abortSignal ? { abortSignal: dependencies.abortSignal } : undefined
  );

  const messages = response.Messages || [];
  logger.info(`Received ${messages.length} messages from queue`);
  if (messages.length === 0) return { processed: 0, failed: 0 };

  const config = parseCollectionConfig(environment);
  const accounts = await discoverAccounts(organizationsClient, config);
  const scope: CollectionScope = {
    accountIds: new Set(
      accounts.filter((account) => account.state === 'ACTIVE').map((account) => account.accountId)
    ),
    regions: new Set(config.regions),
  };

  let processed = 0;
  let failed = 0;

  for (const msg of messages) {
    try {
      if (!msg.ReceiptHandle) throw new Error('SQS message is missing ReceiptHandle');
      const event = JSON.parse(msg.Body || '{}');
      const { nodes, edges } = await processEvent(event, scope, environment);

      if (nodes.length > 0 || edges.length > 0) {
        await writeGraph({
          nodes,
          edges,
          observedAt: event.detail?.eventTime || event.time || new Date().toISOString(),
        });
      }

      await sqsClient.send(
        new DeleteMessageCommand({
          QueueUrl: queueUrl,
          ReceiptHandle: msg.ReceiptHandle,
        })
      );

      processed++;
    } catch (error) {
      failed++;
      logger.error(`Failed to process message: ${error}`);
    }
  }

  return { processed, failed };
}

export const handler = () => processBatch();

async function processEvent(
  event: any,
  scope: CollectionScope,
  environment: NodeJS.ProcessEnv = process.env
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  const { accountId, region, detail } = requireApprovedEventTarget(event, scope);
  const eventSource = detail.eventSource || '';
  const requestParameters = detail.requestParameters || {};

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const credentials = await getTargetCredentials({
    accountId,
    region,
    homeAccountId: environment.HOME_ACCOUNT_ID,
    externalId: environment.COLLECTOR_EXTERNAL_ID,
    roleName: environment.COLLECTOR_ROLE_NAME || 'SecurityGraphCollectorRole',
  });

  try {
    if (eventSource.includes('ec2') && requestParameters.groupId) {
      const client = new EC2Client({ region, credentials });
      const sg = await client.send(
        new DescribeSecurityGroupsCommand({ GroupIds: [requestParameters.groupId] })
      );
      if (sg.SecurityGroups?.[0]) {
        const s = sg.SecurityGroups[0];
        nodes.push({
          id: `arn:aws:ec2:${region}:${accountId}:security-group/${s.GroupId}`,
          label: 'SecurityGroup',
          properties: {
            id: s.GroupId,
            arn: `arn:aws:ec2:${region}:${accountId}:security-group/${s.GroupId}`,
            account_id: accountId,
            name: s.GroupName,
            vpc_id: s.VpcId,
          },
        });
      }
    } else if (eventSource.includes('s3') && requestParameters.bucketName) {
      const bucketName = requestParameters.bucketName;
      nodes.push({
        id: `arn:aws:s3:::${bucketName}`,
        label: 'S3Bucket',
        properties: {
          id: bucketName,
          arn: `arn:aws:s3:::${bucketName}`,
          account_id: accountId,
          name: bucketName,
        },
      });
    } else if (eventSource.includes('iam') && requestParameters.userName) {
      const client = new IAMClient({ region, credentials });
      const user = await client.send(new GetUserCommand({ UserName: requestParameters.userName }));
      if (user.User) {
        nodes.push({
          id: `arn:aws:iam::${accountId}:user/${requestParameters.userName}`,
          label: 'IamUser',
          properties: {
            id: requestParameters.userName,
            arn: `arn:aws:iam::${accountId}:user/${requestParameters.userName}`,
            account_id: accountId,
          },
        });
      }
    }
  } catch (error) {
    logger.error(`Error processing event: ${error}`);
    throw error;
  }

  return { nodes, edges };
}
