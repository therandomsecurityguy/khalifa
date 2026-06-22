import { SQSClient, ReceiveMessageCommand, DeleteMessageCommand } from '@aws-sdk/client-sqs';
import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { EC2Client, DescribeSecurityGroupsCommand } from '@aws-sdk/client-ec2';
import { IAMClient, GetUserCommand } from '@aws-sdk/client-iam';
import type { GraphNode, GraphEdge } from '../shared/types';
import { Logger } from '../shared/types';
import { getSecret } from '../shared/secrets-client';

const logger = new Logger('incremental-processor');
const sqsClient = new SQSClient({ region: process.env.AWS_REGION || 'us-east-1' });
const stsClient = new STSClient({ region: process.env.AWS_REGION || 'us-east-1' });

export const handler = async (): Promise<{ processed: number }> => {
  const queueUrl = process.env.SQS_QUEUE_URL || '';
  const masterAccountId = process.env.MASTER_ACCOUNT_ID || '';

  const response = await sqsClient.send(
    new ReceiveMessageCommand({
      QueueUrl: queueUrl,
      MaxNumberOfMessages: 10,
      WaitTimeSeconds: 10,
    })
  );

  const messages = response.Messages || [];
  logger.info(`Received ${messages.length} messages from queue`);

  let processed = 0;

  for (const msg of messages) {
    try {
      const event = JSON.parse(msg.Body || '{}');
      const { nodes, edges } = await processEvent(event, masterAccountId);

      if (nodes.length > 0 || edges.length > 0) {
        await writeToNeptune({ nodes, edges });
      }

      if (msg.ReceiptHandle) {
        await sqsClient.send(
          new DeleteMessageCommand({
            QueueUrl: queueUrl,
            ReceiptHandle: msg.ReceiptHandle,
          })
        );
      }

      processed++;
    } catch (error) {
      logger.error(`Failed to process message: ${error}`);
    }
  }

  return { processed };
};

async function processEvent(
  event: any,
  masterAccountId: string
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  const detail = event.detail || event;
  const _eventName = detail.eventName || '';
  const eventSource = detail.eventSource || '';
  const requestParameters = detail.requestParameters || {};
  const userIdentity = detail.userIdentity || {};
  const accountId = userIdentity.arn?.split(':')[4] || userIdentity.accountId || '';

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  if (!accountId) {
    return { nodes, edges };
  }

  const region = detail.awsRegion || process.env.AWS_REGION || 'us-east-1';
  const isMaster = accountId === masterAccountId;

  let credentials: any;
  if (!isMaster) {
    credentials = await stsClient
      .send(
        new AssumeRoleCommand({
          RoleArn: `arn:aws:iam::${accountId}:role/SecurityGraphCollectorRole`,
          RoleSessionName: `SecurityGraphInc-${Date.now()}`,
          DurationSeconds: 900,
          ExternalId: process.env.EXTERNAL_ID || 'khalifa-collector',
        })
      )
      .then((res) => res.Credentials);
  }

  try {
    if (eventSource.includes('ec2') && requestParameters.groupId) {
      const client = new EC2Client({ region, credentials: isMaster ? undefined : credentials });
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
      const client = new IAMClient({ region, credentials: isMaster ? undefined : credentials });
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
  }

  return { nodes, edges };
}

async function writeToNeptune(data: { nodes: GraphNode[]; edges: GraphEdge[] }): Promise<void> {
  const endpoint = process.env.NEPTUNE_ENDPOINT || '';
  const secretArn = process.env.NEPTUNE_AUTH_SECRET_ARN || '';

  const secret = await getSecret(secretArn);
  const client = new (await import('gremlin')).driver.Client(`wss://${endpoint}:8182/gremlin`, {
    traversalSource: 'g',
    username: secret.username,
    password: secret.password,
  });

  try {
    for (const node of data.nodes) {
      const bindings: Record<string, any> = { lbl: node.label, arn: node.id };
      const propParts: string[] = [];
      let pi = 0;
      for (const [k, v] of Object.entries(node.properties)) {
        if (v === undefined) continue;
        bindings[`pk_${pi}`] = k;
        bindings[`pv_${pi}`] = v;
        propParts.push(`property(pk_${pi}, pv_${pi})`);
        pi++;
      }
      const propsClause = propParts.length > 0 ? '.' + propParts.join('.') : '';
      await client.submit(
        `g.V().has(lbl, 'arn', arn).fold().coalesce(unfold(), addV(lbl).property('arn', arn)${propsClause}).next()`,
        bindings
      );
    }

    for (const edge of data.edges) {
      await client.submit(
        `g.V().has('arn', ef).as('from').V().has('arn', et).as('to').coalesce(__.select('from').out(el).where(__.as('to')), __.addE(el).from('from').to('to')).next()`,
        { ef: edge.from, et: edge.to, el: edge.label }
      );
    }
  } finally {
    await client.close();
  }
}
