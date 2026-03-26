import { STSClient, AssumeRoleCommand } from '@aws-sdk/client-sts';
import { EC2Client, paginateDescribeInstances } from '@aws-sdk/client-ec2';
import { S3Client, ListBucketsCommand } from '@aws-sdk/client-s3';
import { IAMClient, ListUsersCommand, ListRolesCommand, ListPoliciesCommand } from '@aws-sdk/client-iam';
import { KMSClient, ListKeysCommand, DescribeKeyCommand } from '@aws-sdk/client-kms';
import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import { EKSClient, ListClustersCommand, DescribeClusterCommand } from '@aws-sdk/client-eks';
import { SecurityHubClient, GetFindingsCommand } from '@aws-sdk/client-securityhub';
import { GraphNode, GraphEdge, Logger } from '../../shared/types';

const logger = new Logger('collector');
const stsClient = new STSClient({ region: 'us-east-1' });

interface CollectorEvent {
  accountId: string;
}

export const handler = async (event: CollectorEvent): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> => {
  const { accountId } = event;
  logger.info(`Starting collection for account: ${accountId}`);

  const mockMode = process.env.MOCK_MODE === 'true';
  const masterAccountId = process.env.MASTER_ACCOUNT_ID;

  let ec2Client: EC2Client, s3Client: S3Client, iamClient: IAMClient, kmsClient: KMSClient, rdsClient: RDSClient, eksClient: EKSClient, securityHubClient: SecurityHubClient;

  if (mockMode || accountId === masterAccountId) {
    ec2Client = new EC2Client({ region: 'us-east-1' });
    s3Client = new S3Client({ region: 'us-east-1' });
    iamClient = new IAMClient({ region: 'us-east-1' });
    kmsClient = new KMSClient({ region: 'us-east-1' });
    rdsClient = new RDSClient({ region: 'us-east-1' });
    eksClient = new EKSClient({ region: 'us-east-1' });
    securityHubClient = new SecurityHubClient({ region: 'us-east-1' });
  } else {
    const roleArn = `arn:aws:iam::${accountId}:role/SecurityGraphCollectorRole`;
    const credentials = await stsClient.send(new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: `SecurityGraphIngestion-${Date.now()}`,
      DurationSeconds: 3600,
    })).then(res => res.Credentials);

    if (!credentials) throw new Error('Failed to assume role');

    ec2Client = new EC2Client({ region: 'us-east-1', credentials });
    s3Client = new S3Client({ region: 'us-east-1', credentials });
    iamClient = new IAMClient({ region: 'us-east-1', credentials });
    kmsClient = new KMSClient({ region: 'us-east-1', credentials });
    rdsClient = new RDSClient({ region: 'us-east-1', credentials });
    eksClient = new EKSClient({ region: 'us-east-1', credentials });
    securityHubClient = new SecurityHubClient({ region: 'us-east-1', credentials });
  }

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const ec2Data = await collectEc2(ec2Client, accountId);
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

  const rdsData = await collectRds(rdsClient, accountId);
  nodes.push(...rdsData.nodes);
  edges.push(...rdsData.edges);

  const eksData = await collectEks(eksClient, accountId);
  nodes.push(...eksData.nodes);
  edges.push(...eksData.edges);

  const shData = await collectSecurityHub(securityHubClient, accountId);
  nodes.push(...shData.nodes);
  edges.push(...shData.edges);

  logger.info(`Collection complete: ${nodes.length} nodes, ${edges.length} edges`);
  return { nodes, edges };
};

async function collectEc2(client: EC2Client, accountId: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const paginator = paginateDescribeInstances({ client }, {});
  for await (const page of paginator) {
    for (const reservation of page.Reservations || []) {
      for (const instance of reservation.Instances || []) {
        const region = instance.Placement?.AvailabilityZone?.slice(0, -1) || 'us-east-1';
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
      nodes.push({
        id: bucketArn,
        label: 'S3Bucket',
        properties: {
          id: bucket.Name,
          arn: bucketArn,
          account_id: accountId,
          name: bucket.Name,
          creation_date: bucket.CreationDate?.toISOString(),
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

  const users = await client.send(new ListUsersCommand({}));
  for (const user of users.Users || []) {
    const userArn = `arn:aws:iam::${accountId}:user/${user.UserName}`;
    nodes.push({
      id: userArn,
      label: 'IamUser',
      properties: { id: user.UserName, arn: userArn, account_id: accountId, path: user.Path, create_date: user.CreateDate?.toISOString() },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: userArn, label: 'OWNS' });
  }

  const roles = await client.send(new ListRolesCommand({}));
  for (const role of roles.Roles || []) {
    const roleArn = `arn:aws:iam::${accountId}:role/${role.RoleName}`;
    nodes.push({
      id: roleArn,
      label: 'IamRole',
      properties: { id: role.RoleName, arn: roleArn, account_id: accountId, path: role.Path, create_date: role.CreateDate?.toISOString() },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: roleArn, label: 'OWNS' });
  }

  const policies = await client.send(new ListPoliciesCommand({ Scope: 'Local' }));
  for (const policy of policies.Policies || []) {
    const policyArn = `arn:aws:iam::${accountId}:policy/${policy.PolicyName}`;
    nodes.push({
      id: policyArn,
      label: 'IamPolicy',
      properties: { id: policy.PolicyName, arn: policyArn, account_id: accountId, policy_name: policy.PolicyName, policy_type: policy.Type },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: policyArn, label: 'OWNS' });
  }

  return { nodes, edges };
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
          properties: { id: kmd.KeyId, arn: kmd.Arn, account_id: accountId, key_state: kmd.KeyState, key_usage: kmd.KeyUsage },
        });
        edges.push({ from: `arn:aws:iam::${accountId}:root`, to: kmd.Arn!, label: 'OWNS' });
      }
    } catch (e) {}
  }

  return { nodes, edges };
}

async function collectRds(client: RDSClient, accountId: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const dbs = await client.send(new DescribeDBInstancesCommand({}));
  for (const db of dbs.DBInstances || []) {
    const dbArn = `arn:aws:rds:${db.AvailabilityZone?.slice(0, -1) || 'us-east-1'}:${accountId}:db:${db.DBInstanceIdentifier}`;
    nodes.push({
      id: dbArn,
      label: 'RdsInstance',
      properties: { id: db.DBInstanceIdentifier, arn: dbArn, account_id: accountId, engine: db.Engine, instance_class: db.DBInstanceClass, publicly_accessible: db.PubliclyAccessible },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: dbArn, label: 'OWNS' });
  }

  return { nodes, edges };
}

async function collectEks(client: EKSClient, accountId: string) {
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
          properties: { id: c.cluster.name, arn: clusterArn, account_id: accountId, name: c.cluster.name, version: c.cluster.version },
        });
        edges.push({ from: `arn:aws:iam::${accountId}:root`, to: clusterArn, label: 'OWNS' });
      }
    } catch (e) {}
  }

  return { nodes, edges };
}

async function collectSecurityHub(client: SecurityHubClient, accountId: string) {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  try {
    const findings = await client.send(new GetFindingsCommand({ Filters: { RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }] }, MaxResults: 100 }));
    for (const f of findings.Findings || []) {
      const findingArn = `arn:aws:securityhub:${f.Region || 'us-east-1'}:${accountId}:finding/${f.Id}`;
      nodes.push({
        id: findingArn,
        label: 'Finding',
        properties: { id: f.Id, arn: findingArn, account_id: accountId, title: f.Title, severity: f.Severity?.Label, status: f.RecordState },
      });
      edges.push({ from: `arn:aws:iam::${accountId}:root`, to: findingArn, label: 'HAS_FINDING' });
    }
  } catch (e) {
    console.error('SecurityHub collection error:', e);
  }

  return { nodes, edges };
}
