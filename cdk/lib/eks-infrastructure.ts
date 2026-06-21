import * as cdk from 'aws-cdk-lib';
import * as eks from 'aws-cdk-lib/aws-eks';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as logs from 'aws-cdk-lib/aws-logs';
import type { Construct } from 'constructs';

export interface SecurityGraphEksStackProps extends cdk.StackProps {
  vpcId: string;
  neptuneEndpoint: string;
  issuesTableName: string;
  evidenceTableName: string;
  reportsTableName: string;
  certificateArn: string;
  cognitoUserPoolId: string;
  cognitoClientId: string;
}

export class SecurityGraphEksStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: SecurityGraphEksStackProps) {
    super(scope, id, props);

    const clusterName = 'security-graph-cluster';

    const cluster = new eks.Cluster(this, 'SecurityGraphCluster', {
      clusterName,
      version: eks.KubernetesVersion.V1_29,
      vpc: ec2.Vpc.fromLookup(this, 'VPC', { vpcId: props.vpcId }),
      coreDnsComputeType: eks.CoreDnsComputeType.FARGATE,
      endpointAccess: eks.EndpointAccess.PUBLIC_AND_PRIVATE,
      kubectlLayer: lambda.LayerVersion.fromLayerVersionArn(
        this,
        'KubectlLayer',
        `arn:aws:lambda:${this.region}:544384666941:layer:kubectl-v29:1`
      ),
      clusterLogging: [
        eks.ClusterLoggingTypes.API,
        eks.ClusterLoggingTypes.AUDIT,
        eks.ClusterLoggingTypes.AUTHENTICATOR,
        eks.ClusterLoggingTypes.CONTROLLER_MANAGER,
        eks.ClusterLoggingTypes.SCHEDULER,
      ],
    });

    const apiServiceRole = new iam.Role(this, 'ApiServiceRole', {
      assumedBy: new iam.WebIdentityPrincipal('eks.amazonaws.com', {
        Statement: [
          {
            Effect: iam.Effect.ALLOW,
            Action: ['sts:AssumeRoleWithWebIdentity'],
            Condition: {
              StringLike: {
                'eks.amazonaws.com:sub': ['system:serviceaccount:security-graph:api-service'],
              },
            },
          },
        ],
      }),
      description: 'IRSA role for API service pods',
    });

    apiServiceRole.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          'dynamodb:GetItem',
          'dynamodb:Query',
          'dynamodb:Scan',
          'dynamodb:PutItem',
          'dynamodb:UpdateItem',
        ],
        resources: [
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.issuesTableName}`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.issuesTableName}/index/*`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.evidenceTableName}`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.evidenceTableName}/index/*`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.reportsTableName}`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.reportsTableName}/index/*`,
        ],
      })
    );

    apiServiceRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['neptune-db:Connect'],
        resources: [`arn:aws:neptune-db:${this.region}:${this.account}:*`],
      })
    );

    apiServiceRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [
          `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/eks/${clusterName}/workload/*`,
        ],
      })
    );

    const ruleRunnerRole = new iam.Role(this, 'RuleRunnerRole', {
      assumedBy: new iam.WebIdentityPrincipal('eks.amazonaws.com', {
        Statement: [
          {
            Effect: iam.Effect.ALLOW,
            Action: ['sts:AssumeRoleWithWebIdentity'],
            Condition: {
              StringLike: {
                'eks.amazonaws.com:sub': ['system:serviceaccount:security-graph:rule-runner'],
              },
            },
          },
        ],
      }),
      description: 'IRSA role for rule-runner pods',
    });

    ruleRunnerRole.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          'dynamodb:GetItem',
          'dynamodb:Query',
          'dynamodb:Scan',
          'dynamodb:PutItem',
          'dynamodb:UpdateItem',
          'dynamodb:BatchWriteItem',
        ],
        resources: [
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.issuesTableName}`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.issuesTableName}/index/*`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.evidenceTableName}`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.evidenceTableName}/index/*`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.reportsTableName}`,
          `arn:aws:dynamodb:${this.region}:${this.account}:table/${props.reportsTableName}/index/*`,
        ],
      })
    );

    ruleRunnerRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['neptune-db:Connect'],
        resources: [`arn:aws:neptune-db:${this.region}:${this.account}:*`],
      })
    );

    ruleRunnerRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
        resources: [
          `arn:aws:logs:${this.region}:${this.account}:log-group:/aws/eks/${clusterName}/workload/*`,
        ],
      })
    );

    new logs.LogGroup(this, 'SecurityGraphLogGroup', {
      logGroupName: `/aws/eks/${clusterName}/workload`,
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    cluster.addNodegroupCapacity('SecurityGraphNodeGroup', {
      nodegroupName: 'security-graph-nodes',
      instanceTypes: [new ec2.InstanceType('m6i.xlarge')],
      minSize: 2,
      maxSize: 10,
      desiredSize: 3,
      labels: {
        'workload-type': 'security-graph',
      },
    });

    new cdk.CfnOutput(this, 'ApiServiceRoleArn', {
      value: apiServiceRole.roleArn,
      description: 'ARN of the IRSA role for API service',
      exportName: 'ApiServiceRoleArn',
    });

    new cdk.CfnOutput(this, 'RuleRunnerRoleArn', {
      value: ruleRunnerRole.roleArn,
      description: 'ARN of the IRSA role for rule-runner',
      exportName: 'RuleRunnerRoleArn',
    });

    new cdk.CfnOutput(this, 'ClusterName', {
      value: clusterName,
      description: 'Name of the EKS cluster',
      exportName: 'ClusterName',
    });

    new cdk.CfnOutput(this, 'ClusterEndpoint', {
      value: cluster.clusterEndpoint,
      description: 'Endpoint of the EKS cluster',
      exportName: 'ClusterEndpoint',
    });
  }
}
