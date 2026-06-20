import * as cdk from 'aws-cdk-lib';
import * as stepfunctions from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import type { Construct } from 'constructs';

export interface SecurityGraphIngestionStackProps extends cdk.StackProps {
  neptuneEndpoint: string;
  masterAccountId: string;
  accountIds: string[];
}

export class SecurityGraphIngestionStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: SecurityGraphIngestionStackProps) {
    super(scope, id, props);

    const { neptuneEndpoint, masterAccountId, accountIds } = props;

    const neptuneSecret = new secretsmanager.Secret(this, 'NeptuneAuthSecret', {
      secretName: 'khalifa-neptune-auth',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          username: 'neptune_user',
          password: 'generate_random_password',
        }),
        generateStringKey: 'password',
      },
    });

    const deadLetterQueue = new sqs.Queue(this, 'DeadLetterQueue', {
      queueName: 'security-graph-dlq.fifo',
      fifo: true,
    });

    const incrementalQueue = new sqs.Queue(this, 'IncrementalQueue', {
      queueName: 'security-graph-incremental-queue.fifo',
      fifo: true,
      deadLetterQueue: {
        queue: deadLetterQueue,
        maxReceiveCount: 3,
      },
      retentionPeriod: cdk.Duration.days(4),
      visibilityTimeout: cdk.Duration.minutes(5),
    });

    const lambdaExecutionRole = new iam.Role(this, 'LambdaExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('servicerole/AWSLambdaBasicExecutionRole'),
      ],
    });
    lambdaExecutionRole.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['secretsmanager:GetSecretValue'],
        resources: [neptuneSecret.secretArn],
      })
    );

    const collectorAssumeRole = new iam.Role(this, 'CollectorAssumeRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    collectorAssumeRole.addToPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['sts:AssumeRole'],
        resources: [`arn:aws:iam::*:role/SecurityGraphCollectorRole`],
      })
    );

    const listAccountsFn = new lambda.Function(this, 'ListAccountsFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/list-accounts'),
      role: lambdaExecutionRole,
      timeout: cdk.Duration.minutes(1),
      memorySize: 256,
      environment: {
        MOCK_MODE: process.env.MOCK_MODE || 'false',
      },
    });
    listAccountsFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['organizations:ListAccounts', 'organizations:ListOrganizationalUnitsForParent'],
        resources: ['*'],
      })
    );

    const collectorFn = new lambda.Function(this, 'CollectorFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/collector'),
      role: collectorAssumeRole,
      timeout: cdk.Duration.minutes(10),
      memorySize: 1024,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
        MASTER_ACCOUNT_ID: masterAccountId,
        MOCK_MODE: process.env.MOCK_MODE || 'false',
        NEPTUNE_AUTH_SECRET_ARN: neptuneSecret.secretArn,
      },
    });

    const graphWriterFn = new lambda.Function(this, 'GraphWriterFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/graph-writer'),
      role: lambdaExecutionRole,
      timeout: cdk.Duration.minutes(5),
      memorySize: 1024,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
        NEPTUNE_AUTH_SECRET_ARN: neptuneSecret.secretArn,
      },
    });

    const incrementalProcessorFn = new lambda.Function(this, 'IncrementalProcessorFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/incremental-collector'),
      role: collectorAssumeRole,
      timeout: cdk.Duration.minutes(2),
      memorySize: 512,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
        MASTER_ACCOUNT_ID: masterAccountId,
        NEPTUNE_AUTH_SECRET_ARN: neptuneSecret.secretArn,
        SQS_QUEUE_URL: incrementalQueue.queueUrl,
      },
    });

    const eventBridgeTarget = new targets.SqsQueue(incrementalQueue, {
      retryAttempts: 3,
    });

    const logGroup = (fn: lambda.Function, name: string) => {
      new logs.LogGroup(this, `${name}Logs`, {
        logGroupName: `/aws/lambda/${fn.functionName}`,
        retention: logs.RetentionDays.ONE_WEEK,
      });
    };

    logGroup(listAccountsFn, 'ListAccounts');
    logGroup(collectorFn, 'Collector');
    logGroup(graphWriterFn, 'GraphWriter');
    logGroup(incrementalProcessorFn, 'IncrementalProcessor');

    const accessAnalyzerTable = new dynamodb.Table(this, 'AccessAnalyzerCacheTable', {
      tableName: 'AccessAnalyzerCache',
      partitionKey: { name: 'principalArn', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'eventSourceEventName', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      timeToLiveAttribute: 'ttl',
    });
    accessAnalyzerTable.addGlobalSecondaryIndex({
      indexName: 'ActionIndex',
      partitionKey: { name: 'eventSourceEventName', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'lastUsed', type: dynamodb.AttributeType.STRING },
    });

    const policyEvaluatorFn = new lambda.Function(this, 'PolicyEvaluatorFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/policy-evaluator'),
      role: lambdaExecutionRole,
      timeout: cdk.Duration.minutes(15),
      memorySize: 1024,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
        NEPTUNE_AUTH_SECRET_ARN: neptuneSecret.secretArn,
      },
    });

    logGroup(policyEvaluatorFn, 'PolicyEvaluator');

    const cloudTrailAnalyzerFn = new lambda.Function(this, 'CloudTrailAnalyzerFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/cloudtrail-analyzer'),
      role: lambdaExecutionRole,
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      environment: {
        ACCESS_ANALYZER_TABLE: accessAnalyzerTable.tableName,
        ATHENA_WORKGROUP: 'khalifa-cloudtrail-analysis',
        ATHENA_DATABASE: 'khalifa_cloudtrail_db',
        CLOUDTRAIL_S3_LOCATION: 's3://cloudtrail-logs/AWSLogs/',
        ANALYSIS_DAYS: '90',
      },
    });
    cloudTrailAnalyzerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'athena:StartQueryExecution',
          'athena:GetQueryExecution',
          'athena:GetQueryResults',
          'athena:StopQueryExecution',
        ],
        resources: ['*'],
      })
    );
    cloudTrailAnalyzerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'dynamodb:BatchWriteItem',
          'dynamodb:Query',
          'dynamodb:GetItem',
          'dynamodb:PutItem',
        ],
        resources: [accessAnalyzerTable.tableArn, accessAnalyzerTable.tableArn + '/index/*'],
      })
    );
    cloudTrailAnalyzerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['s3:GetObject'],
        resources: ['arn:aws:s3:::cloudtrail-logs/*', 'arn:aws:s3:::cloudtrail-logs'],
      })
    );
    cloudTrailAnalyzerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['glue:GetTable', 'glue:GetDatabase', 'glue:GetPartitions'],
        resources: ['*'],
      })
    );

    logGroup(cloudTrailAnalyzerFn, 'CloudTrailAnalyzer');

    const listAccounts = new tasks.LambdaInvoke(this, 'ListAccounts', {
      lambdaFunction: listAccountsFn,
      outputPath: '$.Payload',
    });

    const mapAccounts = new stepfunctions.Map(this, 'MapAccounts', {
      itemsPath: stepfunctions.JsonPath.stringAt('$.accounts'),
      parameters: {
        'accountId.$': '$$.Map.Item.Value',
      },
      maxConcurrency: 20,
      resultPath: stepfunctions.JsonPath.DISCARD,
    });

    new cdk.CfnOutput(this, 'AccountIds', {
      value: cdk.Fn.join(',', accountIds),
      description: 'AWS account IDs covered by the security graph',
      exportName: 'SecurityGraphAccountIds',
    });

    const collector = new tasks.LambdaInvoke(this, 'Collector', {
      lambdaFunction: collectorFn,
      inputPath: '$',
      outputPath: '$.Payload',
    });

    const graphWriter = new tasks.LambdaInvoke(this, 'GraphWriter', {
      lambdaFunction: graphWriterFn,
      inputPath: '$',
      outputPath: '$.Payload',
    });

    const collectorWithRetry = collector.addRetry({
      maxAttempts: 3,
      interval: cdk.Duration.seconds(30),
      backoffRate: 2,
    });

    const graphWriterWithRetry = graphWriter.addRetry({
      maxAttempts: 3,
      interval: cdk.Duration.seconds(30),
      backoffRate: 2,
    });

    const policyEvaluator = new tasks.LambdaInvoke(this, 'PolicyEvaluator', {
      lambdaFunction: policyEvaluatorFn,
      outputPath: '$.Payload',
    });

    const accountBranch = collectorWithRetry.next(graphWriterWithRetry).next(policyEvaluator);
    mapAccounts.itemProcessor(accountBranch);

    const definition = listAccounts.next(mapAccounts);

    const stateMachine = new stepfunctions.StateMachine(this, 'SecurityGraphIngestion', {
      definition,
      timeout: cdk.Duration.hours(2),
      tracingEnabled: true,
    });

    new events.Rule(this, 'ScheduledTrigger', {
      ruleName: 'security-graph-scheduled-trigger',
      schedule: events.Schedule.rate(cdk.Duration.hours(2)),
      targets: [new targets.SfnStateMachine(stateMachine)],
    });

    const eventRules = [
      {
        name: 'SecurityGroupChange',
        source: 'aws.ec2',
        events: [
          'AuthorizeSecurityGroupIngress',
          'AuthorizeSecurityGroupEgress',
          'RevokeSecurityGroupIngress',
          'RevokeSecurityGroupEgress',
          'CreateSecurityGroup',
          'DeleteSecurityGroup',
        ],
      },
      {
        name: 'S3BucketChange',
        source: 'aws.s3',
        events: ['PutBucketPolicy', 'PutBucketAcl', 'DeleteBucketPolicy'],
      },
      {
        name: 'IamChange',
        source: 'aws.iam',
        events: [
          'CreateUser',
          'DeleteUser',
          'CreateRole',
          'DeleteRole',
          'CreatePolicy',
          'DeletePolicy',
          'AttachUserPolicy',
          'DetachUserPolicy',
          'AttachRolePolicy',
          'DetachRolePolicy',
        ],
      },
      {
        name: 'KmsKeyChange',
        source: 'aws.kms',
        events: ['CreateKey', 'DisableKey', 'ScheduleKeyDeletion'],
      },
      {
        name: 'RdsInstanceChange',
        source: 'aws.rds',
        events: ['CreateDBInstance', 'DeleteDBInstance', 'ModifyDBInstance'],
      },
      {
        name: 'EksClusterChange',
        source: 'aws.eks',
        events: ['CreateCluster', 'DeleteCluster', 'UpdateCluster'],
      },
    ];

    eventRules.forEach(({ name, source, events: eventNames }) => {
      new events.Rule(this, name, {
        ruleName: `security-graph-${name.toLowerCase()}`,
        eventPattern: {
          source: [source],
          detailType: ['AWS API Call via CloudTrail'],
          detail: {
            eventSource: [`${source.replace('aws.', '')}.amazonaws.com`],
            eventName: eventNames,
          },
        },
        targets: [eventBridgeTarget],
      });
    });

    new events.Rule(this, 'QueueProcessorTrigger', {
      ruleName: 'security-graph-queue-processor',
      schedule: events.Schedule.rate(cdk.Duration.minutes(1)),
      targets: [new targets.LambdaFunction(incrementalProcessorFn)],
    });

    const issuesTable = new dynamodb.Table(this, 'SecurityIssuesTable', {
      tableName: 'SecurityIssues',
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'ruleId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    issuesTable.addGlobalSecondaryIndex({
      indexName: 'RuleIdIndex',
      partitionKey: { name: 'ruleId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'updatedAt', type: dynamodb.AttributeType.STRING },
    });
    issuesTable.addGlobalSecondaryIndex({
      indexName: 'StatusIndex',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'updatedAt', type: dynamodb.AttributeType.STRING },
    });

    const evidenceTable = new dynamodb.Table(this, 'ComplianceEvidenceTable', {
      tableName: 'ComplianceEvidence',
      partitionKey: { name: 'controlId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'resourceId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const reportsTable = new dynamodb.Table(this, 'ComplianceReportsTable', {
      tableName: 'ComplianceReports',
      partitionKey: { name: 'framework', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'generatedAt', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const riskEngineFn = new lambda.Function(this, 'RiskEngineFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../packages/risk-engine'),
      role: lambdaExecutionRole,
      timeout: cdk.Duration.minutes(15),
      memorySize: 512,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
        ISSUES_TABLE: issuesTable.tableName,
        NEPTUNE_AUTH_SECRET_ARN: neptuneSecret.secretArn,
      },
    });
    riskEngineFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:PutItem', 'dynamodb:GetItem', 'dynamodb:UpdateItem', 'dynamodb:Query'],
        resources: [issuesTable.tableArn, issuesTable.tableArn + '/index/*'],
      })
    );
    riskEngineFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'dynamodb:PutItem',
          'dynamodb:GetItem',
          'dynamodb:UpdateItem',
          'dynamodb:Query',
          'dynamodb:Scan',
          'dynamodb:BatchWriteItem',
        ],
        resources: [evidenceTable.tableArn, reportsTable.tableArn],
      })
    );

    logGroup(riskEngineFn, 'RiskEngine');

    new events.Rule(this, 'RiskEngineScheduledTrigger', {
      ruleName: 'risk-engine-scheduled-trigger',
      schedule: events.Schedule.rate(cdk.Duration.hours(1)),
      targets: [new targets.LambdaFunction(riskEngineFn)],
    });

    new events.Rule(this, 'PolicyEvaluatorScheduledTrigger', {
      ruleName: 'policy-evaluator-scheduled-trigger',
      schedule: events.Schedule.rate(cdk.Duration.hours(6)),
      targets: [new targets.LambdaFunction(policyEvaluatorFn)],
    });

    new events.Rule(this, 'CloudTrailAnalyzerScheduledTrigger', {
      ruleName: 'cloudtrail-analyzer-scheduled-trigger',
      schedule: events.Schedule.cron({ minute: '0', hour: '2' }),
      targets: [new targets.LambdaFunction(cloudTrailAnalyzerFn)],
    });
  }
}
