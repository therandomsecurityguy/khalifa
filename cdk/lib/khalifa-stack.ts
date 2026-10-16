import * as cdk from 'aws-cdk-lib';
import * as stepfunctions from 'aws-cdk-lib/aws-stepfunctions';
import * as tasks from 'aws-cdk-lib/aws-stepfunctions-tasks';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { SqsEventSource } from 'aws-cdk-lib/aws-lambda-event-sources';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import type { Construct } from 'constructs';

export interface SecurityGraphIngestionStackProps extends cdk.StackProps {
  neptuneEndpoint: string;
  neptuneClusterResourceId: string;
  homeAccountId: string;
  accountIds: string[];
  parentIds: string[];
  collectionRegions: string[];
  /** Deploy canary IAM credentials. Any use of a canary key is a security incident (RULE-023). */
  enableCanaries?: boolean;
  /** Optional VPC isolation for the DSPM scanner. When set, the scanner runs in this VPC
   *  with no internet egress, reaching S3/Macie/Lambda/Logs via interface endpoints. */
  scannerVpcId?: string;
  scannerPrivateSubnetIds?: string[];
  scannerAvailabilityZones?: string[];
  scannerSecurityGroupId?: string;
  /** Opt-in event-driven scanning: an SQS queue + Lambda that scans objects on S3 events. */
  enableDspmEventTrigger?: boolean;
  /** Buckets the DSPM scanner may read object content from. Empty keeps the
   *  historical all-buckets grant; setting it scopes s3:GetObject. */
  dspmBucketAllowlist?: string[];
}

export class SecurityGraphIngestionStack extends cdk.Stack {
  public readonly issuesTable!: dynamodb.Table;
  public readonly evidenceTable!: dynamodb.Table;
  public readonly reportsTable!: dynamodb.Table;
  public readonly leastPrivilegeFindingsTable!: dynamodb.Table;

  constructor(scope: Construct, id: string, props: SecurityGraphIngestionStackProps) {
    super(scope, id, props);

    const {
      neptuneEndpoint,
      neptuneClusterResourceId,
      homeAccountId,
      accountIds,
      parentIds,
      collectionRegions,
    } = props;
    const neptuneResource = `arn:aws:neptune-db:${this.region}:${this.account}:${neptuneClusterResourceId}/*`;

    // One customer-managed key for every table below. Using a CMK means the
    // calling principal must hold kms:Decrypt / GenerateDataKey, which
    // grantReadWriteData does not add, so each consumer is granted the key
    // explicitly where its table access is declared.
    const tableKey = new kms.Key(this, 'TableKey', {
      description: 'Khalifa DynamoDB table encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const deadLetterQueue = new sqs.Queue(this, 'DeadLetterQueue', {
      queueName: 'security-graph-dlq.fifo',
      fifo: true,
    });

    const incrementalQueue = new sqs.Queue(this, 'IncrementalQueue', {
      queueName: 'security-graph-incremental-queue.fifo',
      fifo: true,
      contentBasedDeduplication: true,
      deadLetterQueue: {
        queue: deadLetterQueue,
        maxReceiveCount: 3,
      },
      retentionPeriod: cdk.Duration.days(4),
      visibilityTimeout: cdk.Duration.minutes(5),
    });
    incrementalQueue.addToResourcePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        actions: ['sqs:SendMessage'],
        resources: [incrementalQueue.queueArn],
        conditions: { Bool: { 'aws:PrincipalIsAWSService': 'false' } },
      })
    );

    // One role per function. The functions that previously shared a role have
    // very different needs: list-accounts never touches Neptune, yet it used to
    // inherit the right to read the Neptune auth secret. Each function now
    // starts from the logging baseline and receives only what it uses.
    const lambdaRole = (id: string) =>
      new iam.Role(this, id, {
        assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName('servicerole/AWSLambdaBasicExecutionRole'),
        ],
      });
    const listAccountsRole = lambdaRole('ListAccountsRole');

    // The CIEM lambdas sign Neptune requests with SigV4 like graph-writer and
    // the risk engine, so they hold neptune-db permissions instead of a static
    // password read from Secrets Manager.
    const policyEvaluatorRole = lambdaRole('PolicyEvaluatorRole');
    policyEvaluatorRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['neptune-db:ReadDataViaQuery', 'neptune-db:WriteDataViaQuery'],
        resources: [neptuneResource],
      })
    );
    const leastPrivilegeSweepRole = lambdaRole('LeastPrivilegeSweepRole');
    // The sweep only reads the graph; its findings go to DynamoDB.
    leastPrivilegeSweepRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ['neptune-db:ReadDataViaQuery'],
        resources: [neptuneResource],
      })
    );

    // The hub's external ID lives in Secrets Manager, not in Lambda environment
    // variables. It is generated here the way the Terraform module generates
    // it, so no cleartext ever enters the CloudFormation template: the IAM
    // condition refers to the secret through a dynamic reference.
    // Literal, not a token: a dynamic reference must appear verbatim in the
    // template. Interpolating a token makes CDK emit an Fn::Join, which
    // CloudFormation does not treat as a dynamic reference.
    const COLLECTOR_RUNTIME_SECRET_NAME = 'khalifa/runtime';
    const runtimeSecret = new secretsmanager.Secret(this, 'RuntimeSecret', {
      secretName: COLLECTOR_RUNTIME_SECRET_NAME,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: 'COLLECTOR_EXTERNAL_ID',
        passwordLength: 32,
        excludePunctuation: true,
      },
    });
    const collectorExternalIdRef = `{{resolve:secretsmanager:${COLLECTOR_RUNTIME_SECRET_NAME}:SecretString:COLLECTOR_EXTERNAL_ID}}`;

    // Member-account collection is limited to the approved accounts, and the
    // hub must present the external ID the member role's trust policy requires.
    // Keep this name in step with the Terraform `collector_role_name` variable.
    const COLLECTOR_ROLE_NAME = 'SecurityGraphCollectorRole';
    const memberCollectorRoleArns = accountIds.map(
      (accountId) => `arn:aws:iam::${accountId}:role/${COLLECTOR_ROLE_NAME}`
    );
    const assumeMemberCollector = new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sts:AssumeRole'],
      // When no approved accounts are configured the deployment relies on
      // organization discovery, so no account can be named here; the external
      // ID condition still applies. Set accountIds to tighten this further.
      resources:
        memberCollectorRoleArns.length > 0
          ? memberCollectorRoleArns
          : [`arn:aws:iam::*:role/${COLLECTOR_ROLE_NAME}`],
      conditions: { StringEquals: { 'sts:ExternalId': collectorExternalIdRef } },
    });
    const collectorRole = lambdaRole('CollectorRole');
    collectorRole.addToPolicy(assumeMemberCollector);
    runtimeSecret.grantRead(collectorRole);
    // The dynamic reference above is an opaque string, so CloudFormation will
    // not infer that the policy needs the secret to exist first. Make it
    // explicit or the policy can be created before the secret has a value.
    collectorRole.node.addDependency(runtimeSecret);
    const incrementalCollectorRole = lambdaRole('IncrementalCollectorRole');
    incrementalCollectorRole.addToPolicy(assumeMemberCollector);
    runtimeSecret.grantRead(incrementalCollectorRole);
    incrementalCollectorRole.node.addDependency(runtimeSecret);
    const organizationsReadActions = [
      'organizations:ListAccounts',
      'organizations:ListAccountsForParent',
      'organizations:ListOrganizationalUnitsForParent',
    ];
    const listAccountsFn = new lambda.Function(this, 'ListAccountsFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/list-accounts/dist'),
      role: listAccountsRole,
      timeout: cdk.Duration.minutes(1),
      memorySize: 256,
      environment: {
        COLLECTION_ACCOUNT_IDS: accountIds.join(','),
        COLLECTION_PARENT_IDS: parentIds.join(','),
        COLLECTION_REGIONS: collectionRegions.join(','),
      },
    });
    listAccountsFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: organizationsReadActions,
        resources: ['*'],
      })
    );

    const collectorFn = new lambda.Function(this, 'CollectorFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/collector/dist'),
      role: collectorRole,
      timeout: cdk.Duration.minutes(10),
      memorySize: 1024,
      environment: {
        HOME_ACCOUNT_ID: homeAccountId,
        COLLECTOR_EXTERNAL_ID_SECRET_ARN: runtimeSecret.secretArn,
      },
    });

    const graphWriterFn = new lambda.Function(this, 'GraphWriterFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/graph-writer/dist'),
      timeout: cdk.Duration.minutes(5),
      memorySize: 1024,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
      },
    });
    graphWriterFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['neptune-db:ReadDataViaQuery', 'neptune-db:WriteDataViaQuery'],
        resources: [neptuneResource],
      })
    );
    listAccountsFn.addEnvironment('GRAPH_WRITER_FUNCTION_NAME', graphWriterFn.functionName);
    graphWriterFn.grantInvoke(listAccountsFn);
    collectorFn.addEnvironment('GRAPH_WRITER_FUNCTION_NAME', graphWriterFn.functionName);
    graphWriterFn.grantInvoke(collectorFn);

    const incrementalProcessorFn = new lambda.Function(this, 'IncrementalProcessorFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/incremental-collector/dist'),
      role: incrementalCollectorRole,
      timeout: cdk.Duration.minutes(2),
      memorySize: 512,
      environment: {
        COLLECTION_ACCOUNT_IDS: accountIds.join(','),
        COLLECTION_PARENT_IDS: parentIds.join(','),
        COLLECTION_REGIONS: collectionRegions.join(','),
        HOME_ACCOUNT_ID: homeAccountId,
        COLLECTOR_EXTERNAL_ID_SECRET_ARN: runtimeSecret.secretArn,
        SQS_QUEUE_URL: incrementalQueue.queueUrl,
        GRAPH_WRITER_FUNCTION_NAME: graphWriterFn.functionName,
      },
    });
    graphWriterFn.grantInvoke(incrementalProcessorFn);
    incrementalQueue.grantConsumeMessages(incrementalProcessorFn);
    incrementalProcessorFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: organizationsReadActions,
        resources: ['*'],
      })
    );

    const eventBridgeTarget = new targets.SqsQueue(incrementalQueue, {
      retryAttempts: 3,
      messageGroupId: 'security-graph-changes',
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
      pointInTimeRecovery: true,
      deletionProtection: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tableKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      timeToLiveAttribute: 'ttl',
    });
    accessAnalyzerTable.addGlobalSecondaryIndex({
      indexName: 'ActionIndex',
      partitionKey: { name: 'eventSourceEventName', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'lastUsed', type: dynamodb.AttributeType.STRING },
    });

    this.leastPrivilegeFindingsTable = new dynamodb.Table(this, 'LeastPrivilegeFindingsTable', {
      tableName: 'LeastPrivilegeFindings',
      partitionKey: { name: 'accountId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'principalArn', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      deletionProtection: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tableKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.leastPrivilegeFindingsTable.addGlobalSecondaryIndex({
      indexName: 'RiskLevelIndex',
      partitionKey: { name: 'riskLevel', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'removedActionCount', type: dynamodb.AttributeType.NUMBER },
    });

    const policyEvaluatorFn = new lambda.Function(this, 'PolicyEvaluatorFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/policy-evaluator/dist'),
      role: policyEvaluatorRole,
      timeout: cdk.Duration.minutes(15),
      memorySize: 1024,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
      },
    });

    logGroup(policyEvaluatorFn, 'PolicyEvaluator');

    const leastPrivilegeSweepFn = new lambda.Function(this, 'LeastPrivilegeSweepFn', {
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/least-privilege-sweep'),
      role: leastPrivilegeSweepRole,
      timeout: cdk.Duration.minutes(15),
      memorySize: 1024,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
        ACCESS_ANALYZER_TABLE: accessAnalyzerTable.tableName,
        LEAST_PRIVILEGE_TABLE: this.leastPrivilegeFindingsTable.tableName,
        SAFETY_MARGIN_DAYS: '7',
      },
    });
    leastPrivilegeSweepFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:Query'],
        resources: [accessAnalyzerTable.tableArn],
      })
    );
    leastPrivilegeSweepFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:PutItem', 'dynamodb:Query', 'dynamodb:GetItem'],
        resources: [
          this.leastPrivilegeFindingsTable.tableArn,
          this.leastPrivilegeFindingsTable.tableArn + '/index/*',
        ],
      })
    );

    logGroup(leastPrivilegeSweepFn, 'LeastPrivilegeSweep');
    tableKey.grantEncryptDecrypt(leastPrivilegeSweepRole);

    // Canary credentials (feature-flagged). Each canary user has no permissions: the
    // credentials do nothing except appear in CloudTrail when used, which the daily
    // analyzer turns into a CANARY_USED anomaly (RULE-023 treats it as an incident).
    const canaryPrincipalArns: string[] = [];
    if (props.enableCanaries) {
      for (const index of [1, 2]) {
        const canaryUser = new iam.User(this, `CanaryUser${index}`, {
          userName: `khalifa-canary-${index}`,
        });
        cdk.Tags.of(canaryUser).add('canary', 'true');
        const canaryKey = new iam.CfnAccessKey(this, `CanaryKey${index}`, {
          userName: canaryUser.userName,
        });
        new secretsmanager.Secret(this, `CanarySecret${index}`, {
          secretName: `khalifa-canary/credentials-${index}`,
          description:
            'Khalifa canary credential. Any CloudTrail activity from this key is investigated as a security incident (RULE-023).',
          secretObjectValue: {
            access_key_id: cdk.SecretValue.unsafePlainText(canaryKey.ref),
            secret_access_key: cdk.SecretValue.unsafePlainText(canaryKey.attrSecretAccessKey),
            principal_arn: cdk.SecretValue.unsafePlainText(canaryUser.userArn),
          },
        });
        canaryPrincipalArns.push(canaryUser.userArn);
      }
    }

    const cloudTrailAnalyzerFn = new lambda.Function(this, 'CloudTrailAnalyzerFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/cloudtrail-analyzer/dist'),
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      environment: {
        ACCESS_ANALYZER_TABLE: accessAnalyzerTable.tableName,
        ATHENA_WORKGROUP: 'khalifa-cloudtrail-analysis',
        ATHENA_DATABASE: 'khalifa_cloudtrail_db',
        ATHENA_RESULTS_S3_LOCATION: 's3://cloudtrail-logs/khalifa-athena-results/',
        ANALYSIS_DAYS: '90',
        GRAPH_WRITER_FUNCTION_NAME: graphWriterFn.functionName,
        CANARY_PRINCIPAL_ARNS: canaryPrincipalArns.join(','),
      },
    });
    cloudTrailAnalyzerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['lambda:InvokeFunction'],
        resources: [graphWriterFn.functionArn],
      })
    );
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
        actions: ['s3:GetObject', 's3:PutObject', 's3:AbortMultipartUpload'],
        resources: ['arn:aws:s3:::cloudtrail-logs/*'],
      })
    );
    cloudTrailAnalyzerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['s3:GetBucketLocation', 's3:ListBucket'],
        resources: ['arn:aws:s3:::cloudtrail-logs'],
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
    tableKey.grantEncryptDecrypt(cloudTrailAnalyzerFn);

    // Optional VPC isolation for the DSPM scanner: no internet egress, all AWS
    // API calls (S3, Macie, Lambda invoke, CloudWatch Logs) go through interface
    // endpoints. Off by default; enabled by supplying scannerVpcId + subnets.
    let scannerVpc: ec2.IVpc | undefined;
    let scannerSecurityGroups: ec2.ISecurityGroup[] | undefined;
    if (props.scannerVpcId && props.scannerPrivateSubnetIds?.length) {
      scannerVpc = ec2.Vpc.fromVpcAttributes(this, 'ScannerVpc', {
        vpcId: props.scannerVpcId,
        availabilityZones: props.scannerAvailabilityZones ?? this.availabilityZones,
        privateSubnetIds: props.scannerPrivateSubnetIds,
      });
      const scannerSg = props.scannerSecurityGroupId
        ? ec2.SecurityGroup.fromSecurityGroupId(this, 'ScannerSg', props.scannerSecurityGroupId)
        : new ec2.SecurityGroup(this, 'ScannerSg', {
            vpc: scannerVpc,
            allowAllOutbound: false,
          });
      if (!props.scannerSecurityGroupId) {
        // Allow the Lambda to reach the endpoints (and vice versa) on 443 only.
        scannerSg.connections.allowInternally(ec2.Port.tcp(443));
      }
      scannerSecurityGroups = [scannerSg];

      for (const service of [
        ec2.InterfaceVpcEndpointAwsService.S3,
        ec2.InterfaceVpcEndpointAwsService.MACIE,
        ec2.InterfaceVpcEndpointAwsService.LAMBDA,
        ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      ]) {
        scannerVpc.addInterfaceEndpoint(`Scanner${service.shortName}Endpoint`, {
          service,
          subnets: { subnets: scannerVpc.privateSubnets },
          securityGroups: [scannerSg],
          open: false,
        });
      }
    }

    // Content reads require an explicit allowlist. An empty list grants no
    // object access at all: falling back to every bucket is the broad grant
    // this workstream exists to remove. Bucket tags cannot scope this either:
    // S3 objects are not tag-conditioned by aws:ResourceTag, and the opt-in
    // dspm-scan tag lives on the bucket, so the tag gate stays as runtime
    // defence in depth.
    const dspmReadResources =
      (props.dspmBucketAllowlist?.length ?? 0) > 0
        ? [
            ...props.dspmBucketAllowlist!.map((bucket) => `arn:aws:s3:::${bucket}`),
            ...props.dspmBucketAllowlist!.map((bucket) => `arn:aws:s3:::${bucket}/*`),
          ]
        : undefined;

    const dspmScannerFn = new lambda.Function(this, 'DspmScannerFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../lambdas/dspm-scanner/dist'),
      timeout: cdk.Duration.minutes(15),
      memorySize: 2048,
      vpc: scannerVpc,
      securityGroups: scannerSecurityGroups,
      environment: {
        GRAPH_WRITER_FUNCTION_NAME: graphWriterFn.functionName,
        DSPM_SCAN_MODE: process.env.DSPM_SCAN_MODE || 'tagged-only',
        MACIE_ENABLED: process.env.MACIE_ENABLED || 'false',
        DSPM_CLASSIFY_BUDGET_MS: process.env.DSPM_CLASSIFY_BUDGET_MS || '30000',
      },
    });
    graphWriterFn.grantInvoke(dspmScannerFn);
    if (dspmReadResources) {
      dspmScannerFn.addToRolePolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['s3:ListBucket', 's3:GetObject', 's3:GetBucketTagging'],
          // Object actions match only object ARNs, so both forms are required.
          resources: dspmReadResources,
        })
      );
    }
    dspmScannerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        // ListAllMyBuckets cannot be resource-scoped and returns names only.
        actions: ['s3:ListAllMyBuckets'],
        resources: ['*'],
      })
    );
    dspmScannerFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['lambda:ListFunctions'],
        resources: ['*'],
      })
    );
    if (process.env.MACIE_ENABLED === 'true') {
      dspmScannerFn.addToRolePolicy(
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: ['macie2:ListFindings', 'macie2:GetFindings', 'macie2:DescribeBuckets'],
          resources: ['*'],
        })
      );
    }

    logGroup(dspmScannerFn, 'DspmScanner');

    if (props.enableDspmEventTrigger) {
      const dspmQueue = new sqs.Queue(this, 'DspmScannerQueue', {
        queueName: 'dspm-scanner-events',
        visibilityTimeout: cdk.Duration.minutes(5),
      });
      const dspmSqsFn = new lambda.Function(this, 'DspmScannerSqsFn', {
        runtime: lambda.Runtime.NODEJS_24_X,
        handler: 'index.sqsHandler',
        code: lambda.Code.fromAsset('../lambdas/dspm-scanner/dist'),
        timeout: cdk.Duration.minutes(5),
        memorySize: 2048,
        vpc: scannerVpc,
        securityGroups: scannerSecurityGroups,
        environment: {
          GRAPH_WRITER_FUNCTION_NAME: graphWriterFn.functionName,
          DSPM_CLASSIFY_BUDGET_MS: process.env.DSPM_CLASSIFY_BUDGET_MS || '30000',
        },
      });
      graphWriterFn.grantInvoke(dspmSqsFn);
      if (dspmReadResources) {
        dspmSqsFn.addToRolePolicy(
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['s3:GetObject'],
            resources: dspmReadResources,
          })
        );
      }
      dspmQueue.grantConsumeMessages(dspmSqsFn);
      dspmSqsFn.addEventSource(new SqsEventSource(dspmQueue, { batchSize: 10 }));
      logGroup(dspmSqsFn, 'DspmScannerSqs');
    }

    const listAccounts = new tasks.LambdaInvoke(this, 'ListAccounts', {
      lambdaFunction: listAccountsFn,
      outputPath: '$.Payload',
    });

    const mapAccounts = new stepfunctions.Map(this, 'MapAccounts', {
      itemsPath: stepfunctions.JsonPath.stringAt('$.workItems'),
      itemSelector: {
        'accountId.$': '$$.Map.Item.Value.accountId',
        'region.$': '$$.Map.Item.Value.region',
        'collectGlobal.$': '$$.Map.Item.Value.collectGlobal',
      },
      maxConcurrency: 20,
      resultPath: stepfunctions.JsonPath.DISCARD,
    });

    const collector = new tasks.LambdaInvoke(this, 'Collector', {
      lambdaFunction: collectorFn,
      inputPath: '$',
      outputPath: '$.Payload',
    });

    const collectorWithRetry = collector.addRetry({
      maxAttempts: 3,
      interval: cdk.Duration.seconds(30),
      backoffRate: 2,
      jitterStrategy: stepfunctions.JitterType.FULL,
    });

    const policyEvaluator = new tasks.LambdaInvoke(this, 'PolicyEvaluator', {
      lambdaFunction: policyEvaluatorFn,
      outputPath: '$.Payload',
    });

    mapAccounts.itemProcessor(collectorWithRetry);

    const definition = listAccounts.next(mapAccounts).next(policyEvaluator);

    const stateMachine = new stepfunctions.StateMachine(this, 'SecurityGraphIngestion', {
      definitionBody: stepfunctions.DefinitionBody.fromChainable(definition),
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

    this.issuesTable = new dynamodb.Table(this, 'SecurityIssuesTable', {
      tableName: 'SecurityIssues',
      partitionKey: { name: 'id', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'ruleId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      deletionProtection: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tableKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });
    this.issuesTable.addGlobalSecondaryIndex({
      indexName: 'RuleIdIndex',
      partitionKey: { name: 'ruleId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'updatedAt', type: dynamodb.AttributeType.STRING },
    });
    this.issuesTable.addGlobalSecondaryIndex({
      indexName: 'StatusIndex',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'updatedAt', type: dynamodb.AttributeType.STRING },
    });
    this.issuesTable.addGlobalSecondaryIndex({
      indexName: 'StatusCreatedIndex',
      partitionKey: { name: 'status', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'createdAt', type: dynamodb.AttributeType.STRING },
    });

    this.evidenceTable = new dynamodb.Table(this, 'ComplianceEvidenceTable', {
      tableName: 'ComplianceEvidence',
      partitionKey: { name: 'controlId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'resourceId', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      deletionProtection: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tableKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    this.reportsTable = new dynamodb.Table(this, 'ComplianceReportsTable', {
      tableName: 'ComplianceReports',
      partitionKey: { name: 'framework', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'generatedAt', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      deletionProtection: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tableKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    const postureTrendsTable = new dynamodb.Table(this, 'PostureTrendsTable', {
      tableName: 'PostureTrends',
      partitionKey: { name: 'metric', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'date', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      pointInTimeRecovery: true,
      deletionProtection: true,
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tableKey,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      timeToLiveAttribute: 'ttl',
    });

    const issuesTopic = new sns.Topic(this, 'IssuesTopic', {
      topicName: 'khalifa-issues',
      displayName: 'Khalifa Security Issues',
    });

    const riskEngineFn = new lambda.Function(this, 'RiskEngineFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../packages/risk-engine/dist/lambda'),
      timeout: cdk.Duration.minutes(15),
      memorySize: 512,
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
        ISSUES_TABLE: this.issuesTable.tableName,
        POSTURE_TRENDS_TABLE: postureTrendsTable.tableName,
        ISSUES_TOPIC_ARN: issuesTopic.topicArn,
        ISSUE_SINKS: process.env.ISSUE_SINKS || 'sns',
        SLACK_WEBHOOK_URL: process.env.SLACK_WEBHOOK_URL || '',
        SLACK_MIN_SEVERITY: process.env.SLACK_MIN_SEVERITY || 'high',
        UI_BASE_URL: process.env.UI_BASE_URL || '',
      },
    });
    riskEngineFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['neptune-db:ReadDataViaQuery'],
        resources: [neptuneResource],
      })
    );
    riskEngineFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:PutItem', 'dynamodb:GetItem', 'dynamodb:UpdateItem', 'dynamodb:Query'],
        resources: [this.issuesTable.tableArn, this.issuesTable.tableArn + '/index/*'],
      })
    );
    riskEngineFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['dynamodb:PutItem', 'dynamodb:UpdateItem', 'dynamodb:Query'],
        resources: [postureTrendsTable.tableArn],
      })
    );
    riskEngineFn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['sns:Publish'],
        resources: [issuesTopic.topicArn],
      })
    );

    logGroup(riskEngineFn, 'RiskEngine');
    tableKey.grantEncryptDecrypt(riskEngineFn);

    const complianceEngineFn = new lambda.Function(this, 'ComplianceEngineFn', {
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('../packages/risk-engine/dist/compliance-lambda'),
      timeout: cdk.Duration.minutes(15),
      environment: {
        NEPTUNE_ENDPOINT: neptuneEndpoint,
        COMPLIANCE_EVIDENCE_TABLE: this.evidenceTable.tableName,
        COMPLIANCE_REPORTS_TABLE: this.reportsTable.tableName,
      },
    });
    complianceEngineFn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ['neptune-db:ReadDataViaQuery'],
        resources: [neptuneResource],
      })
    );
    this.evidenceTable.grantReadWriteData(complianceEngineFn);
    this.reportsTable.grantReadWriteData(complianceEngineFn);

    logGroup(complianceEngineFn, 'ComplianceEngine');
    tableKey.grantEncryptDecrypt(complianceEngineFn);

    new events.Rule(this, 'RiskEngineScheduledTrigger', {
      ruleName: 'risk-engine-scheduled-trigger',
      schedule: events.Schedule.rate(cdk.Duration.hours(1)),
      targets: [new targets.LambdaFunction(riskEngineFn)],
    });

    new events.Rule(this, 'ComplianceEngineScheduledTrigger', {
      ruleName: 'compliance-engine-scheduled-trigger',
      schedule: events.Schedule.rate(cdk.Duration.hours(6)),
      targets: [new targets.LambdaFunction(complianceEngineFn)],
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

    new events.Rule(this, 'DspmScannerScheduledTrigger', {
      ruleName: 'dspm-scanner-scheduled-trigger',
      schedule: events.Schedule.cron({ minute: '0', hour: '3' }),
      targets: [new targets.LambdaFunction(dspmScannerFn)],
    });

    new events.Rule(this, 'LeastPrivilegeSweepScheduledTrigger', {
      ruleName: 'least-privilege-sweep-scheduled-trigger',
      schedule: events.Schedule.cron({ minute: '0', hour: '3' }),
      targets: [new targets.LambdaFunction(leastPrivilegeSweepFn)],
    });
  }
}
