"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SecurityGraphIngestionStack = void 0;
const cdk = __importStar(require("aws-cdk-lib"));
const stepfunctions = __importStar(require("aws-cdk-lib/aws-stepfunctions"));
const tasks = __importStar(require("aws-cdk-lib/aws-stepfunctions-tasks"));
const lambda = __importStar(require("aws-cdk-lib/aws-lambda"));
const events = __importStar(require("aws-cdk-lib/aws-events"));
const targets = __importStar(require("aws-cdk-lib/aws-events-targets"));
const logs = __importStar(require("aws-cdk-lib/aws-logs"));
const iam = __importStar(require("aws-cdk-lib/aws-iam"));
const sqs = __importStar(require("aws-cdk-lib/aws-sqs"));
const secretsmanager = __importStar(require("aws-cdk-lib/aws-secretsmanager"));
const dynamodb = __importStar(require("aws-cdk-lib/aws-dynamodb"));
class SecurityGraphIngestionStack extends cdk.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        const { neptuneEndpoint, masterAccountId } = props;
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
        lambdaExecutionRole.addToPolicy(new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['secretsmanager:GetSecretValue'],
            resources: [neptuneSecret.secretArn],
        }));
        const collectorAssumeRole = new iam.Role(this, 'CollectorAssumeRole', {
            assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        });
        collectorAssumeRole.addToPolicy(new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['sts:AssumeRole'],
            resources: [`arn:aws:iam::*:role/SecurityGraphCollectorRole`],
        }));
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
        listAccountsFn.addToRolePolicy(new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['organizations:ListAccounts', 'organizations:ListOrganizationalUnitsForParent'],
            resources: ['*'],
        }));
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
        const logGroup = (fn, name) => {
            new logs.LogGroup(this, `${name}Logs`, {
                logGroupName: `/aws/lambda/${fn.functionName}`,
                retention: logs.RetentionDays.ONE_WEEK,
            });
        };
        logGroup(listAccountsFn, 'ListAccounts');
        logGroup(collectorFn, 'Collector');
        logGroup(graphWriterFn, 'GraphWriter');
        logGroup(incrementalProcessorFn, 'IncrementalProcessor');
        const listAccounts = new tasks.LambdaInvoke(this, 'ListAccounts', {
            lambdaFunction: listAccountsFn,
            outputPath: '$.Payload',
        });
        const mapAccounts = new stepfunctions.Map(this, 'MapAccounts', {
            itemsPath: '$.accounts',
            maxConcurrency: 20,
            resultPath: stepfunctions.JsonPath.DISCARD,
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
        const accountBranch = collectorWithRetry.next(graphWriterWithRetry);
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
            { name: 'SecurityGroupChange', source: 'aws.ec2', events: ['AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup'] },
            { name: 'S3BucketChange', source: 'aws.s3', events: ['PutBucketPolicy', 'PutBucketAcl', 'DeleteBucketPolicy'] },
            { name: 'IamChange', source: 'aws.iam', events: ['CreateUser', 'DeleteUser', 'CreateRole', 'DeleteRole', 'CreatePolicy', 'DeletePolicy', 'AttachUserPolicy', 'DetachUserPolicy', 'AttachRolePolicy', 'DetachRolePolicy'] },
            { name: 'KmsKeyChange', source: 'aws.kms', events: ['CreateKey', 'DisableKey', 'ScheduleKeyDeletion'] },
            { name: 'RdsInstanceChange', source: 'aws.rds', events: ['CreateDBInstance', 'DeleteDBInstance', 'ModifyDBInstance'] },
            { name: 'EksClusterChange', source: 'aws.eks', events: ['CreateCluster', 'DeleteCluster', 'UpdateCluster'] },
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
        const riskEngineFn = new lambda.Function(this, 'RiskEngineFn', {
            runtime: lambda.Runtime.NODEJS_20_X,
            handler: 'index.handler',
            code: lambda.Code.fromAsset('../lambdas/risk-engine'),
            role: lambdaExecutionRole,
            timeout: cdk.Duration.minutes(15),
            memorySize: 512,
            environment: {
                NEPTUNE_ENDPOINT: neptuneEndpoint,
                ISSUES_TABLE: issuesTable.tableName,
                NEPTUNE_AUTH_SECRET_ARN: neptuneSecret.secretArn,
            },
        });
        riskEngineFn.addToRolePolicy(new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: ['dynamodb:PutItem', 'dynamodb:GetItem', 'dynamodb:UpdateItem', 'dynamodb:Query'],
            resources: [issuesTable.tableArn, issuesTable.tableArn + '/index/*'],
        }));
        logGroup(riskEngineFn, 'RiskEngine');
        new events.Rule(this, 'RiskEngineScheduledTrigger', {
            ruleName: 'risk-engine-scheduled-trigger',
            schedule: events.Schedule.rate(cdk.Duration.hours(1)),
            targets: [new targets.LambdaFunction(riskEngineFn)],
        });
    }
}
exports.SecurityGraphIngestionStack = SecurityGraphIngestionStack;
//# sourceMappingURL=khalifa-stack.js.map