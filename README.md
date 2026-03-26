# Kalifa - Security Graph Ingestion

Agentless ingestion of AWS Org resources and Security Hub findings into a Neptune-backed security graph.

## Architecture

```
EventBridge Schedule (every 2 hours)
    │
    ▼
Step Functions State Machine
    │
    ├─ ListAccounts Lambda
    └─ MapAccounts (parallel per account)
          │
          ▼
    Collector Lambda (per account)
    ├─ STS assume role into target account
    ├─ Collect: EC2, S3, IAM, KMS, RDS, EKS, SecurityHub
    └─ GraphWriter Lambda → Neptune

Event-Driven (incremental updates)
    │
    ▼
EventBridge → SQS Queue → IncrementalProcessor Lambda → Neptune
```

## Prerequisites

- Node.js 20+
- AWS CDK CLI
- AWS credentials with permissions to deploy:
  - Lambda, Step Functions, EventBridge, SQS
  - Secrets Manager, CloudWatch Logs
  - IAM roles and policies
- Neptune cluster in us-east-1

## Project Structure

```
kalifa/
├── cdk/                    # CDK infrastructure
│   ├── bin/kalifa.ts
│   └── lib/kalifa-stack.ts
├── lambdas/
│   ├── shared/             # Shared types and utilities
│   ├── list-accounts/      # Lists org accounts
│   ├── collector/          # Collects AWS resources
│   ├── graph-writer/       # Writes to Neptune
│   └── incremental-collector/  # Event-driven updates
└── templates/
    └── SecurityGraphCollectorRole.yaml  # Cross-account role
```

## Quick Start

### 1. Install dependencies

```bash
# CDK
cd cdk && npm install && cd ..

# Lambdas
cd lambdas/shared && npm install && cd ..
cd lambdas/list-accounts && npm install && cd ..
cd lambdas/collector && npm install && cd ..
cd lambdas/graph-writer && npm install && cd ..
cd lambdas/incremental-collector && npm install && cd ..
```

### 2. Deploy CDK stack

```bash
cd cdk
npm run build

cdk deploy SecurityGraphIngestionStack \
  --neptune-endpoint neptune-cluster.us-east-1.amazonaws.com \
  --master-account-id 123456789012
```

### 3. Deploy StackSet to member accounts

```bash
# Create StackSet
aws cloudformation create-stack-set \
  --stack-set-name SecurityGraphCollectorRole \
  --template-body file://../templates/SecurityGraphCollectorRole.yaml \
  --parameters ParameterKey=MasterAccountId,ParameterValue=123456789012

# Add member accounts
aws cloudformation create-stack-instances \
  --stack-set-name SecurityGraphCollectorRole \
  --accounts 223456789012 323456789012 \
  --regions us-east-1 \
  --operation-preferences FailureToleranceCount:0,MaxConcurrentCount:5
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `NEPTUNE_ENDPOINT` | Neptune cluster endpoint | - |
| `MASTER_ACCOUNT_ID` | Org master account ID | - |
| `MOCK_MODE` | Enable local mock mode | false |
| `NEPTUNE_AUTH_SECRET_ARN` | Secrets Manager ARN | - |

## Local Development

Run Lambda functions locally with mock data:

```bash
MOCK_MODE=true npx ts-node lambdas/list-accounts/index.ts
MOCK_MODE=true npx ts-node lambdas/collector/index.ts
```

## Graph Schema

### Node Labels
- AwsAccount, Vpc, Subnet, SecurityGroup, NetworkInterface
- InternetGateway, Ec2Instance, S3Bucket, RdsInstance
- IamUser, IamRole, IamPolicy, Finding, Cve
- ContainerImage, Pod, KmsKey, Secret

### Edge Labels
- OWNS, CONTAINS, HAS, PROTECTS, ATTACHED_TO
- CONNECTED_TO, ALLOWS_TRAFFIC_FROM, RUNS_IMAGE
- HAS_FINDING, RELATED_TO, ENCRYPTED_WITH, USES

## Monitoring

- CloudWatch Logs: `/aws/lambda/*`
- Step Functions: SecurityGraphIngestion
- EventBridge: security-graph-*-trigger rules

## Troubleshooting

### Check Lambda logs
```bash
aws logs filter-log-events --log-group-name /aws/lambda/ListAccounts-fn
```

### Check Step Functions execution
```bash
aws stepfunctions list-executions --state-machine-arn <arn>
```

### Manually trigger ingestion
```bash
aws stepfunctions start-execution --state-machine-arn <arn>
```
