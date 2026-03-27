# Khalifa - Security Graph & Risk Engine

Agentless ingestion of AWS Org resources and Security Hub findings into a Neptune-backed security graph, with a risk and attack-path engine to identify security issues.

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

Risk Engine (every 1 hour)
    │
    ▼
EventBridge Schedule → RiskEngine Lambda → Neptune (query)
    │
    ▼
DynamoDB (Issues table)
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
khalifa/
├── cdk/                    # CDK infrastructure
│   ├── bin/khalifa.ts
│   └── lib/khalifa-stack.ts
├── lambdas/
│   ├── shared/             # Shared types and utilities
│   ├── list-accounts/     # Lists org accounts
│   ├── collector/          # Collects AWS resources
│   ├── graph-writer/       # Writes to Neptune
│   ├── incremental-collector/  # Event-driven updates
│   └── risk-engine/        # Risk and attack-path engine
│       ├── types.ts        # Rule/Issue schemas
│       ├── rules.ts        # Gremlin risk rules
│       ├── scoring.ts      # Risk scoring algorithm
│       ├── runner.ts       # Rule execution engine
│       └── index.ts        # Lambda handler
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
cd lambdas/risk-engine && npm install && cd ..
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
| `ISSUES_TABLE` | DynamoDB table for issues | SecurityIssues |

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
- HAS_IAM_ROLE, ALLOWS_ACCESS_TO, TRUSTS, RUNS_ON

## Risk Engine

The Risk Engine executes Gremlin traversals against the security graph to identify security issues. It runs on an EventBridge schedule (every 1 hour).

### Risk Rules (10 rules)

| Rule ID | Name | Severity |
|---------|------|----------|
| RULE-001 | Internet-Exposed EC2 with High-Privilege IAM Role to Restricted S3 | critical |
| RULE-002 | Security Groups with 0.0.0.0/0 on SSH/RDP | high |
| RULE-003 | Container Images with Critical CVEs on Internet-Exposed Workloads | critical |
| RULE-004 | Over-Privileged IAM Roles with Internet-Reachable Workloads | high |
| RULE-005 | Crown Jewel Attack Path from Internet | critical |
| RULE-006 | Cross-Account IAM Trust with Admin Privileges | critical |
| RULE-007 | Public S3 Buckets with Sensitive Data | critical |
| RULE-008 | RDS with Public Access and Sensitive Data | critical |
| RULE-009 | Lambda with VPC and Internet Gateway to Sensitive Resources | medium |
| RULE-010 | Secrets Manager Secrets with Overly Permissive IAM | high |

### Risk Scoring Formula

Risk score combines multiple factors (0-100 scale):

```
Score = CVSS×10×0.25 + Exposure×100×0.2 + Identity×100×0.2 + DataClass×100×0.2 + Env×100×0.15 + CrownJewelBonus
```

**Severity Thresholds:**
- Critical: ≥80
- High: ≥60
- Medium: ≥40
- Low: <40

### Running Risk Engine Locally

```bash
cd lambdas/risk-engine
MOCK_MODE=true npx ts-node index.ts
```

### Running Tests

```bash
cd lambdas/risk-engine
npm test
```

## Monitoring

- CloudWatch Logs: `/aws/lambda/*`
- Step Functions: SecurityGraphIngestion
- EventBridge: security-graph-*-trigger, risk-engine-scheduled-trigger rules
- DynamoDB: SecurityIssues table

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

### Manually trigger risk engine
```bash
aws lambda invoke --function-name RiskEngine-fn --payload '{}' response.json
```

### Query issues from DynamoDB
```bash
aws dynamodb query --table-name SecurityIssues --key-condition-expression "ruleId = :rid" --expression-attribute-values "{\":rid\":{\"S\":\"RULE-001\"}}"
```
