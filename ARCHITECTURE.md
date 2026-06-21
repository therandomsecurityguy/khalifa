# Khalifa Architecture

## Data Flow

```
                              AWS Org (multi-account)
                                       │
                                       ▼
              ┌──────────────────────────────────────────────┐
              │  Step Functions State Machine (every 2h)     │
              │  + EventBridge → SQS → Incremental Updates   │
              └─────────────┬──────────────────────────────┘
                            ▼
              ┌──────────────────────────────────────────────┐
              │  Collector Lambda (per account, per region)  │
              │  - STS AssumeRole → SecurityGraphCollectorRole│
              │  - 25+ AWS service APIs                        │
              │  - Tag ingestion via ResourceGroupsTaggingAPI │
              │  - Internet exposure derivation               │
              │  - Cross-account trust analysis                │
              └─────────────┬──────────────────────────────┘
                            ▼
              ┌──────────────────────────────────────────────┐
              │  Graph Writer Lambda                          │
              │  → Neptune (Gremlin)                          │
              └─────────────┬──────────────────────────────┘
                            ▼
              ┌──────────────────────────────────────────────┐
              │  Neptune Security Graph                       │
              │  - 50+ vertex labels                          │
              │  - 30+ edge labels                            │
              │  - Tag-derived properties (env, data_class)   │
              └────────┬─────────────────────┬───────────────┘
                       ▼                     ▼
        ┌──────────────────────┐   ┌────────────────────────┐
        │  Risk Engine Lambda  │   │  Compliance Evaluators  │
        │  (every 1h)          │   │  (CIS/SOC2/ISO27001)    │
        │  - 10 Gremlin rules  │   │  - 124 controls         │
        │  - Risk scoring      │   │  - DynamoDB persistence │
        └──────────┬───────────┘   └────────────┬───────────┘
                   ▼                           ▼
        ┌──────────────────────┐   ┌────────────────────────┐
        │  DynamoDB:           │   │  DynamoDB:             │
        │  SecurityIssues      │   │  ComplianceEvidence    │
        │                      │   │  ComplianceReports     │
        └──────────┬───────────┘   └────────────┬───────────┘
                   ▼                           ▼
        ┌─────────────────────────────────────────────────┐
        │  api-service (Express on EKS)                    │
        │  - JWT/Cognito auth (jose)                       │
        │  - RBAC: Viewer/Analyst/Admin via Cognito groups │
        │  - Gremlin query parameterization                 │
        └─────────────┬───────────────────────────────────┘
                      ▼
        ┌─────────────────────────────────────────────────┐
        │  ui (Next.js)                                    │
        │  - /issues, /attack-paths, /compliance/[framework]│
        │  - Cognito OIDC bearer tokens                    │
        └─────────────────────────────────────────────────┘
```

## Graph Schema

### Vertex Labels

| Label | AWS Service | Required Properties |
|-------|-------------|---------------------|
| `Internet` | (synthetic) | `is_internet_exposed` |
| `AwsAccount` | (synthetic) | `account_id` |
| `ExternalAccount` | IAM | `account_id` |
| `Ec2Instance` | EC2 | `arn`, `account_id`, `instance_type`, `state`, `public_ip` |
| `NetworkInterface` | EC2 | `arn`, `subnet_id`, `vpc_id` |
| `SecurityGroup` | EC2 | `arn`, `vpc_id`, `is_world_open` |
| `SecurityGroupRule` | EC2 | `protocol`, `port_range`, `cidr_block` |
| `Vpc` | EC2 | `arn`, `cidr_block`, `flow_logs_enabled` |
| `Subnet` | EC2 | `arn`, `vpc_id`, `is_public` |
| `InternetGateway` | EC2 | `arn` |
| `NatGateway` | EC2 | `arn` |
| `RouteTable` | EC2 | `arn`, `vpc_id` |
| `NetworkAcl` | EC2 | `arn`, `vpc_id` |
| `TransitGateway` | EC2 | `arn` |
| `S3Bucket` | S3 | `arn`, `is_publicly_accessible`, `versioning_enabled` |
| `IamUser` | IAM | `arn`, `password_enabled`, `mfa_enabled` |
| `IamRole` | IAM | `arn`, `has_cross_account_trust`, `is_admin_role` |
| `IamPolicy` | IAM | `arn` |
| `AccountPasswordPolicy` | IAM | `min_password_length`, etc. |
| `KmsKey` | KMS | `arn`, `key_state` |
| `RdsInstance` | RDS | `arn`, `publicly_accessible`, `storage_encrypted` |
| `EksCluster` | EKS | `arn`, `version` |
| `EcrRepository` | ECR | `arn`, `name` |
| `ContainerImage` | ECR | `arn`, `digest`, `tag` |
| `LoadBalancer` | ELBv2 | `arn`, `scheme`, `is_internet_facing` |
| `Finding` | SecurityHub | `severity` |
| `CloudTrail` | CloudTrail | `is_multi_region_trail` |
| `ConfigRecorder` | Config | `arn` |
| `ConfigRule` | Config | `arn` |
| `GuardDutyDetector` | GuardDuty | `arn`, `status` |
| `AccessAnalyzer` | IAM Access Analyzer | `arn` |
| `LambdaFunction` | Lambda | `arn`, `runtime`, `role` |
| `LambdaAlias` | Lambda | `arn` |
| `ApiGateway` | API Gateway | `arn`, `endpoint_type` |
| `ApiGatewayStage` | API Gateway | `arn` |
| `StateMachine` | Step Functions | `arn` |
| `EventBus` | EventBridge | `arn` |
| `DynamoDBTable` | DynamoDB | `arn`, `encryption`, `point_in_time_recovery` |
| `ElastiCacheCluster` | ElastiCache | `arn`, `transit_encryption` |
| `OpenSearchDomain` | OpenSearch | `arn`, `encryption_at_rest` |
| `RedshiftCluster` | Redshift | `arn`, `publicly_accessible` |
| `Secret` | Secrets Manager | `arn`, `rotation_enabled` |
| `Parameter` | SSM Parameter Store | `arn`, `type` |
| `BackupVault` | AWS Backup | `arn` |
| `BackupPlan` | AWS Backup | `arn` |
| `HostedZone` | Route53 | `arn` |

### Edge Labels

| Edge | Meaning |
|------|---------|
| `EXPOSES` | Internet → IGW/LB/ExternalAccount |
| `CONTAINS` | VPC → Subnet/Instance; Account → Resource |
| `ATTACHED_TO` | ENI → Instance; IGW → VPC |
| `PROTECTS` | SecurityGroup → NetworkInterface |
| `PART_OF` | Rule → SecurityGroup |
| `ALLOWS_INGRESS` | SG rule → SG (legacy compatibility) |
| `HAS_IAM_ROLE` | Instance → IAMRole |
| `ALLOWS_ACCESS_TO` | IAMRole → Resource |
| `CONTAINS` | (also: Policy → Statement) |
| `TRUSTS` | IAMRole → ExternalAccount |
| `OWNS` | Account root → Resource |
| `HAS_FINDING` | Account → SecurityHub finding |
| `HAS_STATUS` | CloudTrail → CloudTrailStatus |
| `IN_SUBNET` | LB/NatGW → Subnet |
| `HAS_ENDPOINT` | VPC → VPC Endpoint |
| `HAS_NACL` / `HAS_ROUTE_TABLE` | VPC → NACL/RouteTable |
| `BELONGS_TO` | ContainerImage → EcrRepository |
| `RUNS_ON` | ContainerImage → workload (Phase 1) |
| `HAS_ALIAS` / `HAS_STAGE` | Function → Alias/Stage |

### Risk Rule Properties (queried by Gremlin rules)

| Property | Type | Source |
|----------|------|--------|
| `is_internet_exposed` | boolean | Collector derivation |
| `crown_jewel` | boolean | `crown_jewel` tag |
| `data_classification` | string | `data_classification` tag |
| `env` | string | `env` or `environment` tag |
| `is_publicly_accessible` | boolean | S3/RDS direct fetch |
| `has_cross_account_trust` | boolean | IAM trust analysis |

## Authentication

- **Cognito User Pool** authenticates users
- **Cognito Groups** (`khalifa-admin`, `khalifa-analyst`, `khalifa-viewer`) drive RBAC
- **JWKS verification** in api-service via `jose`
- **ALB OIDC** (EKS deployment) for browser-based UI auth; API service enforces JWT independently

## Deployment Topologies

| Topology | Use Case | Tradeoffs |
|----------|----------|-----------|
| **Lambda + Step Functions** | Small orgs, <50 accounts | Lower operational overhead |
| **EKS + CronJob** | Large orgs, >50 accounts | Better scaling, more control |