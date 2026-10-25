# Khalifa Architecture

## Data Flow

```
                               AWS Org (multi-account)
                                          │
                                          ▼
              ┌──────────────────────────────────────────────────────┐
              │  Step Functions State Machine (every 2h)             │
              │  + EventBridge → SQS → Incremental Updates           │
              └───────────────────────────┬──────────────────────────┘
                                          ▼
              ┌──────────────────────────────────────────────────────┐
              │  Collector Lambda (per account, per region)          │
              │  - STS AssumeRole → SecurityGraphCollectorRole       │
               │  - 30+ AWS service APIs                              │
               │  - Tag ingestion via ResourceGroupsTaggingAPI        │
               │  - Internet exposure derivation (incl. Lambda URLs)  │
               │  - Instance-profile role edges, generic secret inventory│
               │  - Cross-account trust analysis                      │
               │  - Bounded graph-writer batches + coverage checkpoint│
              └───────────────────────────┬──────────────────────────┘
                                          ▼
              ┌──────────────────────────────────────────────────────┐
              │  Graph Writer Lambda                                 │
              │  → Neptune (Gremlin)                                 │
              └───────────────────────────┬──────────────────────────┘
                                          ▼
              ┌──────────────────────────────────────────────────────┐
              │  Neptune Security Graph                              │
              │  - 50+ vertex labels                                 │
              │  - 30+ edge labels                                   │
              │  - Tag-derived properties (env, data_class)          │
              └────────────┬────────────────────────────┬────────────┘
                           ▼                            ▼
              ┌──────────────────────────────────────────────────────┐
              │  Risk Engine Lambda    │  │  Compliance Evaluators   │
              │  (every 1h)            │  │  (CIS + baseline)        │
               │  - 34 Gremlin rules    │  │  - per-control evaluators│
              │  - Risk scoring        │  │  - DynamoDB persistence  │
              └────────────┬───────────┘  └─────────────┬────────────┘
                           ▼                            ▼
              ┌────────────────────────┐  ┌──────────────────────────┐
              │  DynamoDB:             │  │  DynamoDB:               │
              │  SecurityIssues        │  │  ComplianceEvidence      │
              │                        │  │  ComplianceReports       │
              └────────────────────────┘  └──────────────────────────┘
                           │                            │
                           └─────────────┬──────────────┘
                                         ▼
              ┌──────────────────────────────────────────────────────┐
              │  api-service (Express on EKS)                        │
              │  - JWT/Cognito auth (jose)                           │
              │  - RBAC: Viewer/Analyst/Admin via Cognito groups     │
              │  - Gremlin query parameterization                    │
              └──────────────────────────┬───────────────────────────┘
                                         ▼
              ┌──────────────────────────────────────────────────────┐
               │  ui (Next.js)                                        │
               │  - /issues, /attack-paths, /secrets, /compliance     │
              │  - Cognito OIDC bearer tokens                        │
              └──────────────────────────────────────────────────────┘
```

## Workflow Map

The full set of concurrent workflows against one graph. Solid arrows are data flow; dashed edges are detection signals.

```mermaid
flowchart LR
    subgraph ORG["AWS Organization"]
        direction TB
        RES["Resources<br/>EC2 (IMDS options), EKS (endpoint config),<br/>KMS (rotation), CloudTrail trails,<br/>security groups (world-open, default)"]
        IAMRES["IAM<br/>users, access keys, MFA,<br/>policies, trusts"]
        SM["Secrets Manager<br/>+ resource policies"]
        GD["GuardDuty<br/>detectors"]
        SH["Security Hub<br/>active findings"]
        CT["CloudTrail logs<br/>(organization trail)"]
        CN["Canary credentials<br/>(permission-less decoys,<br/>tagged canary:true)"]
    end

    subgraph COLLECT["Collector: per account + region, every 2h"]
        direction TB
        STAGES["30+ service stages<br/>iam-access-keys<br/>iam-credential-report<br/>guardduty, securityhub"]
        TAGS["Tag extraction:<br/>env, data_classification,<br/>crown_jewel, canary, owner"]
        EXP["Exposure derivation:<br/>is_internet_exposed,<br/>EKS endpoint_world_open"]
    end

    subgraph DETECT["Detection pipelines"]
        direction TB
        CTA["CloudTrail Analyzer (daily)<br/>usage profile + anomaly queries:<br/>ROOT_USAGE, SECRET_READ_NEW_SOURCE_IP,<br/>ACCESS_DENIED_SPIKE, CANARY_USED"]
        DSPM["DSPM Scanner<br/>S3 objects + Lambda env vars<br/>(in-memory classification)"]
    end

    subgraph EVAL["Evaluation engines"]
        direction TB
        PE["Policy Evaluator (6h):<br/>effective permissions,<br/>escalation + pass-role paths"]
        LPS["Least-Privilege Sweep (daily):<br/>rightsizing vs CloudTrail usage"]
        RE["Risk Engine (hourly):<br/>34 rules, attack paths, scoring"]
        COMP["Compliance:<br/>CIS v3.0.0 + Khalifa baseline<br/>(Security Hub reconciliation)"]
    end

    subgraph STORE["State"]
        direction TB
        NEPTUNE[("Neptune security graph<br/>50+ vertex labels, 30+ edge labels")]
        ISSUES["DynamoDB:<br/>SecurityIssues, evidence,<br/>reports, findings, usage cache"]
    end

    subgraph SERVE["Serve"]
        direction LR
        API["REST API<br/>JWT auth (Cognito or<br/>verified Access JWT) + RBAC"]
        UI["Next.js UI"]
    end

    RES -->|"collect"| STAGES
    IAMRES -->|"decompose policies,<br/>keys, MFA, trusts"| STAGES
    SM -->|"GetResourcePolicy"| STAGES
    GD -->|"ListDetectors + features"| STAGES
    SH -->|"GetFindings"| STAGES
    CN -.->|"ingested + tagged"| STAGES

    STAGES --> TAGS
    STAGES --> EXP
    TAGS -->|"typed vertices + edges"| NEPTUNE
    EXP --> NEPTUNE

    CN -.->|"any API call"| CT
    CT -->|"Athena queries"| CTA
    CTA -->|"CloudTrailAnomaly vertices<br/>+ per-run reconcile"| NEPTUNE
    CTA -->|"usage cache"| ISSUES

    STAGES -.->|"sampled S3 objects<br/>and Lambda env vars"| DSPM
    DSPM -->|"DataClassificationFinding<br/>CLASSIFIES resource"| NEPTUNE

    NEPTUNE --> PE
    PE -->|"EffectivePermission vertices"| NEPTUNE
    ISSUES -->|"per-principal usage"| LPS
    NEPTUNE --> LPS
    LPS -->|"LeastPrivilegeFindings"| ISSUES

    NEPTUNE -->|"Gremlin rules RULE-001..034"| RE
    NEPTUNE -->|"control evaluators"| COMP
    RE -->|"issues + attack paths"| ISSUES
    COMP -->|"evidence + reports"| ISSUES

    ISSUES --> API
    NEPTUNE --> API
    API --> UI
```

> [!TIP]
> Reading the map: collection flows from the AWS Organization into the graph; the four detection and evaluation engines loop back over the live graph; all outputs converge in DynamoDB and are served through one RBAC-gated API. The canary credential (dashed) never does legitimate work: its only purpose is to show up in CloudTrail, which the analyzer converts into RULE-023.

## CloudTrail Analyzer

A scheduled Lambda (`lambdas/cloudtrail-analyzer`) runs daily (02:00 UTC) and executes Athena queries over the CloudTrail S3 logs with a configurable lookback window (default 90 days):

- **Usage profile:** per-principal event counts joined with IAM effective permissions by the least-privilege sweep (persisted to `AccessAnalyzerCache` with a 90-day TTL).
- **Anomaly queries:** root-identity activity, Secrets Manager reads from source IPs first seen within 7 days for principals with a longer activity history, and AccessDenied bursts (20+ per principal/IP). Anomalies are written as `CloudTrailAnomaly` vertices through the graph writer under the `cloudtrail-anomalies` reconcile scope, so each run removes anomalies that stop appearing. Detection feeds RULE-020, RULE-021, and RULE-022.
- **Canary tripwire:** when `CANARY_PRINCIPAL_ARNS` is set (populated automatically when the CDK stack deploys with `enableCanaries`), any CloudTrail activity from those principals produces a `CANARY_USED` anomaly. Canary keys are permission-less decoys stored in Secrets Manager (`khalifa-canary/credentials-1/2`) and tagged `canary: true`; their only purpose is to appear in CloudTrail when an attacker tries them. RULE-023 treats any use as a critical incident.

## Least-Privilege Sweep

A scheduled Lambda (`lambdas/least-privilege-sweep`) runs daily (03:00 UTC, after the CloudTrail analyzer) and iterates every `IamUser` and `IamRole` across all accounts. For each principal it joins the `EffectivePermission` vertex (Neptune) with actual usage from `AccessAnalyzerCache` (DynamoDB), computes a rightsizing recommendation via the shared `rightsizer` module, and persists the result to the `LeastPrivilegeFindings` table. Service-linked roles (`/aws-service-role/`) and principals with only AWS-managed policies are skipped.

## Compliance reconciliation and the trust center

The compliance job evaluates the CIS AWS Foundations v3.0.0 and Khalifa
baseline controls against the graph, then reconciles CIS with Security Hub:
it assumes the audit account's read-only reader role (granted through
`khalifa-data.securityhub_reader_role_arn`) and compares each requirement per
account (and Region for regional controls) with Security Hub's CIS v3.0.0
findings. The result is stored as a `CIS_RECONCILIATION` record in the reports
table: per-requirement Security Hub and Khalifa statuses, stability streaks and
the disagreeing accounts. None of that detail ever reaches the public page.

Publication follows Security Hub, the CIS v3.0.0 reference: a requirement is
publishable only when listed in `reconciliation.publishAllowlist` (empty by
default, so nothing is), Security Hub has a result with no missing data, and
its status (FAILED when any account/Region fails, otherwise PASSED) has held
for `reconciliation.minAgreementDays` with no gap in records. The Khalifa
comparison, disagreements and agreement streaks stay in the record for triage
but no longer block publication.
`GET /compliance/reconciliation/publishable` exposes exactly those
requirements as `{requirement, title, section, status}`, gated to the
Cloudflare Access service token identified by
`reconciliation.trustCenterSyncClientId`; staff roles, Admin included, cannot
call it.

The nightly `Trust center sync` workflow (`scripts/trust-center-sync`) reads
that endpoint, fails closed on `STALE`/`MISSING` records or transport errors,
and builds the static site in `trust-center/` (plain HTML/CSS, statuses only),
which is deployed to Cloudflare Pages. See
[OPERATIONAL.md](OPERATIONAL.md) section J.

Mapped frameworks (SOC 2, ISO 27001, PCI DSS v4.0, NIST SP 800-53 Rev. 5) do
not define their own catalogs: 52 curated requirements cite the canonical controls
(`packages/risk-engine/src/framework-citations.ts`), and their reports derive
from a single canonical assessment pass (no duplicate evaluators, no separate
evidence rows). The publishable endpoint publishes a mapped requirement only
while every mapped control is reconciliation-publishable (CIS) or assessed
PASS/FAIL in the latest Khalifa baseline report; manual or unevaluated controls
keep it off the page, and an unreadable baseline report leaves mapped
frameworks unpublished rather than failing the CIS response. The trust-center
site groups controls under each published framework, and its continuous-
monitoring statement (cadence plus the automatic-unpublish window) derives from
the endpoint's published `maxAgeHours`, so the public claim cannot drift from
the gate.

## Graph Schema

### Vertex Labels

| Label                       | AWS Service         | Required Properties                                                                                                                                                |
| --------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Internet`                  | (synthetic)         | `is_internet_exposed`                                                                                                                                              |
| `AwsAccount`                | (synthetic)         | `account_id`                                                                                                                                                       |
| `CollectionCoverage`        | (synthetic)         | `account_id`, `region`, `status`, `completed_at`                                                                                                                   |
| `ExternalAccount`           | IAM                 | `account_id`                                                                                                                                                       |
| `Ec2Instance`               | EC2                 | `arn`, `account_id`, `instance_type`, `state`, `public_ip`, `metadata_http_tokens`, `metadata_http_endpoint`, `metadata_http_limit_hop`                            |
| `NetworkInterface`          | EC2                 | `arn`, `subnet_id`, `vpc_id`                                                                                                                                       |
| `SecurityGroup`             | EC2                 | `arn`, `vpc_id`, `is_world_open`, `is_default`                                                                                                                     |
| `SecurityGroupRule`         | EC2                 | `protocol`, `port_from`, `port_to`, `port_range`, `cidr_block`                                                                                                     |
| `Vpc`                       | EC2                 | `arn`, `cidr_block`, `flow_logs_enabled`                                                                                                                           |
| `Subnet`                    | EC2                 | `arn`, `vpc_id`, `is_public`                                                                                                                                       |
| `InternetGateway`           | EC2                 | `arn`                                                                                                                                                              |
| `NatGateway`                | EC2                 | `arn`                                                                                                                                                              |
| `RouteTable`                | EC2                 | `arn`, `vpc_id`                                                                                                                                                    |
| `NetworkAcl`                | EC2                 | `arn`, `vpc_id`                                                                                                                                                    |
| `TransitGateway`            | EC2                 | `arn`                                                                                                                                                              |
| `S3Bucket`                  | S3                  | `arn`, `is_publicly_accessible`, `versioning_enabled`                                                                                                              |
| `IamUser`                   | IAM                 | `arn`, `password_enabled`, `mfa_enabled`, `likely_workload_identity_candidate`                                                                                     |
| `IamRole`                   | IAM                 | `arn`, `has_cross_account_trust`, `is_admin_role`                                                                                                                  |
| `IamPolicy`                 | IAM                 | `arn`                                                                                                                                                              |
| `IamPolicyDocument`         | IAM                 | `arn`, `policy_arn`, `document_json`, `policy_type`                                                                                                                |
| `IamPolicyStatement`        | IAM                 | `arn`, `effect`, `actions`, `resources`, `has_wildcard_resource`, `has_wildcard_action`, `grants_secret_read`, `secret_grant_scope`, `has_cross_account_principal` |
| `IamCredentialReport`       | IAM                 | `arn`, `generated_time`, `user_count`, `users_with_mfa`                                                                                                            |
| `AccessKey`                 | IAM                 | `arn`, `status`, `created_date`, `key_age_days`, `last_used_date`, `last_used_days_ago`                                                                            |
| `AccountPasswordPolicy`     | IAM                 | `min_password_length`, etc.                                                                                                                                        |
| `KmsKey`                    | KMS                 | `arn`, `key_state`, `key_manager`, `rotation_enabled`                                                                                                              |
| `RdsInstance`               | RDS                 | `arn`, `publicly_accessible`, `is_publicly_accessible`, `storage_encrypted`                                                                                        |
| `EksCluster`                | EKS                 | `arn`, `version`, `endpoint_public_access`, `endpoint_private_access`, `public_access_cidrs`, `endpoint_world_open`, `vpc_id`                                      |
| `EcrRepository`             | ECR                 | `arn`, `name`                                                                                                                                                      |
| `ContainerImage`            | ECR                 | `arn`, `digest`, `tag`                                                                                                                                             |
| `LoadBalancer`              | ELBv2               | `arn`, `scheme`, `is_internet_facing`                                                                                                                              |
| `Finding`                   | SecurityHub         | `severity`                                                                                                                                                         |
| `SecurityHub`               | Security Hub        | `arn`, `enabled`                                                                                                                                                   |
| `SecurityHubFinding`        | Security Hub        | `arn`, `severity`, `record_state`, `resource_arn`                                                                                                                  |
| `CloudTrailAnomaly`         | CloudTrail Analyzer | `arn`, `anomaly_type`, `principal_arn`, `source_ip`, `event_count`, `first_seen`, `last_seen`                                                                      |
| `CloudTrail`                | CloudTrail          | `is_multi_region_trail`, `is_organization_trail`                                                                                                                   |
| `ConfigRecorder`            | Config              | `arn`                                                                                                                                                              |
| `ConfigRule`                | Config              | `arn`                                                                                                                                                              |
| `GuardDutyDetector`         | GuardDuty           | `arn`, `status`                                                                                                                                                    |
| `AccessAnalyzer`            | IAM Access Analyzer | `arn`                                                                                                                                                              |
| `LambdaFunction`            | Lambda              | `arn`, `runtime`, `role`, `is_in_vpc`, `has_internet_access`, `function_url_auth_type`, `function_url_public`, `public_invoke_policy`                             |
| `LambdaAlias`               | Lambda              | `arn`                                                                                                                                                              |
| `ApiGateway`                | API Gateway         | `arn`, `endpoint_type`                                                                                                                                             |
| `ApiGatewayStage`           | API Gateway         | `arn`                                                                                                                                                              |
| `StateMachine`              | Step Functions      | `arn`                                                                                                                                                              |
| `EventBus`                  | EventBridge         | `arn`                                                                                                                                                              |
| `DynamoDBTable`             | DynamoDB            | `arn`, `encryption`, `point_in_time_recovery`                                                                                                                      |
| `ElastiCacheCluster`        | ElastiCache         | `arn`, `transit_encryption`                                                                                                                                        |
| `OpenSearchDomain`          | OpenSearch          | `arn`, `encryption_at_rest`                                                                                                                                        |
| `RedshiftCluster`           | Redshift            | `arn`, `publicly_accessible`                                                                                                                                       |
| `Secret`                    | Secrets Manager     | `arn`, `rotation_enabled`, `collection_restricted`, `days_since_rotation`, `days_since_access`                                                                     |
| `Parameter`                 | SSM Parameter Store | `arn`, `type`, `collection_restricted`                                                                                                                             |
| `BackupVault`               | AWS Backup          | `arn`                                                                                                                                                              |
| `BackupPlan`                | AWS Backup          | `arn`                                                                                                                                                              |
| `HostedZone`                | Route53             | `arn`                                                                                                                                                              |
| `DataClassificationFinding` | DSPM Scanner        | `arn`, `pii_types`, `secret_count`, `skipped_kms`, `data_classification`, `data_class_source`, `confidence`, `classifier`                                          |
| `EffectivePermission`       | Policy Evaluator    | `principal_arn`, `allowed_actions`, `denied_actions`, `is_admin`, `blast_radius`                                                                                   |
| `EscalationPath`            | Policy Evaluator    | `source_arn`, `target_arn`, `risk_level`, `escalation_type`                                                                                                        |

### Edge Labels

| Edge                           | Meaning                                                         |
| ------------------------------ | --------------------------------------------------------------- |
| `EXPOSES`                      | Internet → IGW/LB/ExternalAccount                               |
| `CONTAINS`                     | VPC → Subnet/Instance; Account → Resource; Policy → Statement   |
| `ATTACHED_TO`                  | ENI → Instance; IGW → VPC; IAMPrincipal → Policy                |
| `PROTECTS`                     | SecurityGroup → NetworkInterface                                |
| `PART_OF`                      | SecurityGroupRule → SecurityGroup                               |
| `HAS_IAM_ROLE`                 | EC2/Lambda → IAMRole                                            |
| `GRANTS`                       | IamPolicyStatement → Resource (non-wildcard)                    |
| `TRUSTS`                       | IAMRole → ExternalAccount/Principal                             |
| `OWNS`                         | Account root → Resource                                         |
| `HAS_FINDING`                  | Account → SecurityHub/AccessAnalyzer finding                    |
| `HAS_ACCESS_KEY`               | IamUser → AccessKey                                             |
| `HAS_RESOURCE_POLICY`          | Secret → IamPolicyDocument                                      |
| `DETECTS_ON`                   | SecurityHubFinding → collected resource                         |
| `HAS_STATUS`                   | CloudTrail → CloudTrailStatus                                   |
| `IN_SUBNET`                    | LB/NatGW → Subnet                                               |
| `HAS_ENDPOINT`                 | VPC → VPC Endpoint                                              |
| `HAS_NACL` / `HAS_ROUTE_TABLE` | VPC → NACL/RouteTable                                           |
| `MEMBER_OF`                    | IamUser → IamGroup                                              |
| `CAN_ESCALATE_TO`              | IAMPrincipal → IAMRole (assume hops, or a `pass_role` compute link) |
| `SHARES_WITH`                  | IamPolicyStatement → AwsAccount (cross-account share)           |
| `BELONGS_TO`                   | ContainerImage → EcrRepository                                  |
| `RUNS_ON`                      | ContainerImage → workload (not yet created)                     |
| `HAS_CVE`                      | ContainerImage → Vulnerability (not yet created)                |
| `HAS_ALIAS` / `HAS_STAGE`      | Function → Alias/Stage                                          |
| `CLASSIFIES`                   | DataClassificationFinding → S3Bucket/RdsInstance/LambdaFunction |

### Risk Rule Properties (queried by Gremlin rules)

| Property                                         | Type             | Source                              |
| ------------------------------------------------ | ---------------- | ----------------------------------- |
| `is_internet_exposed`                            | boolean          | Collector exposure derivation       |
| `is_publicly_accessible`                         | boolean          | S3/RDS direct fetch                 |
| `is_in_vpc`                                      | boolean          | Lambda VPC config                   |
| `has_internet_access`                            | boolean          | Lambda VPC config (inverse)         |
| `crown_jewel`                                    | boolean          | `crown_jewel` tag                   |
| `data_classification`                            | string           | `data_classification` tag           |
| `env`                                            | string           | `env` or `environment` tag          |
| `has_cross_account_trust`                        | boolean          | IAM trust analysis                  |
| `has_wildcard_resource`                          | boolean          | IAM policy statement analysis       |
| `has_wildcard_action`                            | boolean          | IAM policy statement analysis       |
| `grants_secret_read` / `secret_grant_scope`      | boolean / string | IAM policy statement analysis       |
| `mfa_enabled` / `password_enabled`               | boolean          | IAM MFA devices and login profiles  |
| `key_age_days` / `last_used_days_ago`            | number           | IAM access key collection           |
| `endpoint_public_access` / `endpoint_world_open` | boolean          | EKS `resourcesVpcConfig`            |
| `function_url_public` / `public_invoke_policy`   | boolean          | Lambda function URLs and invoke policies |
| `lambda_exposure_restricted`                     | boolean          | Lambda reads the collector role cannot make  |
| `principal_is_anyone` / `principal_account_count` | boolean / number | IAM policy statement principal analysis |
| `principal_org_restricted`                       | boolean          | `aws:PrincipalOrgID` condition on a statement |
| `is_prod`                                        | boolean          | `PROD_ACCOUNT_IDS` account marking  |
| `anomaly_type`                                   | string           | CloudTrail analyzer anomaly queries |
| `port_from` / `port_to`                          | number           | Security group rule                 |
| `flow_logs_enabled`                              | boolean          | EC2 DescribeFlowLogs                |

## Authentication

- **Cognito User Pool** authenticates users; **Cognito Groups** (`khalifa-admin`, `khalifa-analyst`, `khalifa-viewer`) drive RBAC
- **Cloudflare Access** (optional): when `CLOUDFLARE_ACCESS_TEAM_DOMAIN` and `CLOUDFLARE_ACCESS_AUD` are set, the API verifies the `cf-access-jwt-assertion` JWT against the team's Access JWKS and maps verified identities from the configured trusted email domain to Viewer/Analyst (never Admin without a Cognito `khalifa-admin` group)
- **JWKS verification** in api-service via `jose`; email-only headers are never trusted and unauthenticated requests fail closed (`AUTH_NOT_CONFIGURED` when neither provider is configured)
- **ALB OIDC** (EKS deployment) for browser-based UI auth; API service enforces JWT independently

## Deployment Topologies

| Topology                    | Use Case                 | Tradeoffs                    |
| --------------------------- | ------------------------ | ---------------------------- |
| **Lambda + Step Functions** | Small orgs, <50 accounts | Lower operational overhead   |
| **EKS + CronJob**           | Large orgs, >50 accounts | Better scaling, more control |
