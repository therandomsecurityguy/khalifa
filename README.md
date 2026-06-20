# Khalifa
Agentless ingestion of AWS Org resources and Security Hub findings into a Neptune-backed security graph, with a risk and attack-path engine, CIEM (Cloud Infrastructure Entitlement Management) for effective permissions, and automated compliance reporting.

## Architecture

### Lambda-Based Ingestion

```
EventBridge Schedule (every 2 hours)
    |
    v
Step Functions State Machine
    |
    +-- ListAccounts Lambda
    +-- MapAccounts (parallel per account)
          |
          v
Collector Lambda (per account)
     +-- STS assume role into target account
     +-- Collect: EC2, S3, IAM, KMS, RDS, EKS, SecurityHub,
     |       CloudTrail, Config, GuardDuty, Access Analyzer,
     |       VPC Endpoints, NACLs, Route Tables, Transit Gateway,
     |       Route53, API Gateway, Lambda, Step Functions,
     |       EventBridge, DynamoDB, ElastiCache, OpenSearch,
     |       Redshift, Secrets Manager, Parameter Store, Backup
     +-- Enhanced IAM: Groups, inline policies, managed policy
     |   documents, trust policies, permission boundaries,
     |   policy statement decomposition
     +-- GraphWriter Lambda -> Neptune
     +-- PolicyEvaluator Lambda -> Neptune (EffectivePermission
         & EscalationPath nodes)

CloudTrail Analyzer (daily at 02:00 UTC)
    |
    v
EventBridge Schedule -> CloudTrailAnalyzer Lambda
    +-- Athena queries against CloudTrail S3 logs (90-day window)
    +-- Writes usage data to AccessAnalyzerCache DynamoDB table

Policy Evaluator (every 6 hours + after collector)
    |
    v
EventBridge Schedule / Step Function -> PolicyEvaluator Lambda
    +-- Resolves effective permissions per principal
    +-- Detects escalation paths (max 3 hops)
    +-- Pre-computes EffectivePermission & EscalationPath nodes

Event-Driven (incremental updates)
    |
    v
EventBridge -> SQS Queue -> IncrementalProcessor Lambda -> Neptune

Risk Engine (every 1 hour)
    |
    v
EventBridge Schedule -> RiskEngine Lambda -> Neptune (query)
    |
    +-- Risk Rules (10 rules)
    +-- Compliance Evaluators (40+ evaluators)
    |
    v
DynamoDB (Issues table)
```

### EKS-Based Deployment

```
User -> ALB (Cognito OIDC) -> api-service (EKS)
                                      |
                    +-----------------+-----------------+
                    v                 v                 v
Neptune            DynamoDB           CloudWatch
              (Graph DB)    (Issues + AccessAnalyzer)  (Logs)
                    |
                    v
         rule-runner CronJob
              (every 6h)
                    |
                    v
              Neptune queries
                    |
                    +-- Risk rules
                    +-- Compliance evaluators
                    v
              DynamoDB (Issues)
```

## Two Deployment Options

| Approach | Use Case | Complexity |
|----------|----------|------------|
| Lambda + EventBridge | Development/Small scale | Lower |
| EKS + CronJob | Production (>20 accounts) | Higher |

---

## Quick Start: EKS Deployment (Recommended)

### Prerequisites

- Node.js 20+
- AWS CDK CLI
- kubectl configured for your EKS cluster
- Docker for building container images

### 1. Build and Push Container Images

```bash
# API Service
cd api-service
npm install
npm run build
docker build -t security-graph-api:latest .
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/security-graph-api:v1.0.0

# Rule Runner (reuses risk-engine)
cd ../packages/risk-engine
npm install
npm run build
docker build -t security-graph-rule-runner:latest .
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/security-graph-rule-runner:v1.0.0
```

### 2. Deploy EKS Infrastructure (CDK)

```bash
cd cdk
npm install
npm run build

cdk deploy SecurityGraphEksStack \
  --vpc-id vpc-12345678 \
  --neptune-endpoint neptune-cluster.us-east-1.amazonaws.com \
  --issues-table-name SecurityIssues \
  --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/xxxxx \
  --cognito-user-pool-id us-east-1_xxxxx \
  --cognito-client-id xxxxx
```

### 3. Deploy Kubernetes Manifests

```bash
# Update ConfigMap with your values
# Edit eks-manifests/01-configmap.yaml

# Deploy all manifests
kubectl apply -f eks-manifests/

# Verify deployment
kubectl rollout status deployment/api-service -n security-graph
kubectl get pods -n security-graph
```

### 4. Verify API

```bash
# Get ALB hostname
kubectl get ingress -n security-graph

# Test health endpoint
curl https://<alb-hostname>/health

# Test issues endpoint
curl https://<alb-hostname>/issues

# Test compliance endpoint
curl https://<alb-hostname>/compliance/frameworks
```

---

## API Endpoints

### Issues & Risk

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check (unauthenticated) |
| `GET /issues` | List issues with filters (Viewer+) |
| `GET /issues/:id` | Get issue details with attack path (Viewer+) |
| `GET /issues/counts` | Get issue counts by severity (Viewer+) |
| `GET /issues/stats` | Get detailed statistics (Viewer+) |
| `GET /attack-paths?fromSelector=X&toSelector=Y` | Find attack paths (Viewer+) |
| `GET /resources/:arn` | Get resource with neighbors and issues (Viewer+) |
| `GET /resources/search?label=EC2Instance` | Search resources (Viewer+) |

### Compliance

| Endpoint | Description |
|----------|-------------|
| `GET /compliance/frameworks` | List available compliance frameworks (Viewer+) |
| `GET /compliance/frameworks/:framework` | Get framework overview with control summaries (Viewer+) |
| `GET /compliance/frameworks/:framework/controls` | List all controls for a framework (Viewer+) |
| `GET /compliance/frameworks/:framework/controls/:controlId` | Get control details with evidence (Viewer+) |
| `GET /compliance/frameworks/:framework/report` | Generate compliance report (Viewer+) |
| `GET /compliance/frameworks/:framework/drift` | Detect configuration drift since last evaluation (Viewer+) |

> All routes (except `/health`) require a valid Cognito bearer JWT. RBAC roles are mapped from Cognito groups: `khalifa-admin` → Admin, `khalifa-analyst` → Analyst, `khalifa-viewer` → Viewer.

### CIEM / Identity

| Endpoint | Description |
|----------|-------------|
| `GET /identity/effective-permissions/:principal` | Get computed effective permissions for a principal |
| `GET /identity/escalation-paths` | List detected escalation paths with filters |
| `GET /identity/unused-permissions?principal=X&days=90` | Find unused permissions by comparing effective perms vs CloudTrail usage |
| `GET /identity/rightsizing/:principal?safetyMarginDays=7` | Generate least-privilege policy recommendation |
| `GET /identity/trust-graph?account=X` | Retrieve cross-account trust relationships as a graph |

### Query Parameters for /issues

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string[] | Filter by severity (critical, high, medium, low) |
| `team` | string[] | Filter by owning team |
| `status` | string[] | Filter by status (open, resolved, suppressed) |
| `ruleId` | string | Filter by rule ID |
| `limit` | number | Max results (default: 50, max: 1000) |
| `nextToken` | string | Pagination token |

### Example: Get Critical Issues

```bash
curl "https://api.example.com/issues?severity=critical&status=open&limit=100" \
  -H "Authorization: Bearer $TOKEN"
```

### Example: Find Attack Paths

```bash
curl "https://api.example.com/attack-paths?fromSelector=Internet&toSelector=S3Bucket&maxPathLength=4" \
  -H "Authorization: Bearer $TOKEN"
```

### Example: Check CIS Compliance

```bash
# List frameworks
curl "https://api.example.com/compliance/frameworks" \
  -H "Authorization: Bearer $TOKEN"

# Get CIS report
curl "https://api.example.com/compliance/CIS_AWS_FOUNDATIONS/report" \
  -H "Authorization: Bearer $TOKEN"

# Check for drift
curl "https://api.example.com/compliance/CIS_AWS_FOUNDATIONS/drift" \
  -H "Authorization: Bearer $TOKEN"
```

### Example: CIEM / Identity Queries

```bash
# Get effective permissions for a role
curl "https://api.example.com/identity/effective-permissions/arn:aws:iam::123456:role/AdminRole" \
  -H "Authorization: Bearer $TOKEN"

# Find critical escalation paths
curl "https://api.example.com/identity/escalation-paths?riskLevel=critical" \
  -H "Authorization: Bearer $TOKEN"

# Check unused permissions (90-day window)
curl "https://api.example.com/identity/unused-permissions?principal=arn:aws:iam::123456:role/DataRole&days=90" \
  -H "Authorization: Bearer $TOKEN"

# Get rightsizing recommendation
curl "https://api.example.com/identity/rightsizing/arn:aws:iam::123456:role/DataRole?safetyMarginDays=7&includeReadonlySafe=true" \
  -H "Authorization: Bearer $TOKEN"

# View cross-account trust graph
curl "https://api.example.com/identity/trust-graph?account=123456789012" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Compliance Frameworks

Khalifa includes automated compliance evaluation against three industry-standard frameworks with 124 controls and 40+ automated evaluators that run Gremlin graph queries against your security data.

### CIS AWS Foundations Benchmark v3.0 (78 controls)

Covers the foundational security configurations for AWS accounts:

| Section | Controls | Focus |
|---------|----------|-------|
| 1. IAM | 18 | Root account, MFA, password policy, access keys |
| 2. Logging | 10 | CloudTrail, Config, S3 logging |
| 3. Monitoring | 28 | CloudWatch alarms, GuardDuty, Config rules |
| 4. Networking | 12 | VPC flow logs, security groups, NACLs |
| 5. Data Protection | 10 | Encryption, KMS rotation, backup |

### SOC 2 Type II (22 controls)

Maps to Trust Services Criteria:

| Section | Controls | Focus |
|---------|----------|-------|
| CC6 | 8 | Logical access, authentication, authorization |
| CC7 | 6 | Monitoring, incident response, change management |
| CC8 | 4 | Risk mitigation, system boundaries |
| CC9 | 4 | Additional criteria |

### ISO 27001:2022 (24 controls)

Based on Annex A controls:

| Section | Controls | Focus |
|---------|----------|-------|
| A.5 | 4 | Organizational controls, policies |
| A.6 | 4 | People controls, onboarding, training |
| A.8 | 6 | Technological controls, encryption, logging |
| A.9 | 4 | Physical and environmental security |
| A.12 | 3 | Operations security, vulnerability management |
| A.13 | 3 | Communications security, network controls |

### How It Works

1. **Collector** ingests AWS resource configurations into the Neptune graph
2. **Compliance Engine** runs evaluators that query the graph to check each control
3. Each evaluator produces evidence (pass/fail/manual) with resource-level details
4. Results are stored in DynamoDB and exposed via the API
5. **UI** shows a dashboard with filterable controls, evidence, and CSV export

---

## Project Structure

```
khalifa/
├── cdk/                          # CDK infrastructure
│   ├── bin/khalifa.ts            # Lambda stack entry
│   └── lib/
│       ├── khalifa-stack.ts      # Lambda + EventBridge stack
│       └── eks-infrastructure.ts # EKS stack
├── lambdas/
│   ├── shared/                   # Shared types and utilities
│   ├── list-accounts/            # Lists org accounts
│   ├── collector/                # Collects AWS resources (30 services)
│   │                              # Enhanced IAM: groups, policies, trust docs
│   ├── graph-writer/             # Writes to Neptune
│   ├── incremental-collector/    # Event-driven updates
│   ├── policy-evaluator/         # CIEM: effective permissions engine
│   │   ├── types.ts              # EffectivePermission, EscalationPath, etc.
│   │   ├── policy-parser.ts      # IAM policy JSON parsing, wildcard matching
│   │   ├── condition-evaluator.ts # 20+ IAM condition operators
│   │   ├── effect-resolver.ts    # Policy merge → net effective permissions
│   │   ├── escalation-detector.ts # Trust graph traversal, escalation paths
│   │   ├── rightsizer.ts         # Unused permissions, rightsizing recommendations
│   │   └── index.ts              # Lambda handler (Neptune read/write)
│   ├── cloudtrail-analyzer/      # CloudTrail log analysis via Athena
│   │   └── index.ts              # Athena queries → DynamoDB cache
├── packages/
│   └── risk-engine/              # Risk, attack-path, and compliance engine
│       ├── types.ts              # Rule/Issue schemas
│       ├── rules.ts              # Gremlin risk rules (10)
│       ├── scoring.ts            # Risk scoring algorithm
│       ├── runner.ts             # Rule execution engine
│       ├── compliance-types.ts   # Compliance schemas (124 controls)
│       ├── compliance-rules.ts   # Automated evaluators (40+)
│       └── compliance-engine.ts  # Compliance evaluation engine
├── api-service/                  # REST API (EKS)
│   ├── src/
│   │   ├── app.ts               # Express server
│   │   ├── routes/
│   │   │   ├── issues.ts        # Issue endpoints
│   │   │   ├── attack-paths.ts  # Attack path endpoints
│   │   │   ├── resources.ts     # Resource endpoints
│   │   │   ├── compliance.ts    # Compliance endpoints
│   │   │   └── identity.ts      # CIEM/identity endpoints
│   │   ├── services/            # Neptune/DynamoDB clients
│   │   └── types/               # TypeScript interfaces
│   └── package.json
├── eks-manifests/               # Kubernetes manifests
│   ├── 00-namespace.yaml
│   ├── 01-configmap.yaml
│   ├── 02-serviceaccounts.yaml
│   ├── 03-api-deployment.yaml
│   ├── 04-api-service.yaml
│   ├── 05-api-ingress.yaml
│   ├── 06-rule-runner-cronjob.yaml
│   ├── 07-hpa.yaml
│   └── 08-network-policy.yaml
├── ui/                          # Next.js UI
│   ├── app/
│   │   ├── issues/              # Issues dashboard
│   │   ├── attack-paths/        # Attack path explorer
│   │   └── compliance/          # Compliance dashboard
│   │       ├── page.tsx         # Framework overview
│   │       └── [framework]/     # Framework-specific pages
│   │           ├── page.tsx           # Controls list
│   │           ├── controls/[controlId]/page.tsx  # Control detail
│   │           ├── report/page.tsx    # Compliance report
│   │           └── drift/page.tsx     # Drift detection
│   ├── lib/api.ts               # API client
│   └── types/index.ts           # UI types
├── .github/workflows/
│   ├── ci.yml                   # CI: lint, typecheck, build, test
│   └── release.yml              # Manual release workflow
└── templates/
    └── SecurityGraphCollectorRole.yaml  # Cross-account role
```

---

## AWS Services Collected

The collector ingests configuration data from 30 AWS services:

| Category | Services |
|----------|---------|
| Compute | EC2, EKS, Lambda (aliases + event source mappings) |
| Storage | S3 (versioning, encryption, logging, public access block) |
| Database | RDS, DynamoDB, ElastiCache, OpenSearch, Redshift |
| Identity | IAM (users, roles, policies, groups, inline policies, managed policy documents, trust policies, permission boundaries, credential reports), KMS |
| Network | VPC, VPC Endpoints, NACLs, Route Tables, Transit Gateway, Route53 |
| Security | SecurityHub, GuardDuty, Access Analyzer, Config |
| Logging | CloudTrail, Config |
| Serverless | API Gateway, Step Functions, EventBridge |
| Secrets | Secrets Manager, Parameter Store |
| Backup | Backup Vaults, Backup Plans |

---

## Risk Engine Rules

The Risk Engine executes Gremlin traversals against the security graph to identify security issues.

### Risk Rules (10 rules)

| Rule ID | Name | Severity |
|---------|------|----------|
| RULE-001 | Internet-Exposed EC2 with High-Privilege IAM Role to Restricted S3 | critical |
| RULE-002 | Security Groups with 0.0.0.0/0 on SSH/RDP | high |
| RULE-003 | Container Images with Critical CVEs on Internet-Exposed Workloads | critical |
| RULE-004 | Over-Privileged IAM Roles with Internet-Reachable Workloads | high |
| RULE-005 | Crown Jewel Attack Path from Internet | critical |
| RULE-006 | Cross-Account IAM Trust with Admin Privileges | critical | *Enhanced by CIEM escalation detector* |
| RULE-007 | Public S3 Buckets with Sensitive Data | critical |
| RULE-008 | RDS with Public Access and Sensitive Data | critical |
| RULE-009 | Lambda with VPC and Internet Gateway to Sensitive Resources | medium |
| RULE-010 | Secrets Manager Secrets with Overly Permissive IAM | high |

### Risk Scoring Formula

Risk score combines multiple factors (0-100 scale):

```
Score = CVSSx10x0.25 + Exposurex100x0.2 + Identityx100x0.2 + DataClassx100x0.2 + Envx100x0.15 + CrownJewelBonus
```

**Severity Thresholds:**
- Critical: >=80
- High: >=60
- Medium: >=40
- Low: <40

---

## UI Usage

### Start Development Server

```bash
cd ui
npm install
npm run dev
```

Navigate to:
- `http://localhost:3000/issues` - Issues dashboard
- `http://localhost:3000/issues/:id` - Issue details with attack path
- `http://localhost:3000/attack-paths` - Attack path explorer
- `http://localhost:3000/compliance` - Compliance framework overview
- `http://localhost:3000/compliance/CIS_AWS_FOUNDATIONS` - CIS controls list
- `http://localhost:3000/compliance/CIS_AWS_FOUNDATIONS/controls/1.4` - Control detail with evidence
- `http://localhost:3000/compliance/CIS_AWS_FOUNDATIONS/report` - Compliance report (CSV export)
- `http://localhost:3000/compliance/CIS_AWS_FOUNDATIONS/drift` - Configuration drift view

### Authentication

The UI uses OIDC via Cognito. Tokens are stored in localStorage and passed to the API via the `Authorization: Bearer` header.

---

## CI/CD

### GitHub Actions Workflows

**CI** (`.github/workflows/ci.yml`) runs on push/PR to main:

- **Lint & Format** - ESLint and Prettier across all workspaces
- **TypeCheck** - TypeScript compilation for all packages
- **Build** - Build all workspaces
- **Test** - Run unit tests

**Release** (`.github/workflows/release.yml`) triggered manually:

- Builds container images for API service and rule runner
- Pushes to ECR
- Creates GitHub release with version tag

### Local Development

```bash
# Install all dependencies
npm ci --workspaces

# Run across all workspaces
npm run lint          # Lint all packages
npm run format        # Format all packages
npm run format:check  # Check formatting
npm run build         # Build all packages
npm run test          # Run all tests

# Build a specific package
npm run build:api
npm run build:cdk
npm run build:ui
npm run build:lambdas
```

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEPTUNE_ENDPOINT` | Neptune cluster endpoint | - |
| `NEPTUNE_AUTH_SECRET_ARN` | Secrets Manager ARN for Neptune auth | - |
| `ISSUES_TABLE` | DynamoDB table for issues | SecurityIssues |
| `ACCESS_ANALYZER_TABLE` | DynamoDB table for CloudTrail usage cache | AccessAnalyzerCache |
| `ATHENA_DATABASE` | Glue database for CloudTrail logs | khalifa_cloudtrail_db |
| `ATHENA_WORKGROUP` | Athena workgroup | khalifa-cloudtrail-analysis |
| `CLOUDTRAIL_S3_LOCATION` | S3 prefix for CloudTrail logs | s3://cloudtrail-logs/AWSLogs/ |
| `ANALYSIS_DAYS` | CloudTrail lookback window | 90 |
| `AWS_REGION` | AWS region | us-east-1 |
| `LOG_LEVEL` | Logging level | info |
| `RULE_RUNNER_SCHEDULE` | Cron schedule | `0 */6 * * *` (every 6h) |

### Kubernetes ConfigMap

Edit `eks-manifests/01-configmap.yaml` before deployment:

```yaml
data:
  NEPTUNE_ENDPOINT: "neptune-cluster.us-east-1.amazonaws.com"
  ISSUES_TABLE: "SecurityIssues"
  ACCESS_ANALYZER_TABLE: "AccessAnalyzerCache"
  ATHENA_DATABASE: "khalifa_cloudtrail_db"
  ATHENA_WORKGROUP: "khalifa-cloudtrail-analysis"
  CLOUDTRAIL_S3_LOCATION: "s3://cloudtrail-logs/AWSLogs/"
  ANALYSIS_DAYS: "90"
  LOG_LEVEL: "info"
  API_PORT: "8080"
  RULE_RUNNER_SCHEDULE: "0 */6 * * *"
```

---

## Monitoring & Operations

### View Logs

```bash
# API service
kubectl logs -l app=api-service -n security-graph -f

# Rule runner
kubectl logs -l app=rule-runner -n security-graph
```

### Manual Rule Execution

```bash
kubectl create job --from=cronjob/rule-runner rule-runner-manual -n security-graph
```

### Check Rule Runner Status

```bash
kubectl get jobs -n security-graph
kubectl get pods -l job-name=rule-runner-manual -n security-graph
```

### Scale API Service

```bash
# Manual scale
kubectl scale deployment api-service --replicas=5 -n security-graph

# Auto-scaling is configured via HPA
kubectl get hpa -n security-graph
```

---

## Troubleshooting

### API Returns 503

Check pod status:
```bash
kubectl get pods -n security-graph
kubectl describe pod <pod-name> -n security-graph
```

### Neptune Connection Errors

Verify IRSA role is correctly configured:
```bash
kubectl describe serviceaccount api-service -n security-graph
aws iam get-role --role-name SecurityGraphApiServiceRole
```

### Rule Runner Job Failed

```bash
kubectl get job <job-name> -n security-graph
kubectl logs job/<job-name> -n security-graph
```

### Check Issue Counts

```bash
curl https://<api-host>/issues/counts
```

### Check Compliance Status

```bash
curl https://<api-host>/compliance/frameworks
curl https://<api-host>/compliance/CIS_AWS_FOUNDATIONS
```

### Check Effective Permissions

```bash
curl https://<api-host>/identity/effective-permissions/arn:aws:iam::123456:role/MyRole
```

### Find Escalation Paths

```bash
curl https://<api-host>/identity/escalation-paths?riskLevel=critical
```

### Review CloudTrail Analysis

```bash
aws athena get-query-execution --query-execution-id <id>
aws dynamodb query --table-name AccessAnalyzerCache --key-condition-expression "principalArn = :arn" --expression-attribute-values '{":arn": {"S": "arn:aws:iam::123456:role/MyRole"}}'
```

---

## Security Hardening Checklist

Before production deployment:

- [ ] Enable VPC Flow Logs
- [ ] Configure GuardDuty on all accounts
- [ ] Enable CloudTrail with Lake integration
- [ ] Restrict IAM roles to minimum required permissions
- [ ] Enable encryption at rest for DynamoDB
- [ ] Enable encryption in transit for Neptune
- [ ] Configure WAF on ALB
- [ ] Review and restrict NetworkPolicies
- [ ] Enable Pod Security Standards (restricted)
- [ ] Configure RBAC for namespace access
- [ ] Review compliance findings and address critical/high controls
- [ ] Review escalation paths detected by CIEM engine
- [ ] Apply rightsizing recommendations for over-privileged roles
- [ ] Verify CloudTrail logging is enabled for unused permission analysis
- [ ] Configure Glue table for Athena CloudTrail queries

See `OPERATIONAL.md` for complete operational procedures.

---

## CIEM: Cloud Infrastructure Entitlement Management

Khalifa includes a full CIEM engine that computes effective permissions, detects escalation paths, identifies unused permissions, and generates rightsizing recommendations.

### How It Works

1. **Enhanced IAM Collector** ingests groups, inline policies, managed policy documents, trust policies, and permission boundaries into the Neptune graph
2. **Policy Evaluator** resolves identity-based + resource-based + boundary + SCP policies into net effective permissions per principal
3. **Escalation Detector** traverses cross-account trust edges (max 3 hops) to find admin, privilege escalation, and lateral movement paths
4. **CloudTrail Analyzer** queries Athena against CloudTrail S3 logs (90-day window) and caches results in DynamoDB
5. **Rightsizer** compares effective permissions against actual usage to generate least-privilege recommendations

### IAM Data in Neptune

| Node Label | Description | Key Properties |
|------------|-------------|----------------|
| `IamUser` | IAM user | `arn`, `account_id`, `path` |
| `IamRole` | IAM role | `arn`, `account_id`, `assume_role_policy_document` |
| `IamGroup` | IAM group | `arn`, `account_id`, `path` |
| `IamPolicyDocument` | Policy document (inline or managed) | `policy_arn`, `policy_type`, `document_json` |
| `IamPolicyStatement` | Individual policy statement | `effect`, `actions`, `resources`, `conditions_json` |
| `EffectivePermission` | Computed net permissions | `principal_arn`, `allowed_actions`, `is_admin`, `blast_radius` |
| `EscalationPath` | Detected escalation path | `source_arn`, `target_arn`, `risk_level`, `escalation_type` |

| Edge Label | Description |
|------------|-------------|
| `MEMBER_OF` | User → Group membership |
| `ATTACHED_TO` | Principal → Policy document |
| `CONTAINS` | Policy document → Statement |
| `GRANTS` | Statement → Resource |
| `TRUSTS` | External principal → Role (from trust policy) |
| `HAS_PERMISSION_BOUNDARY` | Role → Boundary policy |
| `OWNS` | Account → Principal/Group/Policy |

### Policy Evaluation Logic

The effect resolver follows AWS evaluation rules:

1. **Explicit Deny** always wins
2. **Allow** from identity + resource + session policies
3. **Permission Boundary** must also allow (scoping)
4. **SCP** must also allow (organization-level scoping)
5. **Implicit Deny** if no matching allow

Wildcards (`*`, `s3:*`, `s3:Get*`) are fully supported. When a permission boundary is present, `*` is expanded through the boundary to only the actions the boundary permits.

### Condition Evaluation

20+ IAM condition operators are supported:

| Category | Operators |
|----------|-----------|
| String | `StringEquals`, `StringNotEquals`, `StringLike`, `StringNotLike` |
| IP | `IpAddress`, `NotIpAddress` |
| ARN | `ArnEquals`, `ArnLike`, `ArnNotEquals`, `ArnNotLike` |
| Numeric | `NumericEquals`, `NumericLessThan`, `NumericGreaterThan`, etc. |
| Boolean | `Bool` |
| Date | `DateEquals`, `DateLessThan`, `DateGreaterThan`, etc. |
| Null | `Null` |

Service-specific condition keys are defined for `aws`, `s3`, `kms`, `ec2`, `lambda`, `dynamodb`, `rds`, and `ssm`.

### Escalation Path Detection

Paths are classified into three types:

| Type | Description | Risk Level |
|------|-------------|------------|
| `admin` | Trust → role with `*` or `AdministratorAccess` | critical |
| `privilege_escalation` | Trust → role with `iam:PassRole`, `iam:CreateAccessKey`, etc. | high |
| `lateral_movement` | Cross-account trust → role with data access (S3, DynamoDB, KMS) | medium |

Detection traverses trust edges up to 3 hops (configurable), detecting chained trust paths across accounts.

### CloudTrail Analysis Pipeline

```
CloudTrail S3 Logs
       |
       v
Athena Workgroup (khalifa-cloudtrail-analysis)
       |
       v
SQL: GROUP BY principal, eventSource, eventName (90-day window)
       |
       v
DynamoDB AccessAnalyzerCache table
  PK: principalArn
  SK: eventSource#eventName
  TTL: 90 days
  GSI: ActionIndex (reverse lookup by action)
```

Requires a Glue database (`khalifa_cloudtrail_db`) pointing to the CloudTrail S3 location.

### Rightsizing Recommendations

The rightsizer generates least-privilege policy diffs:

- Starts with CloudTrail usage data (90-day window)
- Applies a configurable safety margin (default: 7 days)
- Optionally keeps safe read-only actions (`Get*`, `List*`, `Describe*`)
- Consolidates actions by service (`s3:GetObject` + `s3:GetObjectVersion` → `s3:GetObject*`)
- Assigns risk level based on removal ratio:
  - **low**: removes <20% of current permissions
  - **medium**: removes 20-50%
  - **high**: removes >50% (may be too aggressive)

### CIEM Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ATHENA_DATABASE` | Glue database for CloudTrail logs | `khalifa_cloudtrail_db` |
| `ATHENA_WORKGROUP` | Athena workgroup | `khalifa-cloudtrail-analysis` |
| `CLOUDTRAIL_S3_LOCATION` | S3 prefix for CloudTrail logs | `s3://cloudtrail-logs/AWSLogs/` |
| `ACCESS_ANALYZER_TABLE` | DynamoDB table for usage cache | `AccessAnalyzerCache` |
| `ANALYSIS_DAYS` | CloudTrail lookback window in days | `90` |
