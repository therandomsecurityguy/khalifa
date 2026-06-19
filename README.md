# Khalifa - Security Graph & Risk Engine

Agentless ingestion of AWS Org resources and Security Hub findings into a Neptune-backed security graph, with a risk and attack-path engine and automated compliance reporting.

## Architecture

### Lambda-Based Ingestion (Original)

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
    +-- GraphWriter Lambda -> Neptune

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

### EKS-Based Deployment (Recommended for Production)

```
User -> ALB (Cognito OIDC) -> api-service (EKS)
                                      |
                    +-----------------+-----------------+
                    v                 v                 v
              Neptune            DynamoDB           CloudWatch
             (Graph DB)      (Issues table)         (Logs)
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
cd ../lambdas/risk-engine
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
| `GET /health` | Health check |
| `GET /issues` | List issues with filters |
| `GET /issues/:id` | Get issue details with attack path |
| `GET /issues/counts` | Get issue counts by severity |
| `GET /issues/stats` | Get detailed statistics |
| `GET /attack-paths?fromSelector=X&toSelector=Y` | Find attack paths |
| `GET /resources/:arn` | Get resource with neighbors and issues |
| `GET /resources/search?label=EC2Instance` | Search resources |

### Compliance

| Endpoint | Description |
|----------|-------------|
| `GET /compliance/frameworks` | List available compliance frameworks |
| `GET /compliance/:framework` | Get framework overview with control summaries |
| `GET /compliance/:framework/controls` | List all controls for a framework |
| `GET /compliance/:framework/controls/:controlId` | Get control details with evidence |
| `GET /compliance/:framework/report` | Generate compliance report |
| `GET /compliance/:framework/drift` | Detect configuration drift since last evaluation |

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
│   ├── graph-writer/             # Writes to Neptune
│   ├── incremental-collector/    # Event-driven updates
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
│   │   │   └── compliance.ts    # Compliance endpoints
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
| Identity | IAM (users, roles, policies, credential reports), KMS |
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
| RULE-006 | Cross-Account IAM Trust with Admin Privileges | critical |
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
| `ISSUES_TABLE` | DynamoDB table for issues | SecurityIssues |
| `AWS_REGION` | AWS region | us-east-1 |
| `LOG_LEVEL` | Logging level | info |
| `RULE_RUNNER_SCHEDULE` | Cron schedule | `0 */6 * * *` (every 6h) |

### Kubernetes ConfigMap

Edit `eks-manifests/01-configmap.yaml` before deployment:

```yaml
data:
  NEPTUNE_ENDPOINT: "neptune-cluster.us-east-1.amazonaws.com"
  ISSUES_TABLE: "SecurityIssues"
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

See `OPERATIONAL.md` for complete operational procedures.