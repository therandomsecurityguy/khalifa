# Khalifa

Agentless ingestion of AWS Org resources and Security Hub findings into a Neptune-backed security graph, with a risk and attack-path engine to identify security issues.

[Docs](ARCHITECTURE.md) · [Operations](OPERATIONAL.md)

[![CI](https://github.com/therandomsecurityguy/khalifa/actions/workflows/ci.yml/badge.svg)](https://github.com/therandomsecurityguy/khalifa/actions/workflows/ci.yml) [![License: BSD 3-Clause](https://img.shields.io/badge/License-BSD_3--Clause-blue.svg)](https://opensource.org/licenses/BSD-3-Clause) [![Built with TypeScript](https://img.shields.io/badge/Built_with-TypeScript-3178c6.svg)](https://www.typescriptlang.org) [![Built with Node.js](https://img.shields.io/badge/Built_with-Node.js-339933.svg)](https://nodejs.org)

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system diagram and design.

## 1. What is Khalifa?

[](#1-what-is-khalifa)

Khalifa is an agentless ingestion pipeline that sits between your AWS Organization and a Neptune-backed security graph. Every account, resource, and finding gets collected on a schedule, normalized into a graph model you own, and evaluated locally against risk rules, attack-path traversals, and CIEM effective-permission logic.

**Why it was built:** Cloud estates grow faster than any team can review them. A misconfigured S3 bucket, an over-privileged IAM role, or a publicly exposed RDS instance turns into a real finding before anyone notices. Khalifa gives those resources a graph: collected, scored, joined to attack paths, and rendered as issues you can act on.

**How it works:** Collectors run on an EventBridge schedule (or as Kubernetes CronJobs) and assume into every account in the AWS Organization via a cross-account role. They inventory 30+ AWS services, decompose IAM into policy statements + effective permissions, pull Security Hub and GuardDuty findings, and stream everything into Neptune. The Risk Engine then runs Gremlin traversals against the live graph to produce prioritized issues, attack paths, and compliance evaluations against CIS, SOC 2, and ISO 27001 — without ever moving data out of your AWS account.

## 2. Run your security pipeline with Khalifa

[](#2-run-your-security-pipeline-with-khalifa)

### Install

[](#install)

**Prerequisites:** Node.js 20+, AWS CDK CLI, an AWS Organization with a delegated admin account, and a Neptune cluster reachable from your compute.

```bash
git clone https://github.com/therandomsecurityguy/khalifa
cd khalifa
npm ci --workspaces
```

Deploy the cross-account collector role into every member account from the `templates/SecurityGraphCollectorRole.yaml` template, then bootstrap the ingestion stack.

### Quickstart

[](#quickstart)

There are two ways to run Khalifa. Both end up in the same place (a populated security graph with risk findings) but the first is faster to try, the second is the production setup.

**Option A: Lambda + EventBridge (development / small scale)**

The Lambda stack uses EventBridge schedules, Step Functions for parallel account fan-out, and a separate daily CloudTrail analyzer. It scales to roughly 20 accounts without tuning.

```bash
cd cdk
npm install
npm run build

cdk deploy KhalifaStack \
  --neptune-endpoint neptune-cluster.us-east-1.amazonaws.com \
  --issues-table-name SecurityIssues \
  --access-analyzer-table AccessAnalyzerCache \
  --athena-database khalifa_cloudtrail_db \
  --cloudtrail-s3-location s3://cloudtrail-logs/AWSLogs/
```

Every two hours the collector ingests all member accounts. CloudTrail analysis runs daily at 02:00 UTC. The policy evaluator runs every six hours and after each collector pass. The risk engine runs hourly.

**Option B: EKS + CronJob (production / >20 accounts)**

The EKS stack runs the API service, rule runner, and UI as Kubernetes workloads. It is built for sustained load across hundreds of accounts and gives you a UI plus a REST API.

```bash
# 1. Build and push images
cd api-service && docker build -t security-graph-api:latest . && docker push <ecr>/security-graph-api:v1.0.0
cd ../packages/risk-engine && docker build -t security-graph-rule-runner:latest . && docker push <ecr>/security-graph-rule-runner:v1.0.0

# 2. Deploy CDK
cd ../../cdk
cdk deploy SecurityGraphEksStack \
  --vpc-id vpc-12345678 \
  --neptune-endpoint neptune-cluster.us-east-1.amazonaws.com \
  --issues-table-name SecurityIssues \
  --certificate-arn arn:aws:acm:us-east-1:... \
  --cognito-user-pool-id us-east-1_xxxxx \
  --cognito-client-id xxxxx

# 3. Apply manifests
kubectl apply -f eks-manifests/
```

Use this when you want to serve a UI to analysts, expose a stable REST API, or run the rule runner on a schedule that survives control-plane hiccups.

### Two deployment options

[](#two-deployment-options)

| Approach | Use Case | Complexity |
|----------|----------|------------|
| Lambda + EventBridge | Development / small scale (<20 accounts) | Lower |
| EKS + CronJob | Production (>20 accounts, multi-tenant API) | Higher |

### Configuration

[](#configuration)

Environment variables are shared across both stacks. The CDK stack wires sane defaults; override at deploy time or via the Kubernetes `ConfigMap` (`eks-manifests/01-configmap.yaml`).

| Variable | Description | Default |
|----------|-------------|---------|
| `NEPTUNE_ENDPOINT` | Neptune cluster endpoint | — |
| `NEPTUNE_AUTH_SECRET_ARN` | Secrets Manager ARN for Neptune auth | — |
| `ISSUES_TABLE` | DynamoDB table for issues | `SecurityIssues` |
| `ACCESS_ANALYZER_TABLE` | DynamoDB table for CloudTrail usage cache | `AccessAnalyzerCache` |
| `ATHENA_DATABASE` | Glue database for CloudTrail logs | `khalifa_cloudtrail_db` |
| `ATHENA_WORKGROUP` | Athena workgroup | `khalifa-cloudtrail-analysis` |
| `CLOUDTRAIL_S3_LOCATION` | S3 prefix for CloudTrail logs | `s3://cloudtrail-logs/AWSLogs/` |
| `ANALYSIS_DAYS` | CloudTrail lookback window | `90` |
| `AWS_REGION` | AWS region | `us-east-1` |
| `LOG_LEVEL` | Logging level | `info` |
| `RULE_RUNNER_SCHEDULE` | Cron schedule | `0 */6 * * *` (every 6h) |

> Cross-account access is granted via the IAM role defined in `templates/SecurityGraphCollectorRole.yaml`. Deploy it once per member account with a unique external ID per deployment.

### API reference

[](#api-reference)

All routes except `/health` require a valid Cognito bearer JWT. RBAC roles are mapped from Cognito groups: `khalifa-admin` → Admin, `khalifa-analyst` → Analyst, `khalifa-viewer` → Viewer.

**Issues & risk**

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

**Compliance**

| Endpoint | Description |
|----------|-------------|
| `GET /compliance/frameworks` | List available compliance frameworks (Viewer+) |
| `GET /compliance/frameworks/:framework` | Get framework overview with control summaries (Viewer+) |
| `GET /compliance/frameworks/:framework/controls` | List all controls for a framework (Viewer+) |
| `GET /compliance/frameworks/:framework/controls/:controlId` | Get control details with evidence (Viewer+) |
| `GET /compliance/frameworks/:framework/report` | Generate compliance report (Viewer+) |
| `GET /compliance/frameworks/:framework/drift` | Detect configuration drift since last evaluation (Viewer+) |

**CIEM / Identity**

| Endpoint | Description |
|----------|-------------|
| `GET /identity/effective-permissions/:principal` | Get computed effective permissions for a principal |
| `GET /identity/escalation-paths` | List detected escalation paths with filters |
| `GET /identity/unused-permissions?principal=X&days=90` | Find unused permissions by comparing effective perms vs CloudTrail usage |
| `GET /identity/rightsizing/:principal?safetyMarginDays=7` | Generate least-privilege policy recommendation |
| `GET /identity/trust-graph?account=X` | Retrieve cross-account trust relationships as a graph |

**Query parameters for `/issues`**

| Parameter | Type | Description |
|-----------|------|-------------|
| `severity` | string[] | Filter by severity (critical, high, medium, low) |
| `team` | string[] | Filter by owning team |
| `status` | string[] | Filter by status (open, resolved, suppressed) |
| `ruleId` | string | Filter by rule ID |
| `limit` | number | Max results (default: 50, max: 1000) |
| `nextToken` | string | Pagination token |

**Examples**

```bash
# Get critical issues
curl "https://api.example.com/issues?severity=critical&status=open&limit=100" \
  -H "Authorization: Bearer $TOKEN"

# Find attack paths
curl "https://api.example.com/attack-paths?fromSelector=Internet&toSelector=S3Bucket&maxPathLength=4" \
  -H "Authorization: Bearer $TOKEN"

# Get CIS compliance report
curl "https://api.example.com/compliance/CIS_AWS_FOUNDATIONS/report" \
  -H "Authorization: Bearer $TOKEN"

# Get effective permissions for a role
curl "https://api.example.com/identity/effective-permissions/arn:aws:iam::123456:role/AdminRole" \
  -H "Authorization: Bearer $TOKEN"

# Get rightsizing recommendation
curl "https://api.example.com/identity/rightsizing/arn:aws:iam::123456:role/DataRole?safetyMarginDays=7&includeReadonlySafe=true" \
  -H "Authorization: Bearer $TOKEN"
```

### Different operating models

[](#different-operating-models)

**1. Single-account dev (like Quickstart Option A)**

The Lambda stack fans out from a single delegated admin account, assumes into each member account via the collector role, and writes directly to a Neptune cluster in the same VPC. Step Functions parallelize the per-account work.

```bash
cdk deploy KhalifaStack
```

**2. Multi-account org with EKS backend (like Quickstart Option B)**

The EKS stack adds an API service, a UI, and a Kubernetes CronJob for the rule runner. The API is fronted by an ALB with Cognito OIDC, and the rule runner executes Gremlin traversals on the same Neptune cluster.

```bash
cdk deploy SecurityGraphEksStack
kubectl apply -f eks-manifests/
```

**3. Multi-account org with read replicas**

Run collectors in each region and replicate into a single Neptune cluster via Neptune Streams. Use this when accounts are concentrated in specific regions or you need to keep data residency boundaries.

> Full deployment reference: [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`OPERATIONAL.md`](OPERATIONAL.md)

### Compliance frameworks

[](#compliance-frameworks)

Khalifa includes automated compliance evaluation against three industry-standard frameworks with 124 controls and 40+ automated evaluators that run Gremlin graph queries against your security data.

**CIS AWS Foundations Benchmark v3.0 (78 controls)**

Covers the foundational security configurations for AWS accounts:

| Section | Controls | Focus |
|---------|----------|-------|
| 1. IAM | 18 | Root account, MFA, password policy, access keys |
| 2. Logging | 10 | CloudTrail, Config, S3 logging |
| 3. Monitoring | 28 | CloudWatch alarms, GuardDuty, Config rules |
| 4. Networking | 12 | VPC flow logs, security groups, NACLs |
| 5. Data Protection | 10 | Encryption, KMS rotation, backup |

**SOC 2 Type II (22 controls)**

Maps to Trust Services Criteria:

| Section | Controls | Focus |
|---------|----------|-------|
| CC6 | 8 | Logical access, authentication, authorization |
| CC7 | 6 | Monitoring, incident response, change management |
| CC8 | 4 | Risk mitigation, system boundaries |
| CC9 | 4 | Additional criteria |

**ISO 27001:2022 (24 controls)**

Based on Annex A controls:

| Section | Controls | Focus |
|---------|----------|-------|
| A.5 | 4 | Organizational controls, policies |
| A.6 | 4 | People controls, onboarding, training |
| A.8 | 6 | Technological controls, encryption, logging |
| A.9 | 4 | Physical and environmental security |
| A.12 | 3 | Operations security, vulnerability management |
| A.13 | 3 | Communications security, network controls |

The compliance engine runs Gremlin evaluators that query the live graph, produce per-control evidence (pass/fail/manual), and write results to DynamoDB for the UI to render.

## 3. Architecture

[](#3-architecture)

[![Khalifa flow diagram](docs/khalifa-architecture.svg)](ARCHITECTURE.md) 

**[Collector](lambdas/collector):** runs in a delegated admin account, assumes into every member account via the cross-account role, and inventories 30+ AWS services per pass. Writes raw resource nodes to Neptune.

**[Policy Evaluator](lambdas/policy-evaluator):** resolves IAM identity + resource + boundary + SCP policies into net effective permissions per principal, and traverses cross-account trust edges up to 3 hops to surface escalation paths.

**[CloudTrail Analyzer](lambdas/cloudtrail-analyzer):** runs Athena queries against the CloudTrail S3 logs on a daily schedule, with a 90-day lookback window. Writes usage data to the `AccessAnalyzerCache` DynamoDB table for the rightsizer.

**[Risk Engine](packages/risk-engine):** runs Gremlin traversals against the live graph on a schedule, producing prioritized issues, attack paths, and compliance evaluations. Each rule ships with severity, scoring, and remediation guidance.

**[API Service](api-service):** REST API fronted by ALB + Cognito OIDC. Exposes issues, attack paths, resources, compliance reports, and CIEM identity endpoints. RBAC enforced from Cognito groups.

**[UI](ui):** Next.js dashboard for issues, attack paths, and compliance. Renders control-level evidence, drift detection, and CSV export.

### Features

[](#features)

- **Agentless ingestion:** no agents to install in member accounts; collectors assume via a single cross-account role defined in [`templates/SecurityGraphCollectorRole.yaml`](templates/SecurityGraphCollectorRole.yaml)
- **Deterministic graph model:** every resource, IAM statement, and finding becomes a typed node with explicit edges; Gremlin returns the same traversal for the same input every time
- **30+ AWS services collected:** compute, storage, database, identity, network, security, logging, serverless, secrets, and backup
- **Risk + attack path + CIEM in one pass:** rules, traversals, and effective-permission evaluation all run against the same live graph
- **CIEM with CloudTrail grounding:** effective permissions are joined to actual usage from Athena over CloudTrail, with rightsizing recommendations and a configurable safety margin
- **Compliance built in:** CIS v3.0, SOC 2 Type II, and ISO 27001:2022 evaluated by automated Gremlin queries with per-control evidence
- **Two deployment modes:** Lambda + EventBridge for development, EKS + CronJob for production — same data model, same graph, same API

## 4. Repo structure

[](#4-repo-structure)

**Infrastructure**

[`cdk/`](cdk)

CDK stacks: `KhalifaStack` (Lambda + EventBridge) and `SecurityGraphEksStack` (EKS + ALB + Cognito)

[`templates/`](templates)

Cross-account IAM role template deployed once per member account

**Collectors**

[`lambdas/list-accounts`](lambdas/list-accounts)

Lists org accounts from AWS Organizations

[`lambdas/collector`](lambdas/collector)

Per-account collector: 30+ AWS services + enhanced IAM decomposition

[`lambdas/graph-writer`](lambdas/graph-writer)

Neptune writer for raw resource nodes

[`lambdas/incremental-collector`](lambdas/incremental-collector)

Event-driven updates via EventBridge → SQS

[`lambdas/policy-evaluator`](lambdas/policy-evaluator)

CIEM engine: effective permissions, escalation paths, rightsizing

[`lambdas/cloudtrail-analyzer`](lambdas/cloudtrail-analyzer)

Athena queries over CloudTrail S3 logs → DynamoDB cache

**Engine**

[`packages/risk-engine`](packages/risk-engine)

Risk rules, attack-path traversals, scoring, compliance evaluators

**Service**

[`api-service/`](api-service)

REST API (Express) — issues, attack paths, resources, compliance, identity

[`ui/`](ui)

Next.js dashboard — issues, attack paths, compliance

**Deploy**

[`eks-manifests/`](eks-manifests)

Kubernetes manifests for API service, rule runner CronJob, HPA, NetworkPolicy

**Docs**

[`ARCHITECTURE.md`](ARCHITECTURE.md)

System architecture, data model, ingestion topology

[`OPERATIONAL.md`](OPERATIONAL.md)

Runbooks for the rule runner, Neptune, IRSA, and incident response

[`CONTRIBUTING.md`](CONTRIBUTING.md)

Local development, workspaces, CI conventions

[`CHANGELOG.md`](CHANGELOG.md)

Release history

---

## License

[](#license)

BSD 3-Clause. See [LICENSE](LICENSE).
