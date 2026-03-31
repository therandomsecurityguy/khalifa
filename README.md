# Khalifa - Security Graph & Risk Engine

Agentless ingestion of AWS Org resources and Security Hub findings into a Neptune-backed security graph, with a risk and attack-path engine to identify security issues.

## Architecture

### Lambda-Based Ingestion (Original)

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

### EKS-Based Deployment (Recommended for Production)

```
User → ALB (Cognito OIDC) → api-service (EKS)
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
              Neptune            DynamoDB           CloudWatch
             (Graph DB)      (Issues table)         (Logs)
                    │
                    ▼
         rule-runner CronJob
              (every 6h)
                    │
                    ▼
              Neptune queries
                    │
                    ▼
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
```

---

## API Endpoints

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
│   ├── collector/                # Collects AWS resources
│   ├── graph-writer/             # Writes to Neptune
│   ├── incremental-collector/    # Event-driven updates
│   └── risk-engine/              # Risk and attack-path engine
│       ├── types.ts              # Rule/Issue schemas
│       ├── rules.ts              # Gremlin risk rules
│       ├── scoring.ts            # Risk scoring algorithm
│       └── runner.ts             # Rule execution engine
├── api-service/                  # REST API (EKS)
│   ├── src/
│   │   ├── app.ts               # Express server
│   │   ├── routes/              # API routes
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
│   │   ├── issues/              # Issues pages
│   │   ├── attack-paths/        # Attack path explorer
│   │   └── lib/api.ts           # API client
│   └── package.json
└── templates/
    └── SecurityGraphCollectorRole.yaml  # Cross-account role
```

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
Score = CVSS×10×0.25 + Exposure×100×0.2 + Identity×100×0.2 + DataClass×100×0.2 + Env×100×0.15 + CrownJewelBonus
```

**Severity Thresholds:**
- Critical: ≥80
- High: ≥60
- Medium: ≥40
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
- `http://localhost:3000/issues/:id` - Issue details
- `http://localhost:3000/attack-paths` - Attack path explorer

### Authentication

The UI uses OIDC via Cognito. Tokens are stored in localStorage and passed to the API via the `Authorization: Bearer` header.

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

See `OPERATIONAL.md` for complete operational procedures.
