# Security Graph - Operational Checklist

## A. EKS Architecture Summary

### Components

1. **api-service** - REST API deployment (2 replicas by default, optional HPA)
2. **ui** - Next.js UI deployment
3. **rule-runner** - Risk CronJob (every 6 hours)
4. **org-collector** - Organization collection CronJob
5. **incremental** - SQS incremental collector Deployment
6. **graph-writer** - ClusterIP-only graph persistence Deployment
7. **compliance** - Compliance CronJob
8. **cloudtrail-analyzer** - CloudTrail usage CronJob (Athena → AccessAnalyzerCache; optional anomaly nodes via graph-writer)
9. **flow-log-analyzer** - VPC flow-log CronJob (Athena → TrafficObservations; **suspended by default**, reuses the cloudtrail-analyzer IRSA role)
10. **dspm-scanner** - CronJob: secret scanning of S3 objects and Lambda environment variables (Macie primary, regex fallback; findings written via graph-writer)
11. **policy-evaluator / least-privilege-sweep** - Lambdas: effective permissions, escalation paths, rightsizing
12. **IRSA roles** - IAM roles for pod authentication to Neptune/DynamoDB/SQS

### Network Flow

```
User → ALB (443) → api-service (ClusterIP) → Neptune (8182)
                                                    ↓
                                            DynamoDB (Issues table)
```

## B. IRSA Configuration (Critical for Security)

### API Service Role Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": [
        "arn:aws:dynamodb:REGION:ACCOUNT:table/SecurityIssues",
        "arn:aws:dynamodb:REGION:ACCOUNT:table/SecurityIssues/index/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["neptune-db:Connect"],
      "Resource": "arn:aws:neptune-db:REGION:ACCOUNT:*"
    }
  ]
}
```

### Rule Runner Role Permissions

Same as API Service + `dynamodb:UpdateItem` for status updates.

## C. Network Policies

### Pod Egress Restrictions

- **api-service**: Only to Neptune (8182), AWS API (443)
- **rule-runner / compliance / graph-writer**: Neptune (8182), AWS API (443)
- **org-collector / incremental / cloudtrail-analyzer**: graph-writer Service port and targetPort, AWS API (443), Neptune as needed
- **graph-writer ingress**: collectors and the CloudTrail analyzer, on the container/target port; Service is ClusterIP and is not on the Ingress
- **graph-writer auth**: `/mutations` requires `GRAPH_WRITER_TOKEN` and accepts the collector's per-run reconcile; `/livez` and `/readyz` stay unauthenticated for probes
- **collection secrets**: `COLLECTOR_EXTERNAL_ID` and `GRAPH_WRITER_TOKEN` are never ConfigMap data. Leave `collection.externalId` and `graphWriter.token` empty and set `externalSecrets.targetName` (for example `khalifa-runtime`) so workloads mount an existing Secret. Helm-owned Secrets are only rendered when those two values are set. Graph-writer mounts the token key; collectors mount ExternalId plus token.

Render and review with:

```bash
helm template khalifa deploy/helm/khalifa --values <environment-values.yaml>
```

## D. Logging & Observability

### CloudWatch Setup

```bash
# Log group retention
aws logs put-retention-policy \
  --log-group-name /aws/eks/security-graph-cluster/workload \
  --retention-in-days 90
```

### Recommended Dashboards

1. API latency (p50, p95, p99)
2. Issue count by severity
3. Rule execution success/failure
4. Neptune query latency

## E. SLOs

| Service     | SLO                   | Alert Threshold   |
| ----------- | --------------------- | ----------------- |
| API         | 99.9% availability    | < 99.5% for 5 min |
| API         | p99 latency < 500ms   | > 1s for 5 min    |
| Rule Runner | 99% execution success | > 2 failures/day  |
| Rule Runner | Execution < 30 min    | > 45 min          |

## F. Runbooks

### Runbook: API Pod High CPU

1. Check HPA: `kubectl get hpa -n security-graph`
2. Describe pod: `kubectl describe pod -l app.kubernetes.io/component=api -n security-graph`
3. Check logs: `kubectl logs -l app.kubernetes.io/component=api -n security-graph --tail=100`
4. Scale manually if needed: `kubectl scale deployment khalifa-api --replicas=5 -n security-graph`

### Runbook: Rule Runner Job Failed

1. Check job status: `kubectl get job -n security-graph`
2. View logs: `kubectl logs job/<job-name> -n security-graph`
3. Check Neptune connectivity from pod
4. Retry manually: `kubectl create job --from=cronjob/khalifa-rule-runner rule-runner-manual -n security-graph`

### Runbook: Neptune Query Timeout

1. Check Neptune cluster status in Console
2. Increase query timeout in configmap
3. Check for long-running queries in Neptune Insights
4. Consider scaling Neptune instance

### Runbook: Enabling the CloudTrail analyzer

The `cloudtrail-analyzer` CronJob ships suspended. It queries the organization trail through Athena, and everything on the Khalifa side is created by `khalifa-data` once `cloudtrail_logs_bucket` (plus `cloudtrail_organization_id` and `cloudtrail_logs_kms_key_arn`) is set: the Glue database and `cloudtrail_logs` table with partition projection, the Athena workgroup, the encrypted results bucket, and the analyzer role's Athena / Glue / S3 / KMS statements. `helm_values.config` then carries `athenaDatabase`, `athenaWorkgroup`, and `athenaResultsLocation`.

The trail bucket and its KMS key are owned by the audit account, so two grants must be made there for `arn:aws:iam::<home account>:role/<name_prefix>-khalifa-cloudtrail-analyzer` before the CronJob is unsuspended:

1. Bucket policy on the trail bucket: `s3:GetBucketLocation` and `s3:ListBucket` on the bucket; `s3:GetObject` on `<bucket>/AWSLogs/<organization id>/*`.
2. Key policy on the trail's KMS key: `kms:Decrypt`.

Then set `cloudtrailAnalyzer.suspend = false` in the environment's Helm values. The first run scans `ANALYSIS_DAYS` (default 90) days of the collected accounts; every query bounds the `log_date` partition, so Athena reads only that window. A `Query cannot be completed` or `AccessDenied` from Athena on the first run means one of the two grants above is missing.

## G. Security Hardening

### Must Do Before Production

1. [ ] Enable VPC Flow Logs
2. [ ] Configure GuardDuty on all accounts
3. [ ] Enable the CloudTrail analyzer (see the runbook above)
4. [ ] Restrict IAM roles to minimum required permissions
5. [x] Enable encryption at rest for DynamoDB (khalifa-data CMK)
6. [ ] Enable encryption in transit for Neptune
7. [ ] Configure WAF on ALB
8. [ ] Review and restrict NetworkPolicies
9. [ ] Enable Pod Security Standards (restricted)
10. [ ] Configure RBAC for namespace access

## H. Deployment Commands

> Automated and agent-driven installs must follow [`AGENTS.md`](AGENTS.md);
> the end-to-end secure workflow also lives in
> [`deploy/terraform/examples/complete/README.md`](deploy/terraform/examples/complete/README.md).

```bash
# Deploy through the environment repository's Terraform root
terraform apply

# Check deployment status
kubectl rollout status deployment/khalifa-api -n security-graph

# View API logs
kubectl logs -l app.kubernetes.io/component=api -n security-graph -f

# Scale API service
kubectl scale deployment khalifa-api --replicas=5 -n security-graph

# Manual rule runner execution
kubectl create job --from=cronjob/khalifa-rule-runner rule-runner-manual -n security-graph
```

### Runbook: Enabling observed reachability (VPC flow logs)

1. Confirm VPC flow logs are delivered to an S3 bucket for the collected
   accounts (org delivery under `AWSLogs/<org-id>/<account>/vpcflowlogs/...`,
   or the single-account path without the org id).
2. In `khalifa-data`: set `flow_logs_bucket` (plus `flow_logs_prefix`,
   `flow_logs_organization_id`, `flow_logs_kms_key_arn` as applicable).
   `cloudtrail_logs_bucket` must also be set: the analyzer reuses that
   database, workgroup, and results bucket. Apply; neither the bucket policy
   nor a KMS key is changed here — the owning account must allow the
   `cloudtrail-analyzer` IRSA role (see above).
3. Set the flow-log image in the environment values and unsuspend:
   `flowLogAnalyzer.image` (the rule-runner digest) and
   `flowLogAnalyzer.suspend=false`. The window is `flowLogAnalyzer.days`
   (default 7, max 31). Cost note: each run scans the window with Athena and
   writes up to 5000 observations; `flowLogAnalyzer.schedule` defaults to
   daily 04:00 UTC.
4. Verify: run the job once (`kubectl create job --from=cronjob/khalifa-flow-log-analyzer flow-log-manual -n security-graph`),
   check `TrafficObservations` has rows, then the next collector run marks
   instances `traffic_observed` (visible as the Observed traffic fact on
   issue pages, and in path likelihood as observed reachability).
5. Rollback: re-suspend the CronJob; observations expire by TTL (30 days) and
   the collector stops seeing fresh rows (a stale row still marks an instance
   until it expires — acceptable, traffic was real).

## I. Graph Query Profiling

Neptune serves id lookups from the index; a property filter on a whole label
(for example `g.V().hasLabel('EffectivePermission').has('principal_arn', x)`)
scans the label instead. Khalifa keys derived vertices by deterministic ids
(resource ARNs, `eff-perm:<principal ARN>`, `edge-<sha256>`) so hot lookups are
id steps, and CIEM/label-wide traversals are paged with `range(low, high)`.

Before adding a new query, profile it from a workload pod that already has
Neptune access (the rule-runner or graph-writer ServiceAccount has IRSA):

```bash
POD=$(kubectl -n khalifa get pod -l app.kubernetes.io/component=rule-runner -o name | head -1)
kubectl -n khalifa exec "$POD" -- node -e '
  const Gremlin = require("gremlin");
  const c = new Gremlin.driver.Client(process.env.NEPTUNE_URL, { traversalSource: "g" });
  c.submit(process.argv[1]).then((r) => console.log(JSON.stringify(r.toArray(), null, 2)));
' "g.V().hasLabel(''EffectivePermission'').limit(1).profile()"
```

Queries worth profiling after a schema or traversal change:

- `g.V().hasLabel('EffectivePermission').has('principal_arn', <arn>).profile()` vs `g.V('eff-perm:<arn>').limit(1).profile()` (expect an id/index hit and no full-label scan)
- `g.V().hasLabel(within('IamUser', 'IamRole')).values('arn').range(0, 1000).profile()`
- `g.E().hasLabel('TRUSTS').range(0, 1000).profile()`
- `g.V().has('is_internet_exposed', true).repeat(out().simplePath()).times(4).profile()` (attack-path cost)
- The rule templates in `packages/risk-engine/src/rules.ts` and the compliance evaluators, which run on a schedule

Read the profile output for: a `NeptuneGraphStep` with an id or index hit, no
`HasStep` over a whole label at the start of the traversal, and the traverser
count at each step. The evaluator lambdas log a warning when a bounded
enumeration hits its item cap (`maxItems`, default 50000), which is the signal
that a label-wide traversal needs paging or reshaping.

## I. Monitoring URLs

- CloudWatch Log Insights: `/aws/eks/security-graph-cluster/workload`
- X-Ray: Service map for api-service
- Prometheus metrics: `http://<pod>:8080/metrics`

## J. Trust-center sync

The nightly `Trust center sync` workflow renders Khalifa's publishable CIS
posture into a static in-repo trust-center site (`trust-center/`) and deploys
it to Cloudflare Pages. It stays disabled until `TRUST_CENTER_PROJECT` is
configured; variables and secrets are listed in
[`scripts/trust-center-sync/README.md`](scripts/trust-center-sync/README.md).

What it sends: only the requirements whose Security Hub status (FAILED when any
account/Region fails, otherwise PASSED) has held for
`reconciliation.minAgreementDays` with no missing data and that appear in
`reconciliation.publishAllowlist`, as `{requirement, title, section, status}`.
No accounts, Regions, counts, evidence, or disagreements.

Mapped frameworks (SOC 2, ISO 27001, PCI DSS, NIST SP 800-53) publish through the same endpoint: a
requirement appears only while every mapped control is reconciliation-
publishable (CIS) or assessed PASS/FAIL in the latest Khalifa baseline report
(`REPORTS_TABLE`). If that report is unreadable, the endpoint serves CIS only —
mapped frameworks stay unpublished rather than failing the response.

The page states how it is monitored (the "Continuous monitoring" section):
assessment and publication cadence come from `trust-center/site.config.json`
(`monitoring.assessmentCadence` / `monitoring.publishCadence`), and the
staleness window is the API's own published `maxAgeHours` (24h). That makes the
claim "when the last assessment is older than 24 hours, every framework
unpublishes automatically" data-derived rather than a promise. If
`monitoring.staleAfterHours` in the site config contradicts the API's value,
the site build fails instead of publishing a false claim.

Run it by hand after a compliance cycle:

```bash
gh workflow run "Trust center sync"
```

Or locally: `npm run trust-center:sync` (API envs) then
`npm run trust-center:build`; the site lands in `trust-center/dist/`.

Site customization lives in `trust-center/site.config.json` (company name,
security email, links, accent color, footer note). Framework and control
statuses are generated and never hand-edited.

It fails closed: a `STALE`/`MISSING` reconciliation record, an HTTP/auth error,
or a malformed payload leaves the previous configuration in place and fails the
job, so the previous Cloudflare Pages deployment stays live. A page that looks
unchanged usually means the workflow failed closed — check the job log.

Rotating the Access service token: create a new token for the Cloudflare Access
policy that fronts the API, update `CF_ACCESS_CLIENT_ID` /
`CF_ACCESS_CLIENT_SECRET` in the repository secrets, and set
`reconciliation.trustCenterSyncClientId` (Helm values) to the new client id.
Until both sides match, the endpoint accepts no one, by design.

Provenance for a deployed page: the page's publication details show the
generated-at time and the reconciliation record time; the same record is live
at `GET /compliance/reconciliation/publishable`.

### Making the trust center live, step by step

1. Deploy a release and keep the API's public hostname and the Cloudflare
   Access policy that fronts it (see [`AGENTS.md`](AGENTS.md) and the example
   README).
2. Configure the API side (Helm values): `reconciliation.securityHubRoleArn`,
   a non-empty `reconciliation.publishAllowlist`, and
   `reconciliation.trustCenterSyncClientId` set to the Access service token's
   client id. Reconciliation must record `OK` before anything publishes.
3. In Cloudflare Access, create a **service token** for the API hostname's
   policy; you need its client id and secret once.
4. In Cloudflare, create a Pages project and an API token that can edit Pages,
   plus the account id.
5. Configure this repository (the workflow stays skipped until
   `TRUST_CENTER_PROJECT` is set):

   ```bash
   gh variable set KHALIFA_API_URL            --body "https://api.example.com"
   gh variable set TRUST_CENTER_PROJECT       --body "khalifa-trust-center"
   gh variable set TRUST_CENTER_PUBLIC_URL    --body "https://trust.example.com"  # optional: enables the posture changelog
   gh secret set CF_ACCESS_CLIENT_ID
   gh secret set CF_ACCESS_CLIENT_SECRET
   gh secret set CLOUDFLARE_API_TOKEN
   gh secret set CLOUDFLARE_ACCOUNT_ID
   ```

6. Dry run locally (optional): `npm run trust-center:sync` then
   `npm run trust-center:build`, and open `trust-center/dist/index.html`.
7. First publish: `gh workflow run "Trust center sync"` (the nightly cron takes
   over afterwards).
8. Verify: the job's step summary, the Pages URL, each section rendering, and
   `/.well-known/security.txt`. Frameworks appear only when the record is `OK`
   and the requirement is allowlisted; a `STALE`/`MISSING` record publishes
   nothing (the previous deployment stays live).
9. Optional extras: a status-page link
   (`site.config.json` → `monitoring.statusPageUrl`), public documents,
   subprocessors, FAQs, and the questionnaire answer sheet (published
   automatically as `/questionnaire.json`).

If the workflow was skipped, `TRUST_CENTER_PROJECT` is unset. If the page looks
empty, reconciliation is `STALE`/`MISSING` or nothing is allowlisted yet — the
fail-closed behavior, not a bug.
