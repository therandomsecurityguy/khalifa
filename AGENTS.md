# AGENTS.md

Instructions for AI agents and automation working in this repository. Two
audiences: agents that **install Khalifa on AWS**, and agents that **change the
code**. When the two conflict, safety wins: never trade a guardrail for
progress, and stop to ask the operator when a step is destructive or ambiguous.

---

## 1. Installing Khalifa on AWS (secure workflow)

The reference walkthrough lives in
[`deploy/terraform/examples/complete/README.md`](deploy/terraform/examples/complete/README.md).
This section is the security envelope around it. Follow it in order; do not
skip the confirmation gates.

### 1.1 Non-negotiables

- **No long-lived credentials.** Use the operator's existing short-lived
  credentials (SSO, assume-role, GitHub OIDC). Never create IAM users, access
  keys, or long-lived tokens for the install.
- **Verify the target first.** Run `aws sts get-caller-identity` and compare
  the account ID to the operator-supplied account before any write. Refuse to
  continue on mismatch.
- **Secrets never leave Secrets Manager.** The runtime secret
  (`<name_prefix>-khalifa/runtime`) holds `COLLECTOR_EXTERNAL_ID` and
  `GRAPH_WRITER_TOKEN`; it reaches pods through External Secrets. Never copy
  those values into `terraform.tfvars`, Helm values, CI variables, files, or
  chat. If a step requires reading a secret, read only the single field and
  feed it to the consumer — never print it.
- **Require explicit human confirmation** before any of:
  `terraform destroy` or any deletion; disabling DynamoDB deletion protection;
  changing ECR tag immutability; rotating the collector ExternalId; widening
  any IAM policy; exposing a public endpoint (ingress scheme `internet-facing`,
  public EKS endpoints).
- **The EKS cluster is operator-owned.** This repo deploys into an existing
  cluster. Do not create clusters, node groups, or VPCs unless separately and
  explicitly asked.
- **Digest-pinned images only.** The chart schema rejects `repo:tag`
  references; build, push, then reference `repo@sha256:<64 hex>`.
- **The namespace must exist.** The chart never creates it
  (`create_namespace = false`).

### 1.2 Preflight (no writes)

```bash
aws sts get-caller-identity                      # account must match the request
aws eks describe-cluster --name "$CLUSTER" \
  --query 'cluster.{status:status,vpc:resourcesVpcConfig.vpcId,issuer:identity.oidc.issuer}'
terraform version                                # >= 1.7
helm version                                     # 4.x (chart tooling)
```

Collect from the operator: region, cluster name, VPC id/CIDR, private subnets,
node security group, OIDC provider ARN, `name_prefix`, `home_account_id`,
collection scope, `ui_base_url`, `github_repository`. Stop if any value is a
placeholder — the deployment validation script rejects placeholder tokens, and
so should you.

### 1.3 Create the AWS data plane and ECR repositories

```bash
cd deploy/terraform/examples/complete
cp terraform.tfvars.example terraform.tfvars   # fill in; no secrets go here
terraform init
terraform apply -var install_chart=false       # registry + data plane, no chart
kubectl create namespace khalifa
```

This creates the ECR repositories, the data-plane CMK, Neptune, DynamoDB
tables, queues, Cognito pool, Secrets Manager entries, IRSA roles for every
workload, and the External Secrets role. It changes nothing outside the target
account.

### 1.4 Build and push the three images

```bash
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY"   # token is not stored

docker buildx build --platform linux/amd64 --target api         -t "$REGISTRY/example-khalifa-api:latest"         --push .
docker buildx build --platform linux/amd64 --target ui          -t "$REGISTRY/example-khalifa-ui:latest"          --push .
docker buildx build --platform linux/amd64 --target rule-runner -t "$REGISTRY/example-khalifa-rule-runner:latest" --push .
```

Read each digest (`aws ecr describe-images ... --query 'imageDetails[0].imageDigest'`)
and set `image_digests` in `terraform.tfvars`. Never invent a digest.

### 1.5 Install the release

```bash
terraform apply          # installs the Helm release (atomic, waits for readiness)
kubectl -n khalifa get pods
kubectl -n khalifa port-forward svc/khalifa-api 8080:80 &
curl -sf http://localhost:8080/livez && curl -sf http://localhost:8080/readyz
```

Do not install with `install_chart=true` before images exist — the atomic
release will roll back, which is safe but noisy.

### 1.6 Bootstrap access and member collection

- Cognito: create the operator's user and add them to `khalifa-admin`
  (`aws cognito-idp admin-create-user` / `admin-add-user-to-group`).
- Member accounts: deploy
  [`templates/SecurityGraphCollectorRole.yaml`](templates/SecurityGraphCollectorRole.yaml)
  (or the StackSet variant) with the hub IRSA role ARNs as trusted principals
  and the ExternalId from Secrets Manager. `scripts/deploy-collector-role.sh`
  automates this per profile. **Never log the ExternalId.**

### 1.7 Optional features (each gated — ask first)

- **CloudTrail analyzer**: `cloudtrail_logs_bucket`, `cloudtrail_organization_id`,
  `cloudtrail_logs_kms_key_arn`. Confirm the trail owner has allowed the
  analyzer role before unsuspending the CronJob.
- **CIS reconciliation**: `securityhub_reader_role_arn` (audit account,
  read-only). Required before any trust-center publishing.
- **Canaries / DSPM allowlist**: `ENABLE_CANARIES`, `dspm_bucket_allowlist`.
- **Slack issue sink**: `SLACK_WEBHOOK_URL` at CDK deploy time (stored in
  Secrets Manager and read as `SLACK_WEBHOOK_SECRET_ARN`). Never place the
  webhook, or `PROD_ACCOUNT_IDS`, in files or chat.

### 1.8 Trust center (publishing the posture)

Prerequisites: the install above is healthy and reconciliation has produced an
`OK` record. The full step-by-step runbook is
[`OPERATIONAL.md`](OPERATIONAL.md) section J.1; the summary an agent needs:

1. Helm values: `reconciliation.securityHubRoleArn`, a non-empty
   `reconciliation.publishAllowlist`, and
   `reconciliation.trustCenterSyncClientId` (the Access service token's client
   id). Nothing publishes until these are set.
2. Cloudflare: create a **service token** for the Access policy that fronts the
   API, a **Pages project**, and an API token that can edit Pages (plus the
   account id).
3. Configure the repository (the workflow stays skipped until
   `TRUST_CENTER_PROJECT` is set):

   ```bash
   gh variable set KHALIFA_API_URL         --body "https://api.example.com"
   gh variable set TRUST_CENTER_PROJECT    --body "khalifa-trust-center"
   gh variable set TRUST_CENTER_PUBLIC_URL --body "https://trust.example.com"  # optional: enables the posture changelog
   gh secret set CF_ACCESS_CLIENT_ID
   gh secret set CF_ACCESS_CLIENT_SECRET
   gh secret set CLOUDFLARE_API_TOKEN
   gh secret set CLOUDFLARE_ACCOUNT_ID
   ```

4. Dry run locally: `npm run trust-center:sync` then
   `npm run trust-center:build`; inspect `trust-center/dist/index.html`.
5. First publish: `gh workflow run "Trust center sync"` (the nightly cron takes
   over). It fails closed — `STALE`/`MISSING` records leave the previous
   deployment live.
6. Verify the deployed page: framework cards (CIS and the mapped SOC 2 /
   ISO 27001 / PCI DSS / NIST SP 800-53 requirements that are publishable), the
   continuous-monitoring section, `/.well-known/security.txt` (emitted when a
   security email is configured), and `/questionnaire.json`.
7. Deployment-owned content in `trust-center/site.config.json`: practices,
   documents, subprocessors, FAQs, status-page link, security contact. Never
   put identifiers in these — the build trips on account IDs, ARNs, and
   access-key patterns.

### 1.9 Verification gates before declaring success

- `bash scripts/validate-deployment-modules.sh` (where helm/kubeconform exist)
- all pods `Ready`; CronJobs in the intended suspend state
- after the first compliance run: `/compliance/frameworks` lists six
  frameworks (CIS, Khalifa baseline, SOC 2, ISO 27001, PCI DSS, NIST 800-53);
  the CIS reconciliation record (`CIS_RECONCILIATION`) is `OK`
- trust center (when configured): the workflow's step summary, the deployed
  page's sections, and `/.well-known/security.txt`
- fail-closed behavior observed, not assumed: `STALE` reconciliation keeps the
  trust center unpublished; an unreadable baseline report keeps mapped
  frameworks unpublished

### 1.10 Rollback

- Helm operations are atomic (`cleanup_on_fail`) — a failed install rolls back.
- `terraform destroy` is intentionally blocked: DynamoDB deletion protection
  and `RETAIN` policies. Do **not** disable them without explicit written
  operator approval; retained resources (CMK, tables, Neptune) outlive a
  destroy by design.

---

## 2. Changing the code (repository conventions)

**Run the gate before proposing a change:** `npm ci` once, then
`npm run ci:quality` (format, lint, typecheck, all jest projects, builds,
Lambda packaging smoke). Narrow loops: `npx jest --selectProjects <name>`.

### 2.1 Load-bearing files and tests

These exist to keep security and honesty claims true. Do not edit them
casually; when a change genuinely requires it, say so explicitly in the PR body
and in `CHANGELOG.md` under **Unreleased**:

- `packages/risk-engine/src/framework-citations.ts` — the curated requirement
  mappings; `framework-citations.test.ts` pins the golden list and rejects
  unknown control ids.
- `packages/risk-engine/src/control-rule-mapping.test.ts` (`REVIEWED_MAPPING`)
  — every risk rule↔control mapping is reviewed or CI fails.
- `packages/risk-engine/benchmarks/cis-aws-foundations-3.0.0/` — verbatim AWS
  source of truth (prettier ignores it; do not reformat).
- `packages/risk-engine/src/securityhub-cis-v3.ts` and
  `cis-v3-source-of-truth.test.ts` — SH control → CIS requirement mapping.
- `packages/risk-engine/src/compliance-types.ts` (`LEGACY_CONTROL_IDS`) — old
  evidence rows must resolve to current controls.
- `packages/risk-engine/src/cis-reconciliation.ts` and
  `cis-reconciliation.test.ts` — the publishable gate (Security Hub status,
  stability window, `blockedBy`); published posture claims depend on it.
- Sanitization tripwires: `scripts/trust-center-sync/map.ts` (and the
  `questionnaire.ts` / `state.ts` outputs it guards), `trust-center/render.ts`,
  and `api-service/src/routes/trust-center.ts` — layers that must never be
  weakened so identifiers cannot reach the public page.
- Auth gates: `api-service/src/middleware/{auth,rbac}.ts` — the Access trusted
  domain, the service-token claim, and role floors.

### 2.2 Data hygiene

- No real account IDs, ARNs, registry namespaces, email addresses, organization
  ids, or internal ticket references in source, tests, or docs. Use the
  established placeholders (`111122223333`, `222233334444`, `o-xxxxxxxxxx`,
  `example.com`).
- Never commit credentials, secrets, or `.env` files.

### 2.3 Change discipline

- Behavior changes update `CHANGELOG.md` (Unreleased), `README.md`, and the
  matching doc: `ARCHITECTURE.md` for design, `OPERATIONAL.md` for runbooks,
  module READMEs for Terraform inputs/outputs.
- Security-sensitive surfaces (auth, publishable endpoint, External Secrets
  wiring, IAM statements, fail-closed logic) require a short "why this is safe"
  note in the PR description.
- Branch naming: `dac/<short-topic>`. Commit and PR creation only when asked.

---

## 3. Where to look

| Topic                                          | Document                                                                                                                                   |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Install on EKS, module inputs, teardown        | [`deploy/terraform/examples/complete/README.md`](deploy/terraform/examples/complete/README.md)                                             |
| Architecture, graph model, reconciliation flow | [`ARCHITECTURE.md`](ARCHITECTURE.md)                                                                                                       |
| Runbooks: IRSA, analyzer, trust-center go-live | [`OPERATIONAL.md`](OPERATIONAL.md) (sections B, J; J.1 is the step-by-step)                                                                |
| Compliance frameworks and mappings             | [`README.md`](README.md) §Compliance, [`packages/risk-engine/src/framework-citations.ts`](packages/risk-engine/src/framework-citations.ts) |
| Trust-center sync and site                     | [`scripts/trust-center-sync/README.md`](scripts/trust-center-sync/README.md), [`trust-center/README.md`](trust-center/README.md)           |
| Deployment validation                          | [`scripts/validate-deployment-modules.sh`](scripts/validate-deployment-modules.sh)                                                         |
| Contributing (humans)                          | [`CONTRIBUTING.md`](CONTRIBUTING.md)                                                                                                       |
| Vulnerability disclosure                       | [`SECURITY.md`](SECURITY.md)                                                                                                               |
