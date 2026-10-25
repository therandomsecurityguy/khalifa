# Plan: remaining upstream parity port (khalifa-main → this repo)

Status: planned (2026-10-24); G1 merged (PR #23); G2 merged (PR #24); G5 merged (PR #25) — mirror-workflow decision (§7.3) still open; G3 implemented on `dac/parity-g3-secrets` (2026-10-24) with §7.2 decided (auto-ticketing stays off for RULE-006/031–034) and no mapped-framework citations added for KH-IAM-3. Next: G4 (compliance correctness), then G6.
Source of truth for the gap list: a working-tree snapshot of the upstream repo at
`~/Desktop/khalifa-main` (2026-10-23, no `.git`), compared against this repo's `main`.
Read-only reference — nothing is copied wholesale; every port is scrubbed and merged.

---

## 1. Objective

Close the remaining feature gap between this repo and the upstream snapshot:
secrets inventory and its risk rules, collector coverage/correctness fixes, the
CIEM pass-role detector, compliance-engine resilience, Security Hub-authoritative
reconciliation, and the supporting UI, chart, IAM, and test infrastructure.

Explicitly **out of scope** (this repo is ahead or the difference is snapshot-specific):

- Trust center (site, sync, publishable-endpoint changes) — already shipped here.
- The snapshot's private SOC2 Terraform module (`tf-mod-s3-soc2-compliant-bucket`)
  and its GitHub-App-token CI plumbing — this repo keeps the inline
  `s3-access-logging.tf`.
- Snapshot defaults that are regressions here (us-west-2 defaults, hardcoded
  `khalifa-registry` repo/subject, older release workflow) and all
  identifier-bearing text (see §2).

## 2. Guardrails

1. **Scrub on port.** The snapshot contains internal ticket refs (`SEC-*`), real
   account IDs/regions, internal names, and an internal-domain auth helper.
   Apply AGENTS.md §2.2 placeholders; never port those values.
2. **Never weaken load-bearing files** (AGENTS.md §2.1). Adding RULE-031–034 and
   the KH-IAM-3 control requires deliberate, PR-called-out updates to:
   `packages/risk-engine/src/control-rule-mapping.test.ts` (`REVIEWED_MAPPING`),
   `packages/risk-engine/src/compliance-types.ts` (`LEGACY_CONTROL_IDS`, catalog),
   and a decision on `framework-citations.ts` (golden list).
3. **Merge additively into this repo's newer files** — never overwrite:
   `api-service/src/app.ts`, `services/neptune-client.ts`,
   `packages/risk-engine/src/{compliance-engine,compliance-types,cis-reconciliation,index,run-compliance-once}.ts`,
   `rules.graph.test.ts`, Helm `values*.{yaml,json}`/`configmap.yaml`,
   `jest.config.js`, `package.json`, `middleware/{auth,rbac}.ts`,
   `README/ARCHITECTURE/OPERATIONAL/CHANGELOG`, `khalifa-registry`, CI `release.yml`.
4. **IAM widening** (`lambda:GetPolicy`, `lambda:ListFunctionUrlConfigs` on the
   spoke policy and `PlatformRead`) needs the AGENTS.md §1.1 operator
   confirmation before apply.
5. One `dac/<topic>` branch + PR per phase (§4), each with `CHANGELOG.md`
   **Unreleased** entries and the matching doc updates per AGENTS.md §2.3.

## 3. Gap inventory

### G1 — Shared foundations (port first, everything else depends on it)

| Item                       | Snapshot source                                                              | Notes                                                                                                     |
| -------------------------- | ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| ReDoS-safe glob matcher    | `packages/risk-engine/src/glob.ts`, `glob.test.ts`, export in `index.ts`; `lambdas/shared/glob.ts` | Prereq for secret readers and the policy-evaluator regex swap (G5). Non-backtracking `*`/`?` matching.    |
| Graph write integrity      | `lambdas/shared/graph-repository.ts` (~112 lines), `lambdas/shared/types.ts` | Chunked writes: `aggregate('written').by(T.id)` + `cap()` (currently every chunk silently re-runs element-by-element); batched reconcile (`RECONCILE_BATCH_SIZE=1000`, warning when capped); validated `clearProperties` applied via `sideEffect` on refresh only. |
| Graph integration tests    | `lambdas/graph-writer/graph-repository.graph.test.ts`, `packages/risk-engine/jest.graph.config.js` (third `graph-writer` project), root `jest.config.js` `testPathIgnorePatterns`, `test/gremlin/Dockerfile` | Keep this repo's workflow override (`vars.GREMLIN_SERVER_IMAGE`) or adopt the snapshot's GHCR mirror (open decision §7.3). |

### G2 — Collector coverage and correctness

| Item                        | Snapshot source                                        | Notes                                                                                                                |
| --------------------------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------- |
| Role-vertex id normalization| `lambdas/collector/src/iam-ids.ts` (+test)             | `roleVertexId()` strips role paths; wire into `index.ts` (Lambda `HAS_IAM_ROLE`, trust `TRUSTS`, IAM role vertices) and `cross-account.ts` (no duplicate path-ARN `IamRole`). Fixes RULE-009 / RULE-004 misses. |
| EC2 instance-profile roles  | `instance-profiles.ts` (+test)                         | `ListInstanceProfiles` → `HAS_IAM_ROLE` edges; `undefined` on AccessDenied so older member stacks don't fail the stage. Wire into `collectEc2`. |
| Lambda exposure             | `lambda-exposure.ts` (+test)                           | Function URLs (auth type) + resource policies (aliases included); denies → `lambda_exposure_restricted`. IAM: `lambda:GetPolicy`, `lambda:ListFunctionUrlConfigs` in `khalifa-data/iam.tf` `PlatformRead` and `templates/SecurityGraphCollectorRole.yaml` (+ role-template test). |
| Generic secret inventory    | `collectSecrets` export in `index.ts`, `secret-ages.ts` (+test), `secrets.test.ts`, `kms.test.ts` | `collection_restricted: true` stubs for denied `DescribeSecret`/`GetResourcePolicy`/`DescribeKey`; age properties (`created_at`, `days_since_rotation`, `days_since_access`); SSM parameter ARN single-slash fix. |
| Credential-report waiting   | `iam-posture.ts` (+test)                               | Generate + poll up to 60 s; expired/not-ready → stage fails instead of recording an empty "complete" (CIS 1.5/1.10/1.12 correctness). |
| Exposure semantics          | `exposure.ts` (+test), `index.ts`                      | Write `true`/`false` always, but skip `false` when network stages failed or Lambda exposure was restricted; `function_url_public`/`public_invoke_policy` into `deriveIsInternetExposed`; clear `public_ip` on EC2. |
| Tag hygiene                 | `tags.ts` (+test), `index.ts`                          | Clear stale tag-derived properties after a successful lookup; skip ECR digest ARNs (`isTaggableArn`). |
| Principal-aware statements  | `policy-statements.ts` (+test), `index.ts`             | `principalIsAnyone`, `principalAccountIds`, `isOrgRestricted`, `deriveStatementPrincipalProperties`; emit `SHARES_WITH` edges to foreign `:root` accounts for Allow statements. Prereq for RULE-010 rewrite. |
| ExternalAccount scoping     | `index.ts` (scoping pass)                              | Leave `ExternalAccount` unscoped (like Internet/AWS-managed policies) so `account_id` survives; prereq for RULE-006. |
| Timing logs                 | `index.ts`, `collection-stage.test.ts`                 | `durationMs`, `writeMs`, `slowestStages` (top 5) in completion logs. |
| Prod-account marking        | `lambdas/shared/account-inventory.ts`, `list-accounts/index.ts` (+tests) | `PROD_ACCOUNT_IDS` parse/validate; `is_prod` on `AwsAccount`; warn on configured-but-uncollected IDs. Prereq for RULE-032. |
| Fair org collection         | `lambdas/runtime/index.ts` (+test)                     | Fisher–Yates `shuffle()` over `inventory.workItems` (injectable RNG). |
| DSPM opt-in gate            | `lambdas/dspm-scanner/{index.ts,src/s3-sampler.ts}` (+`handler.test.ts`) | SQS path requires the bucket's `dspm-scan=true` tag (memoized, fails closed); early return when `DSPM_SCAN_MODE=off`. |

### G3 — Secrets inventory feature (user-facing)

Depends on G1 (glob, graph-repository) and G2 (secret/age properties, `is_prod`, `SHARES_WITH`).

| Layer       | Snapshot source                                                                                              | Notes |
| ----------- | ------------------------------------------------------------------------------------------------------------ | ----- |
| API reads   | `api-service/src/services/neptune-client.ts` additions: `getResources`, `listSecrets`, `listSecretAccounts`, `getSecret`, `secretReaderRows` (+ `SecretRecord`/`SecretShare` types) | Merge additively into this repo's client. |
| API routes  | `routes/secrets.ts`, `services/secret-readers.ts`, `services/secret-reader-counts.ts`, `app.ts` wiring (`GET /secrets`, `/secrets/reader-counts`, `/secrets/:arn(*)` behind `validateArnPathParam` + `requireViewer` + `expensiveRateLimiter`), `types/index.ts`, 3 test files | |
| Issues API  | `routes/issues.ts` + `__tests__/issue-attack-path.test.ts`: `involvedResources` (off-path vertices via `getResources`, cap 200, failure-tolerant) and `deleted_label` enrichment | |
| Risk rules  | `rules.ts`: RULE-031 (admin user with active key), RULE-032 (prod secret shared with non-prod), RULE-033 (secret shared to another account), RULE-034 (pass-role to compute — depends on G5), helpers `SECRET_SHARE_PATH`/`SHARES_OUTSIDE`/`SHARES_NON_PROD`; `types.ts` `maxSeverity`; `runner.ts` `cappedSeverity()`; `scoring.ts` hints; `rules.test.ts`, `rules.graph.test.ts` (fold into this repo's harness), `control-rule-mapping.test.ts` (+4 reviewed mappings) | Auto-ticketing off in the snapshot (open decision §7.2). |
| Catalog     | `compliance-types.ts`: new KH-IAM-3; KH-IAM-2 gains RULE-034; KH-SEC-1 gains RULE-032/033; `LEGACY_CONTROL_IDS`; decide framework citations | |
| Chart       | `collection.prodAccountIds` → `PROD_ACCOUNT_IDS` (`values.yaml`, `values.schema.json`, `templates/configmap.yaml`) | Keep this repo's `dspmScanner` mountIn etc. |
| UI          | `components/search-select.tsx` (+test), `components/severity-counts.tsx`, `lib/finding-groups.ts` (+test), `lib/secrets.ts` (+test), `app/secrets/page.tsx` (+test), `app/secrets/detail/page.tsx` (+test), `lib/routes.ts` nav + `secretHref`, `lib/api.ts` (`getSecrets`/`getSecretReaderCounts`/`getSecret`), `types/index.ts` | Port `search-select` first (also used by Resources). |
| UI polish   | `app/resources/page.tsx` (SearchSelect), `app/issues/[id]/page.tsx` (involved resources + grouped SecurityHub findings), `components/attack-graph.tsx` (deleted-resource rendering), `components/column-filter.tsx` (counts), `components/ui.tsx` (`min-w-0`, `Table className`), `lib/evidence.ts` (new fact templates + RULE-031–034) | |
| Integrations| `packages/integrations/src/sinks/slack-sink.ts` (`SLACK_WEBHOOK_SECRET_ARN`, lazy resolution, `{SLACK_WEBHOOK_URL}` JSON, ARN-validating health check) + `slack-sink.test.ts`; `orchestrator.test.ts` env cleanup; CDK `SlackWebhookSecret` + read grant | |

### G4 — Risk engine / compliance correctness

| Item                        | Snapshot source                                        | Notes |
| --------------------------- | ------------------------------------------------------ | ----- |
| Fresh coverage              | `compliance-rules.ts`: `COLLECTION_MAX_AGE_MS` (8 h) + `freshCoverage()` requiring `status: 'SUCCEEDED'`; `accountRegionsUnreadable`; CIS 3.6 unreadable-KMS handling; CIS 3.4 rewrite (bucket-name queries, S3 name validation) + `compliance-rules.test.ts`, `rules.graph.test.ts` | Prevents SKIPPED stages / stale coverage from passing IAM & S3 controls. |
| Run resilience              | `compliance-engine.ts`: `assess()` + `runAllAssessments()` returning `{reports, failures}`; `run-compliance-once.ts` reconciles first, then throws | Merge with this repo's mapped-framework derivation so one failed framework still yields a reconciliation record. |
| SH-authoritative reconciliation | `cis-reconciliation.ts`: `securityHubStatus`, `securityHubNoData`, `securityHubNotEvaluated`, `khalifaFailuresFilled`, `stableSince`/`stableDays`, `blockedBy`, `CONFIG_EVALUATIONS_EMPTY` → no result, `MAX_RECORD_GAP_MS` (6 h) + `AGREEMENT_EPOCH` (+ test file) | Behavioral change to what is publishable; reconcile with this repo's mapped-framework gating and trust-center expectations (open decision §7.1). |
| Rule fixes                  | `rules.ts`: RULE-006 `external_account_id` (+ auto-ticket off), RULE-010 resource-policy rewrite, RULE-003 workload-first, RULE-009 keyed on `is_internet_exposed`, RULE-030 excludes `pass_role` | Each needs its REVIEWED_MAPPING entry re-checked. |

### G5 — CIEM pass-role

| Item                  | Snapshot source                                              | Notes |
| --------------------- | ------------------------------------------------------------ | ----- |
| Pass-role detection   | `lambdas/policy-evaluator/pass-role.ts` (+test)              | `iam:PassRole` grants, `iam:PassedToService`, same-account service-trusting admin roles with path-aware ARNs. |
| Wiring                | `policy-evaluator/index.ts`, `types.ts` (`'pass_role'`, `via`), `fetchPoliciesForPrincipal` group union + dedup, `via_services` on paths, distinct `can-escalate:pass-role:` edge id | Prereq for RULE-030 exclusion and RULE-034 matching. |
| Matcher swap          | `condition-evaluator.ts`, `policy-parser.ts`, `policy-statements.ts` use `globMatch` | Same change as G1 glob. |

### G6 — Build, CI, and dependency hygiene

- `.dockerignore`: add `.env`, `.env.*`, `*.pem` patterns.
- `.nvmrc` 24.22.1; `Dockerfile` Chainguard digest bump + Node version assertion;
  `ui/package.json` Next `^16.4.2` (+ lockfiles); CDK least-privilege-sweep
  `NODEJS_24_X`.
- Re-evaluate `.github/npm-audit-baseline.json` (this repo carries one extra
  suppression; keep unless a failure proves otherwise).
- Do **not** port: the snapshot's GitHub-App-token CI steps, private-module
  Terraform source, `khalifa-registry` hardcoding, region default flips, or
  snapshot doc wording.

## 4. Sequencing

| Phase | Contents                                                        | Exit criteria |
| ----- | --------------------------------------------------------------- | ------------- |
| 0     | G1 foundations + G5 matcher swap                                | `glob` and graph-repository tests green; graph-queries job still green |
| 1     | G2 collector + IAM grants (TF + spoke template) + G5 pass-role  | Collector tests green; role-template test pins new actions; pass-role tests green |
| 2     | G3 secrets feature (API → rules/catalog → chart → UI → integrations) | Secrets routes/UI tests green; `npm run ci:quality`; REVIEWED_MAPPING called out in PR + CHANGELOG |
| 3     | G4 compliance correctness (freshCoverage → run resilience → SH reconciliation → rule fixes) | Compliance/reconciliation suites green; trust-center publishable tests unaffected |
| 4     | G6 hygiene + README/ARCHITECTURE/OPERATIONAL/CHANGELOG updates  | Full `npm run ci:quality`; docs match behavior |

Each phase is its own branch/PR (`dac/…`) per AGENTS.md §2.3.

## 5. Verification

1. Per phase: `npx jest --selectProjects <affected>`; before PR: `npm run ci:quality`.
2. Graph tests: ported Gremlin Dockerfile + `graph-writer` jest project; confirm the
   graph-queries workflow runs them.
3. Helm/TF: `bash scripts/validate-deployment-modules.sh`; `terraform test` in
   `khalifa-data` / `khalifa-registry` / `khalifa-eks`.
4. Manual smoke: `GET /secrets`, `/secrets/reader-counts`, `/secrets/:arn`,
   `/issues/:id` (`involvedResources`); Secrets nav + list/detail pages; after a
   collector run, secret properties, `SHARES_WITH`, `is_prod`, and role edges at
   path-free vertices; after a policy-evaluator run, `pass_role` escalation edges.
5. Fail-closed regressions: reconciliation `NO_SECURITY_HUB_RESULT` /
   `SECURITY_HUB_NO_DATA` / record-gap tests; trust-center sync tests still pass.

## 6. Risks

- **Merge collisions** in this repo's newer files (engine, chart, app wiring) —
  mitigate with additive merges and per-phase targeted tests.
- **Rule/control ripple**: new RULE-031–034 + KH-IAM-3 touch REVIEWED_MAPPING,
  citations, catalog counts, and README compliance numbers; each must be
  deliberate and documented.
- **Reconciliation behavior change** may alter trust-center output; the §7.1
  decision must be made before phase 3.
- **Data hygiene**: snapshot tests and changelog text carry identifiers; scrub
  every ported file (no automated tripwire outside the trust-center build).
- **IAM widening** needs explicit operator confirmation before apply.

## 7. Open decisions

1. Does SH-authoritative reconciliation replace Khalifa-agreement gating for the
   trust center's mapped frameworks, or do they coexist?
2. Auto-ticketing for RULE-006/031–034: keep the snapshot's "off" or enable?
3. Gremlin image: adopt the snapshot's GHCR mirror or keep Docker Hub + override
   and only add the hardened Dockerfile?
4. Runtime/dependency bumps in their own PR or folded into phase 4?
5. Should the private SOC2 module ever be adopted here, or is the inline
   `s3-access-logging.tf` final?
