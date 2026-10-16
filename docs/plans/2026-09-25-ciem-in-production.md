# CIEM in production (N12) — plan, NOT applied

## Why this is the top correctness item

Production runs the Terraform/EKS path. The CIEM lambdas are **CDK-only and
undeployed**, so in production:

- no `EffectivePermission`, `EscalationPath` or `LeastPrivilegeFindings` vertices
  are produced by anything
- the identity endpoints (`/identity/*`, least-privilege) read those and are
  permanently empty
- every correctness fix in C1/C2 (fail-loud reads, id-rooted queries, the sweep's
  usage-gap safety) is **moot** until this runs

The mission: run CIEM in the EKS runtime so those surfaces populate.

## Option chosen

**(a) migrate `policy-evaluator` + `least-privilege-sweep` into the EKS runtime**
— the established pattern (a command in `lambdas/runtime/index.ts` plus a CronJob
in the chart). Option (b), deploying the CDK stack, is rejected: nothing else runs
on that path in production, and the runtime pattern is already proven for
`organization-collector`, `dspm-scanner`, `compliance` and `cloudtrail-analyzer`.

## What exists

| Piece | Where |
|---|---|
| Command union (no CIEM entries) | `lambdas/runtime/index.ts:28-34` |
| Per-command help + env validation + dispatch | same file (`validateRuntime`, the `if/else` chain) |
| One CronJob template per workload | `deploy/helm/khalifa/templates/{compliance,dspm-scanner,cloudtrail-analyzer,organization-collector}.yaml` |
| CIEM logic (exports `handler`) | `lambdas/{policy-evaluator,least-privilege-sweep}/index.ts` |
| Runtime image | chart `images.rule_runner` (the `runtime` target) |

## Work

1. **Make the CIEM logic callable as commands.** The runtime imports `runXxx`
   (e.g. `runDspmScan`); the lambdas export `handler`. Add a thin `runPolicyEvaluation`
   / `runLeastPrivilegeSweep` in each that wraps the existing handler, so the
   Lambda path and the runtime path share one implementation (no forked logic).
2. **Register both commands** in `lambdas/runtime/index.ts`: the union, help text,
   env validation, and dispatch. Keep the --check validation honest — a CIEM
   command needs `NEPTUNE_ENDPOINT` and its table names, and should fail fast
   rather than at the first query.
3. **Chart: two CronJob templates**, copied from `compliance.yaml`, with values
   (`schedule`, `image`, `timeZone`, `suspend`, plus `NEPTUNE_ENDPOINT`,
   `ACCESS_ANALYZER_TABLE`, `LEAST_PRIVILEGE_TABLE`).
4. **IRSA.** The jobs need Neptune (the evaluator reads and writes; the sweep
   reads only) and DynamoDB (`AccessAnalyzerCache` read; `LeastPrivilegeFindings`
   write). Follow D1's principle: a role with what that job needs, not a shared
   one. If either job turns out to need nothing beyond the existing rule-runner
   role, say so explicitly rather than silently reusing.
5. **Values** land in the deployment repository that owns the environment
   wiring (the chart values live there), so this is the two-repo path: chart in
   this repo → tag → deployment ref bump → apply.

## Verification (this is what "does it work" means)

1. Trigger one run manually (a suspended-by-default CronJob, or a one-off Job)
   rather than waiting for a schedule.
2. Confirm the graph populates:
   `g.V().hasLabel('EffectivePermission').count()` > 0, `EscalationPath` > 0, and
   `LeastPrivilegeFindings` rows exist.
3. Confirm the API surfaces stop being empty — that is the user-visible outcome.
4. **Idempotency**: run it twice; the id-rooted upserts from B3 must not
   duplicate vertices. This is the cheapest check that the B3 reshaping actually
   works in production.
5. Confirm the sweep does not emit "remove everything" findings — the C1 guard
   skips principals whose usage data is unavailable, and that path is now
   reachable for the first time.

## Risks and mitigations

- **Neptune load.** The evaluator is the heaviest job in the system. B3 bounded
  and id-rooted its reads, which is what makes this viable; schedule it off-peak
  and keep the paging caps.
- **Long runtime.** The Lambda had a 15-minute ceiling; a CronJob does not. That
  is an improvement, but it also means a runaway job is no longer killed for us —
  set a `activeDeadlineSeconds`.
- **First-run volume.** The first run writes every principal's effective
  permission at once. Expect it to be the largest run and schedule accordingly.
- **The correctness work pays off here, not before.** C1's fail-loud and C2's
  reconciled predicates matter only once this runs; until then they are latent.

## Sequencing

1. Steps 1–2 (code, testable locally against the existing unit tests).
2. Step 3–4 (chart + roles), with the CronJob **suspended**.
3. Step 5 (values + ref bump) and apply.
4. Manual trigger → the verification list above → then unsuspend the schedule.
