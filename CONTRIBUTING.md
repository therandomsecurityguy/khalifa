# Contributing to Khalifa

Khalifa is an open-source AWS security graph and risk engine. Contributions are welcome.

Working as an AI agent or building automation against this repo? Start from
[`AGENTS.md`](AGENTS.md): it holds the secure AWS install workflow and the
repository conventions agents must follow.

## Development Setup

```bash
npm ci
npm run ci:quality   # format, lint, typecheck, tests, build, packaging smoke
```

## Project Structure

- `lambdas/` — collector, incremental collector, graph writer, policy evaluator, CloudTrail analyzer, DSPM scanner, least-privilege sweep, runtime dispatcher
- `packages/risk-engine/` — Gremlin-based risk rules, CIEM issue lifecycle, compliance evaluators, CIS reconciliation
- `api-service/` — REST API (Express on EKS or Lambda)
- `ui/` — Next.js dashboard
- `cdk/` — Lambda ingestion infrastructure
- `deploy/` — Helm chart, Terraform modules, and the `examples/complete` root module for existing EKS environments
- `trust-center/` + `scripts/trust-center-sync/` — publishable CIS posture sync and the static trust-center site
- `scripts/` — packaging, smoke, and deployment validation scripts

## Adding a New Risk Rule

1. Edit `packages/risk-engine/src/rules.ts`
2. Add a new `RiskRule` entry to `riskRules` array:
   ```typescript
   {
     id: 'RULE-XXX',
     name: '...',
     description: '...',
     severityHint: 'critical' | 'high' | 'medium' | 'low',
     riskFactors: [...baseRiskFactors],
     gremlinQueryTemplate: `
       g.V().has('label', 'Whatever')...
     `,
     ownerTeam: 'your-team',
     enabled: true,
   }
   ```
3. Add a remediation hint in `packages/risk-engine/src/scoring.ts` (`getRemediationHint`)
4. Add a test in `packages/risk-engine/src/rules.test.ts`
5. Map it to at least one control by adding the rule to that control's `relatedRules`, and add an entry to `REVIEWED_MAPPING` in `control-rule-mapping.test.ts` saying why. **A rule maps to a control when every finding it raises is a violation of that control.** Catching only a narrower slice is fine; detecting something merely adjacent is not -- finding root activity is not evidence that a root-activity alarm is missing. Mapping is per rule, not per finding: a rule that starts from several resource types can only map to controls covering all of them, so split it rather than map it to a single-resource CIS control. If no control fits, add a `KH-` control stated as the outcome the rule measures, rather than attaching the rule to the nearest one.

## Adding a New Compliance Control

**CIS v3.0.0 source of truth:** `packages/risk-engine/benchmarks/cis-aws-foundations-3.0.0/`, AWS Security Hub's CIS page stored verbatim. It decides which requirements are automated and which Security Hub control implements each one. Evaluator logic follows that control's page (e.g. `iam-controls.md#iam-9`): its scope (per account, per bucket…) and its pass/fail definition. Automating a requirement Security Hub leaves manual needs an entry in `KHALIFA_AUTOMATED_BEYOND_SECURITY_HUB` with the reason; `cis-v3-source-of-truth.test.ts` enforces both.

1. Edit `packages/risk-engine/src/compliance-types.ts` to add the control to the framework array (e.g., `CIS_AWS_FOUNDATIONS_V3_CONTROLS`)
2. If automated, add an evaluator in `packages/risk-engine/src/compliance-rules.ts`:
   ```typescript
   {
     controlId: 'X.Y',
     evaluate: async (graphClient) => {
       const result = await graphClient.executeQuery('...');
       return { status: 'PASS' | 'FAIL', evidence: [...], issues: [...] };
     },
   }
   ```
3. Add a test in `packages/risk-engine/src/compliance-rules.test.ts` asserting what the
   query targets: the labels and properties it filters on, the ports or thresholds it
   applies, and the direction it traverses any edge. Two suite-wide tests run every
   evaluator, so a new one goes green without a test of its own -- which is how most
   evaluators ended up with no coverage.
4. If a risk rule detects violations of it, list the rule in `relatedRules` under the same criterion as step 5 above, and update `REVIEWED_MAPPING`. A control with no fitting rule is fine; a control given an unrelated one is not.
5. Test it: `cd packages/risk-engine && npm test`

## Adding a New Collector Service

1. Add the AWS SDK client to `lambdas/collector/package.json`
2. Import and instantiate in `lambdas/collector/index.ts` (the `createClients` function)
3. Write a `collectXyz()` function in `lambdas/collector/src/`
4. Call it from the handler
5. Update `cdk/lib/khalifa-stack.ts` and `templates/SecurityGraphCollectorRole.yaml` with required IAM permissions

## Code Style

- TypeScript strict mode everywhere
- ESLint + Prettier via root `npm run lint` / `npm run format`
- Run `npm test` before opening a PR

## Pull Request Checklist

- [ ] `npm run ci:quality` passes
- [ ] Agent/automation changes follow [`AGENTS.md`](AGENTS.md) (load-bearing files, data hygiene, security notes)
- [ ] New rules/controls have tests
- [ ] CHANGELOG.md updated under "Unreleased"
- [ ] README.md (and OPERATIONAL.md/ARCHITECTURE.md where affected) updated if behavior changes
