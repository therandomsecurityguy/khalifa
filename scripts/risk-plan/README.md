# risk-plan

Predictive, pre-deploy analysis for Terraform: which catalogue rules would a
plan's creations and updates feed, and where would the resulting paths run?

```bash
terraform plan -out plan.out
terraform show -json plan.out > plan.json
npm run risk:plan -- plan.json                      # fails (exit 1) on anything >= high
npm run risk:plan -- plan.json --min-severity critical
npm run risk:plan -- plan.json --json               # machine-readable

# IAM policy diff (outside Terraform too):
npm run risk:plan -- --policy after.json --policy-before before.json
# Helm values for the chart:
npm run risk:plan -- --helm-values values.yaml
```

Exit codes: `0` no finding at or above the minimum severity, `1` the gate
failed, `2` usage or plan-file error.

Checks and the rule they predict (the same catalogue the live engine runs):

| Change                                                         | Rule                               |
| -------------------------------------------------------------- | ---------------------------------- |
| world-open ingress covering SSH (22) or RDP (3389)             | RULE-002                           |
| trust policy allowing an account root or `Principal: *`        | RULE-006                           |
| bucket ACL public, public-access block disabled, anyone policy | RULE-007                           |
| `publicly_accessible = true` RDS                               | RULE-008                           |
| EKS endpoint with `0.0.0.0/0` in `public_access_cidrs`         | RULE-019                           |
| function URL with `authorization_type = "NONE"`                | RULE-009                           |
| secret resource policy allowing anyone or an account root      | RULE-010                           |
| EC2 instance without enforced IMDSv2                           | RULE-024                           |
| world-open ingress on any other port                           | no rule yet — still fails the gate |

A plan knows less than collection does (data classification, which accounts are
collected, the real topology), so findings say what collection would add. The
catalogue is local (`catalogue.ts`) so the script needs no built engine at
runtime; `catalogue.test.ts` pins it to the engine's names and severities.

IAM policies are parsed with the same parser the CIEM evaluator runs
(`lambdas/policy-evaluator/policy-parser.ts`), and with a before document
(plan `change.before`, or `--policy-before` for standalone files) the checks
are a diff: a grant that already existed is not newly introduced. Statement
conditions, SCPs and permission boundaries are **not** evaluated; findings
whose statement has conditions say so. `--helm-values` reads the chart values
with the same YAML a `helm install` would; only ingress that decides network
reach is judged today.

Optional CI gate (a plan artifact has to come from the pipeline that runs
`terraform plan`):

```yaml
- name: Risk-check the plan
  run: |
    terraform -chdir=env plan -out plan.out
    terraform -chdir=env show -json plan.out > plan.json
    npm run risk:plan -- plan.json --min-severity high

- name: Risk-check the chart values
  run: npm run risk:plan -- --helm-values deploy/helm/khalifa/values.yaml
```
