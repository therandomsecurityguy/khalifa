# CIS AWS Foundations Benchmark v3.0.0: source of truth

`aws-securityhub-cis-aws-foundations-benchmark.md` is the single source of truth
for which CIS v3.0.0 requirements Khalifa treats as automated, and which AWS
Security Hub control implements each one. It is AWS's CIS-certified
implementation of the benchmark, stored verbatim.

|         |                                                                                           |
| ------- | ----------------------------------------------------------------------------------------- |
| Source  | https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.md |
| Fetched | 2026-10-02 23:41 UTC                                                                      |
| SHA-256 | `a771cc270741263b04815c056416f763b64b363e7786dad3797f8fd952bdea4c`                        |

Used by `src/cis-v3-source-of-truth.test.ts`, which fails if the CIS catalogue in
`src/compliance-types.ts` drifts from it:

- Every requirement the page maps to a Security Hub control for v3.0.0 is in the
  catalogue and marked automated.
- Every other automated CIS control is in `KHALIFA_AUTOMATED_BEYOND_SECURITY_HUB`,
  with the reason Khalifa automates what Security Hub leaves manual.

The page does not state what each control checks; that is on the linked control
pages (`iam-controls.md`, `ec2-controls.md`, ...). Evaluator logic should follow
the control page for the mapped control.

## Updating

Replace the file with a fresh copy, update the date and hash above, and run
`npx jest packages/risk-engine/src/cis-v3-source-of-truth.test.ts`. A failure is
a real change in the benchmark mapping, to be reviewed rather than silenced.
