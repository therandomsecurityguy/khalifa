# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately. Do not open a public issue.

- **Preferred:** GitHub's private vulnerability reporting on this repository
  (Security → Report a vulnerability).
- **Or email** the contact configured by the deployment's trust center
  (`trust-center/site.config.json` → `company.securityEmail`). Deployments
  publish that contact in `/.well-known/security.txt` when it is set.

Include the affected version or commit, reproduction steps, impact, and any
proof of concept.

## What to expect

- Acknowledgement within 5 business days.
- An assessment and fix timeline communicated after triage.
- Credit in the release notes if you want it. There is no bounty program.

## Scope

The Khalifa code in this repository: lambdas, packages, API service, UI, the
Helm chart, the Terraform modules, the trust center, and CI. Deployments are
operated by their owners — for an issue in someone's running deployment,
contact that operator first.

The strongest points of interest are the auth gates
(`api-service/src/middleware/{auth,rbac}.ts`), the publishable endpoint and its
sanitization (`api-service/src/routes/trust-center.ts`), the trust-center
sync/site tripwires, and the IAM/IRSA definitions in
`deploy/terraform/khalifa-data`.

## Safe harbor

We will not pursue legal action for good-faith research that stays within your
own deployment or the public surface this project exposes, avoids privacy
violations and service disruption, and reports findings privately first.
