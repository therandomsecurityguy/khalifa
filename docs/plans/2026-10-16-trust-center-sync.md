# Plan: Khalifa → trust-center sync

Status: phase 1 implemented (2026-10-16)
Supersedes: the original 2026-10-07 trust-center sync plan (written against the pre-parity
fork)
Related: the deployment fork (Helm + Terraform environment wiring), the audit account that
owns the Security Hub delegated administrator

---

## 1. Objective

Render Khalifa's continuously-evaluated CIS posture into the open-source
[Fimil-dev/trust-center](https://github.com/Fimil-dev/trust-center) static site, so the
public page shows "posture as of the last nightly build" without ever exposing evidence,
account IDs, Regions, counts, or disagreements.

## 2. What already exists (audited 2026-10-16 on `main`)

The trust-center plan predates the parity port; most of its khalifa-side plumbing is
already shipped:

| Piece | Where |
| --- | --- |
| `ComplianceFramework = 'CIS_AWS_FOUNDATIONS' \| 'KHALIFA_BASELINE'` (SOC 2/ISO removed, matching the old plan's premise) | `packages/risk-engine/src/compliance-types.ts` |
| CIS reconciliation vs Security Hub at the end of each compliance run (audit-account reader role, agreement tracking, publish allowlist) | `packages/risk-engine/src/cis-reconciliation.ts`, `RECONCILIATION_*` envs |
| Sanitized, statuses-only publishable endpoint | `GET /compliance/reconciliation/publishable` (`api-service/src/routes/trust-center.ts`) |
| Access service-token gate for that endpoint; empty client id accepts no one | `reconciliation.trustCenterSyncClientId`, `requireTrustCenterSync` |
| Helm config (`securityHubRoleArn`, `securityHubRegion`, `minAgreementDays`, `publishAllowlist`, `trustCenterSyncClientId`) | `deploy/helm/khalifa/values.yaml` |
| `sts:AssumeRole` grant for the compliance IRSA role | `deploy/terraform/khalifa-data` (`securityhub_reader_role_arn`) |

### Superseded plan assumptions

1. **Cognito M2M source is out.** Client-credentials tokens carry no email or Cognito
   groups, so they fail the API's role floor. The shipped contract is the Access service
   token: the sync sends `CF-Access-Client-Id` / `CF-Access-Client-Secret` through the
   Access proxy; the API verifies the resulting `cf-access-jwt-assertion` and maps it to
   the service-token claim.
2. **Direct Security Hub reads from the sync are out.** Khalifa reconciles CIS v3.0.0
   against Security Hub internally; the sync consumes only the publishable endpoint.
   The plan's FSBP/"AWS-native controls" section is not covered by khalifa and is
   deferred.

## 3. Phase 1 (this change)

| Piece | Design |
| --- | --- |
| `scripts/trust-center-sync/` | TypeScript, run with `tsx` (`npm run trust-center:sync`). Fetches the publishable endpoint with the service-token headers, maps statuses, emits `trust.config.json` + `build-meta.json` |
| Mapping | `PASS → implemented`, `FAIL → partial`; controls grouped by CIS `section` (`"1. Identity and Access Management"`, …) as trust-center domains; framework status `in-progress` when requirements exist (never `certified`), `planned` when the record is OK but nothing is publishable yet |
| Sanitization | Defensive re-projection of exactly `{requirement, title, section, status}`; tests assert no ARNs, account IDs, or evidence fields reach the output (the endpoint already whitelists; the tool repeats it) |
| Fail-closed | Only an `OK` record writes outputs (atomic write via temp + rename). `STALE`/`MISSING`, HTTP/auth failures, or malformed payloads leave existing files untouched and exit non-zero, so CI keeps the previous Cloudflare Pages deployment live |
| Config contract | `trust.config.json` carries only the generated sections `{ frameworks, controls }` (Fimil-schema shaped); `trust-center/site.config.json` carries the hand-edited site settings (company, contact, links, theme) |
| Tests | New root jest project: mapping, domain grouping, sanitization, transport (local HTTP fixture server), fail-closed (previous outputs untouched) |
| Site | `trust-center/` — in-repo, dependency-free static generator (TypeScript via `tsx`, `npm run trust-center:build`): renders the generated `trust.config.json` + `build-meta.json` plus the hand-edited `trust-center/site.config.json` into plain HTML/CSS in `trust-center/dist/`. No external fork required; the generated config keeps the public Fimil schema shape so adopting that stack later stays possible |
| CI | `.github/workflows/trust-center-sync.yml` — nightly cron + dispatch; skips until `TRUST_CENTER_PROJECT` is configured. Steps: sync → build the in-repo site → `wrangler pages deploy trust-center/dist`. Failure = previous deploy stays live |
| Docs | This plan, an OPERATIONAL runbook section, and a README pointer |

Environment reference (sync tool):

| Variable | Meaning |
| --- | --- |
| `KHALIFA_API_URL` | API base URL through Cloudflare Access |
| `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET` | Access service token (client id must equal `reconciliation.trustCenterSyncClientId`) |
| `TRUST_CENTER_OUT_DIR` | Output directory (default `./trust-center-config`) |

CI configuration (repository variables / secrets):

| Name | Kind | Meaning |
| --- | --- | --- |
| `KHALIFA_API_URL` | var | API base URL |
| `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET` | secret | Access service token |
| `TRUST_CENTER_REPO` | var | trust-center fork (`owner/name`); workflow skipped while empty |
| `TRUST_CENTER_PROJECT` | var | Cloudflare Pages project name |
| `TRUST_CENTER_REPO_TOKEN` | secret (optional) | clone/deploy token when the fork is private or needs push; falls back to `github.token` |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | secret | Pages deployment |

## 4. Phase 2 (deferred, decide before starting)

- **KHALIFA_BASELINE publishing** — the publishable endpoint is CIS-only today. Options:
  extend it to emit sanitized baseline statuses under the same gate, or a second
  endpoint. Requires the same reconciliation-style "publishable" discipline so an
  internal baseline cannot present an unstable page.
- **FSBP / "AWS-native controls"** — requires a second read path (audit account), which
  the in-khalifa reconciliation deliberately removed for CIS. Only pursue if the page
  genuinely needs a second framework.
- **Audit-logging evidence section** — the old plan shipped hand-maintained static facts
  (log coverage, retention, Object Lock); those facts are deployment-specific and were
  genericized out of this repo. Template belongs in the trust-center fork's static config.
- **Richer granularity** — pass-rate percentages, live updates, subprocessor syncing:
  all require relaxing the statuses-only policy first.

## 5. Open decisions

1. Trust-center fork owner/name and Pages project/account/DNS (workflow variables above).
2. Framework-status vocabulary: phase 1 uses `in-progress` for any published state and
   `planned` when nothing is publishable (trust-center has no "implemented" framework
   status and khalifa must never claim `certified`). Revisit if the fork is extended.
3. Whether phase 2 baseline publishing uses the existing endpoint or a new one.

## 6. Follow-ups

- If richer presentation is ever needed (subprocessors, documents, PDFs), either
  extend `trust-center/` or adopt the Fimil Astro stack — the generated config
  already matches its schema, so only the static sections would move.
- Audit-logging evidence section (static, deployment-owned facts) once there is
  a stable source of truth.

---

## 7. Status update (2026-10-16)

Phase 1 shipped (sync tool, in-repo static site, nightly workflow, docs), and
the SOC 2 / ISO 27001 item from phase 2 shipped in a **different form** than
originally planned: instead of restoring parallel catalogs and evaluators, 26
curated requirements cite the canonical controls
(`packages/risk-engine/src/framework-citations.ts`). One assessment pass and
one evidence store now serve CIS, the Khalifa baseline, SOC 2, and ISO 27001;
the publishable endpoint and the trust center both publish mapped requirements
under the same discipline (CIS-mapped controls must be reconciliation-
publishable; baseline-mapped controls must be assessed PASS/FAIL).

Still deferred: FSBP / "AWS-native controls" (no second audit-account read
path), the audit-logging evidence section, pass-rate percentages, and live
updates.

## 8. Status update (2026-10-16, later)

Phase A and B shipped: security practices, subprocessors, public documents,
FAQs, status-page link, `SECURITY.md` + RFC 9116 `security.txt`, the
questionnaire answer sheet (`questionnaire.json`), the rolling posture
changelog ("Recent posture changes"), and the continuous-monitoring proof
(`maxAgeHours` published by the API, cadence + auto-unpublish stated by the
page, build fails on contradiction). Remaining Phase C decisions: gated
document access (public-only for now), pass-rate aggregates (still excluded by
the statuses-only policy), and additional framework citation tables (PCI DSS,
NIST 800-53, C5).
