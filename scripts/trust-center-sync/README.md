# trust-center sync

Renders Khalifa's continuously-evaluated CIS posture into the generated
sections consumed by the in-repo trust-center site builder (`trust-center/`).

The only data source is the API's sanitized publishable endpoint
(`GET /compliance/reconciliation/publishable`): requirements that both agreed
with Security Hub for `reconciliation.minAgreementDays` and appear in the
`reconciliation.publishAllowlist`. Statuses only — no accounts, Regions,
counts, evidence, or disagreements ever leave Khalifa (`map.ts` re-projects the
payload and trips on any identifier that survives).

```bash
KHALIFA_API_URL=https://api.example.com \
CF_ACCESS_CLIENT_ID=... CF_ACCESS_CLIENT_SECRET=... \
npm run trust-center:sync
```

| Variable                  | Required | Meaning                                                                                       |
| ------------------------- | -------- | --------------------------------------------------------------------------------------------- |
| `KHALIFA_API_URL`         | yes      | API base URL (through Cloudflare Access)                                                      |
| `CF_ACCESS_CLIENT_ID`     | yes      | Access service token client id; must equal the API's `reconciliation.trustCenterSyncClientId` |
| `CF_ACCESS_CLIENT_SECRET` | yes      | Access service token secret                                                                   |
| `TRUST_CENTER_OUT_DIR`    | no       | Output directory (default `trust-center-config`)                                              |
| `TRUST_CENTER_PUBLIC_URL` | no       | Deployed site URL; reads the previous `posture-state.json` to compute the posture changelog   |

Outputs, written atomically only when the record is `OK`:

- `trust.config.json` — `{ frameworks, controls }`; the endpoint's CIS
  requirements plus any publishable mapped-framework requirements (SOC 2 /
  ISO 27001), with each control domain tagged by `framework`. Same shape as the
  public Fimil trust-center schema, so the output stays portable; the site's
  hand-edited `trust-center/site.config.json` keeps company, contact, and theme
- `build-meta.json` — generated-at timestamp, source record freshness
  (`recordGeneratedAt`, `recordAgeHours`), the API's published staleness window
  (`maxAgeHours`, absent on older endpoints — a warning is logged and the page
  omits the window), and counts for the pipeline log
- `questionnaire.json` — machine-readable answer sheet built from publishable
  requirements only (`implemented`/`partial`) for security questionnaires
- `posture-state.json` — the published posture map plus the rolling changelog
  (newest first, capped at 20). The sync diffs it between publishes and writes
  the changelog into `trust.config.json`; it reads the previous state from the
  output directory first, then from `TRUST_CENTER_PUBLIC_URL/posture-state.json`
  (needed in CI, where the output directory is fresh). Unreadable state simply
  means no changelog

The endpoint also publishes `maxAgeHours`, the window after which a record is
`STALE`; the site's continuous-monitoring statement derives from it, so the
public claim cannot drift from the gate (a contradicting
`monitoring.staleAfterHours` in `trust-center/site.config.json` fails the site
build).

Statuses: `PASS → implemented`, `FAIL → partial`; the framework is
`in-progress` while anything is publishable and `planned` while the record is
OK but lists nothing. It is never `certified`.

Fail-closed: `STALE`/`MISSING` records, HTTP/auth failures, or malformed
payloads leave existing outputs untouched and exit non-zero, so the nightly CI
keeps the previous Cloudflare Pages deployment live.

The nightly workflow (`.github/workflows/trust-center-sync.yml`) runs this tool,
then `npm run trust-center:build` (in-repo site), then deploys
`trust-center/dist` to Cloudflare Pages.

CI configuration (repository variables / secrets):

| Name                                             | Kind   | Meaning                                                       |
| ------------------------------------------------ | ------ | ------------------------------------------------------------- |
| `KHALIFA_API_URL`                                | var    | API base URL                                                  |
| `TRUST_CENTER_PROJECT`                           | var    | Cloudflare Pages project; the workflow is skipped while empty |
| `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET` | secret | Access service token                                          |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`  | secret | Pages deployment                                              |
