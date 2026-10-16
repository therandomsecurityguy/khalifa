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

Outputs, written atomically only when the record is `OK`:

- `trust.config.json` — `{ frameworks, controls }`; the endpoint's CIS
  requirements plus any publishable mapped-framework requirements (SOC 2 /
  ISO 27001), with each control domain tagged by `framework`. Same shape as the
  public Fimil trust-center schema, so the output stays portable; the site's
  hand-edited `trust-center/site.config.json` keeps company, contact, and theme
- `build-meta.json` — generated-at timestamp, source record freshness, and counts
  rendered into the page's publication details

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
