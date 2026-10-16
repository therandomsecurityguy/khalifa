# trust-center

Static, dependency-free trust-center site generated from the sync tool's
output. The deploy pipeline renders Khalifa's publishable CIS posture into two
JSON files (`scripts/trust-center-sync`), then this builder turns them plus a
hand-maintained site config into plain HTML/CSS in `dist/` — no framework, no
runtime JavaScript.

```bash
# produce the generated posture first (reads the API)
npm run trust-center:sync

# render the site into trust-center/dist
npm run trust-center:build

# preview the files however you like, e.g.
npx serve trust-center/dist
```

| Flag          | Default                         | Meaning                                                |
| ------------- | ------------------------------- | ------------------------------------------------------ |
| `--config`    | `trust-center/site.config.json` | Hand-maintained site settings                          |
| `--generated` | `trust-center-config`           | Directory with `trust.config.json` + `build-meta.json` |
| `--out`       | `trust-center/dist`             | Output directory                                       |

`site.config.json` is deployment-owned: company name, optional security email,
website, links, accent color, footer note, and the `monitoring` block
(assessment/publication cadence, plus an optional `staleAfterHours` claim).
The monitoring statement is derived from the generated `build-meta.json` — the
API's published staleness window — and the build fails if the configured claim
contradicts it. Everything posture-related comes from the generated files and
is never hand-edited.

The page shows framework and control statuses only, rendered from the
sanitized publishable endpoint (requirements that agreed with Security Hub for
`reconciliation.minAgreementDays` and passed `reconciliation.publishAllowlist`,
plus mapped SOC 2 / ISO 27001 requirements whose controls are all publishable
or assessed). Controls are grouped under their framework when more than one
framework publishes.
The renderer escapes all content, and trips on ARNs, 12-digit account IDs, or
access-key patterns if any ever slip through.

Deployment: `.github/workflows/trust-center-sync.yml` runs the sync, builds
this site, and deploys `trust-center/dist` to Cloudflare Pages
(`TRUST_CENTER_PROJECT`). It stays disabled until the variables and secrets in
`scripts/trust-center-sync/README.md` are configured. Runbooks:
[OPERATIONAL.md](../OPERATIONAL.md) section J.
