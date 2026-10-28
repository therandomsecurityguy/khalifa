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

`site.config.json` is deployment-owned. All fields are optional except
`company.name`:

| Field                                                 | Renders                                                                                                                                                                                   |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `company.name` / `securityEmail` / `website`          | header and contact section; a set email also emits `/.well-known/security.txt`                                                                                                            |
| `links`                                               | footer links                                                                                                                                                                              |
| `theme.primary`, `footerNote`, `title`, `description` | presentation                                                                                                                                                                              |
| `monitoring`                                          | the Continuous monitoring section: `assessmentCadence`, `publishCadence`, optional `staleAfterHours` (must match the API's published window or the build fails), optional `statusPageUrl` |
| `practices`                                           | Security practices bullets                                                                                                                                                                |
| `subprocessors` + `subprocessorsLastUpdated`          | Subprocessors list (an empty array renders an explicit "None")                                                                                                                            |
| `documents`                                           | Documents list; a `url` links, a `requestEmail` renders a request-access mailto                                                                                                           |
| `faqs`                                                | Frequently asked questions                                                                                                                                                                |
| `securityTxt.expiresDays` / `policyUrl`               | RFC 9116 security.txt fields (emitted only with a security email)                                                                                                                         |

Everything posture-related comes from the generated files and is never
hand-edited: `trust.config.json` (framework cards, grouped controls, posture
changelog, series projections), `build-meta.json` (monitoring statement),
`questionnaire.json`
(downloadable answer sheet, linked from Documents), and `posture-state.json`
(published so the next sync can compute the changelog).

The page shows framework and control statuses only, rendered from the
sanitized publishable endpoint (requirements in the
`reconciliation.publishAllowlist` whose Security Hub status — the publication
reference — has held for `reconciliation.minAgreementDays` with no missing
data, plus mapped SOC 2 / ISO 27001 / PCI DSS / NIST SP 800-53 requirements
whose controls are all publishable or assessed). Controls are grouped under
their framework when more than one framework publishes.
The renderer escapes all content, and trips on ARNs, 12-digit account IDs, or
access-key patterns if any ever slip through.

Deployment: `.github/workflows/trust-center-sync.yml` runs the sync, builds
this site, and deploys `trust-center/dist` to Cloudflare Pages
(`TRUST_CENTER_PROJECT`). It stays disabled until the variables and secrets in
`scripts/trust-center-sync/README.md` are configured. Runbooks:
[OPERATIONAL.md](../OPERATIONAL.md) section J.
