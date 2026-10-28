import type {
  BuildMeta,
  ControlStatus,
  FrameworkStatus,
  GeneratedConfig,
  GeneratedControlDomain,
  GeneratedFramework,
  SiteConfig,
} from './types';

export interface RenderedSite {
  'index.html': string;
  'styles.css': string;
}

const STATUS_LABELS: Record<ControlStatus, string> = {
  implemented: 'Implemented',
  partial: 'Partial',
  planned: 'Planned',
};

const FRAMEWORK_LABELS: Record<FrameworkStatus, string> = {
  certified: 'Certified',
  'in-progress': 'In progress',
  planned: 'Planned',
};

const DEFAULT_PRIMARY = '#1e3a8a';
const DEFAULT_FRAMEWORK = 'CIS_AWS_FOUNDATIONS';

export interface SiteAssets {
  /** questionnaire.json was published into dist; render its download link. */
  questionnaire?: boolean;
}

export function renderSite(
  config: SiteConfig,
  generated: GeneratedConfig,
  meta: BuildMeta | null,
  now: Date = new Date(),
  assets: SiteAssets = {}
): RenderedSite {
  const title = config.title?.trim() || `${config.company.name} Trust Center`;
  const frameworks = generated.frameworks ?? [];
  const controls = generated.controls ?? [];
  const generatedAt = meta?.generatedAt ?? now.toISOString();
  const recordAt = meta?.source?.recordGeneratedAt ?? null;

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(config.description ?? `Security posture for ${config.company.name}.`)}"/>
<link rel="stylesheet" href="./styles.css"/>
</head>
<body>
<header class="site-header">
  <div class="wrap">
    <p class="eyebrow">Trust Center</p>
    <h1>${escapeHtml(config.company.name)}</h1>
    <p class="lede">${escapeHtml(config.description ?? 'Continuously evaluated security posture, published from automated configuration checks.')}</p>
  </div>
</header>
<main class="wrap">
${frameworks.map((framework) => renderFramework(framework)).join('\n')}
${renderControlsGrouped(frameworks, controls)}
${renderPractices(config)}
${renderDocuments(config, assets)}
${renderSubprocessors(config)}
${renderChangelog(generated.changelog)}
${renderProjections(generated.projections)}
${renderProvenance(generatedAt, recordAt, config.monitoring, meta?.source?.maxAgeHours)}
${renderFaq(config)}
${renderContact(config)}
</main>
<footer class="site-footer">
  <div class="wrap">
    ${config.links && config.links.length > 0 ? `<nav aria-label="Links">${config.links.map((link) => `<a href="${escapeHtml(link.href)}">${escapeHtml(link.label)}</a>`).join('')}</nav>` : ''}
    <p>${escapeHtml(config.footerNote ?? 'This page reflects automated configuration posture. It is not a certification or an audit report.')}</p>
  </div>
</footer>
</body>
</html>
`;

  const styles = buildStyles(config.theme?.primary);

  assertNoIdentifiers(html);
  return { 'index.html': html, 'styles.css': styles };
}

function renderFramework(framework: GeneratedFramework): string {
  const label = FRAMEWORK_LABELS[framework.status] ?? framework.status;
  return `<section class="card" aria-labelledby="framework-${slug(framework.name)}">
  <div class="card-head">
    <h2 id="framework-${slug(framework.name)}">${escapeHtml(framework.name)}</h2>
    <span class="badge badge-${escapeHtml(framework.status)}">${escapeHtml(label)}</span>
  </div>
  ${framework.description ? `<p>${escapeHtml(framework.description)}</p>` : ''}
  ${framework.lastVerified ? `<p class="muted">Posture verified ${escapeHtml(framework.lastVerified)}</p>` : ''}
</section>`;
}

function renderControlsGrouped(
  frameworks: NonNullable<GeneratedConfig['frameworks']>,
  controls: GeneratedControlDomain[]
): string {
  if (controls.length === 0) return '';

  // Bucket domains by framework; controls without a framework id belong to the
  // first declared framework (single-framework configs omit the field).
  const buckets = new Map<string, GeneratedControlDomain[]>();
  for (const domain of controls) {
    const key = domain.framework ?? frameworks[0]?.id ?? DEFAULT_FRAMEWORK;
    const list = buckets.get(key) ?? [];
    list.push(domain);
    buckets.set(key, list);
  }

  const ordered: Array<{ heading: string | null; domains: GeneratedControlDomain[] }> = [];
  const seen = new Set<string>();
  for (const framework of frameworks) {
    const key = framework.id ?? DEFAULT_FRAMEWORK;
    const domains = buckets.get(key);
    if (!domains) continue;
    seen.add(key);
    ordered.push({ heading: framework.name, domains });
  }
  for (const [key, domains] of buckets) {
    if (!seen.has(key)) ordered.push({ heading: key, domains });
  }

  // Single-framework configs keep the original heading-free layout.
  const grouped = ordered.length > 1;
  return ordered
    .map(({ heading, domains }) => {
      const cards = renderDomainCards(domains);
      if (!grouped) return cards;
      return `<section class="framework-controls" aria-label="${escapeHtml(heading ?? 'Controls')}">
  <h2 class="section-title">${escapeHtml(heading ?? 'Controls')}</h2>
  ${cards}
</section>`;
    })
    .join('\n');
}

function renderDomainCards(controls: GeneratedControlDomain[]): string {
  const sorted = [...controls].sort((a, b) =>
    a.domain.localeCompare(b.domain, 'en', { numeric: true })
  );
  return `<section class="cards" aria-label="Controls by domain">
${sorted
  .map(
    (domain) => `<div class="card">
  <h2>${escapeHtml(domain.domain)}</h2>
  <ul class="controls">
${[...domain.items]
  .sort((a, b) => a.title.localeCompare(b.title, 'en', { numeric: true }))
  .map(
    (item) => `    <li>
      <span class="badge badge-${escapeHtml(item.status)}">${escapeHtml(STATUS_LABELS[item.status] ?? item.status)}</span>
      <span class="control-title">${escapeHtml(item.title)}</span>
      ${item.description ? `<span class="control-description">${escapeHtml(item.description)}</span>` : ''}
    </li>`
  )
  .join('\n')}
  </ul>
</div>`
  )
  .join('\n')}
</section>`;
}

function renderProjections(projections: GeneratedConfig['projections']): string {
  if (!projections || projections.length === 0) return '';
  const items = projections
    .map((projection) => {
      const movement =
        projection.perDay === 0
          ? 'holding flat'
          : projection.perDay > 0
            ? `rising ${Math.abs(projection.perDay)}/day`
            : `falling ${Math.abs(projection.perDay)}/day`;
      return `<li><strong>${escapeHtml(projection.label)}</strong> is ${movement} over the last ${projection.basisDays} days (${escapeHtml(projection.confidence)} confidence), projecting to about ${projection.projectedValue} in ${projection.horizonDays} days.</li>`;
    })
    .join('\n');
  return `<section class="card" aria-label="Projection">
  <h2 class="section-title">Where the posture is heading</h2>
  <p>Straight-line projections over the published series, with a noise band. These are predictions, not commitments, and they publish only while the underlying assessment is current.</p>
  <ul>${items}</ul>
</section>`;
}

function renderProvenance(
  generatedAt: string,
  recordAt: string | null,
  monitoring: SiteConfig['monitoring'],
  maxAgeHours: number | undefined
): string {
  const cadence = monitoring?.assessmentCadence?.trim();
  const publishCadence = monitoring?.publishCadence?.trim() ?? 'on a schedule';
  const monitored = cadence
    ? `Continuously monitored by Khalifa: assessments run ${escapeHtml(cadence)} against the AWS configuration.`
    : 'Continuously monitored by Khalifa.';
  const published = `The page is rebuilt ${escapeHtml(publishCadence)}; last build ${escapeHtml(generatedAt)}${recordAt ? `, assessment recorded ${escapeHtml(recordAt)}` : ''}.`;
  const unpublish =
    maxAgeHours !== undefined && maxAgeHours > 0
      ? ` When the last assessment is older than ${escapeHtml(String(maxAgeHours))} hours, every framework unpublishes automatically until assessments resume.`
      : '';
  const statusPage = monitoring?.statusPageUrl?.trim()
    ? ` Service availability: <a href="${escapeHtml(monitoring.statusPageUrl.trim())}">status page</a>.`
    : '';
  return `<section class="provenance" aria-label="Continuous monitoring">
  <h2>Continuous monitoring</h2>
  <p>${monitored} ${published}${statusPage}</p>
  <p>Requirements appear here only after repeated agreement with the account's Security Hub configuration and an explicit publish allowlist.${unpublish}</p>
</section>`;
}

function renderPractices(config: SiteConfig): string {
  const practices = (config.practices ?? []).filter((entry) => entry.trim().length > 0);
  if (practices.length === 0) return '';
  return `<section class="provenance" aria-label="Security practices">
  <h2>Security practices</h2>
  <ul class="plain-list">
${practices.map((entry) => `    <li>${escapeHtml(entry)}</li>`).join('\n')}
  </ul>
</section>`;
}

function renderDocuments(config: SiteConfig, assets: SiteAssets): string {
  const documents = config.documents ?? [];
  const questionnaire = assets.questionnaire === true;
  if (documents.length === 0 && !questionnaire) return '';
  return `<section class="provenance" aria-label="Documents">
  <h2>Documents</h2>
  <ul class="plain-list">
${documents
  .map((document) => {
    const label = escapeHtml(document.label);
    if (document.url) return `    <li><a href="${escapeHtml(document.url)}">${label}</a></li>`;
    if (document.requestEmail)
      return `    <li>${label} — <a href="mailto:${escapeHtml(document.requestEmail)}?subject=Document%20request%3A%20${encodeURIComponent(document.label)}">request access</a></li>`;
    return `    <li>${label}</li>`;
  })
  .join('\n')}
${questionnaire ? '    <li><a href="./questionnaire.json">Download the security questionnaire answer sheet (JSON, statuses only)</a></li>' : ''}
  </ul>
</section>`;
}

function renderSubprocessors(config: SiteConfig): string {
  if (config.subprocessors === undefined) return '';
  const subprocessors = config.subprocessors;
  const updated = config.subprocessorsLastUpdated?.trim();
  const items =
    subprocessors.length === 0
      ? '    <li>None. This deployment processes data inside its own AWS account.</li>'
      : subprocessors
          .map((vendor) => {
            const dpa = vendor.dpaUrl ? ` · <a href="${escapeHtml(vendor.dpaUrl)}">DPA</a>` : '';
            return `    <li><strong>${escapeHtml(vendor.name)}</strong> — ${escapeHtml(vendor.purpose)} (${escapeHtml(vendor.location)})${dpa}</li>`;
          })
          .join('\n');
  return `<section class="provenance" aria-label="Subprocessors">
  <h2>Subprocessors</h2>
  <ul class="plain-list">
${items}
  </ul>
  ${updated ? `<p class="muted">Last updated ${escapeHtml(updated)}</p>` : ''}
</section>`;
}

function renderChangelog(changelog: GeneratedConfig['changelog']): string {
  const entries = changelog ?? [];
  if (entries.length === 0) return '';
  return `<section class="provenance" aria-label="Posture changes">
  <h2>Recent posture changes</h2>
  <ul class="plain-list">
${entries
  .slice(0, 20)
  .map(
    (entry) =>
      `    <li><span class="muted">${escapeHtml(entry.date)}</span> — ${escapeHtml(entry.title)}${entry.description ? ` <span class="control-description">${escapeHtml(entry.description)}</span>` : ''}</li>`
  )
  .join('\n')}
  </ul>
</section>`;
}

function renderFaq(config: SiteConfig): string {
  const faqs = config.faqs ?? [];
  if (faqs.length === 0) return '';
  return `<section class="provenance" aria-label="Frequently asked questions">
  <h2>Frequently asked questions</h2>
  <dl class="faq">
${faqs
  .map(
    (faq) =>
      `    <dt>${escapeHtml(faq.question)}</dt>
    <dd>${escapeHtml(faq.answer)}</dd>`
  )
  .join('\n')}
  </dl>
</section>`;
}

function renderContact(config: SiteConfig): string {
  const email = config.company.securityEmail?.trim();
  const website = config.company.website?.trim();
  if (!email && !website) return '';
  const policy = config.securityTxt?.policyUrl?.trim();
  const disclosure = policy
    ? ` Report a vulnerability per the <a href="${escapeHtml(policy)}">disclosure policy</a>.`
    : email
      ? ' To report a vulnerability, email the security team; see <a href="./.well-known/security.txt">security.txt</a>.'
      : '';
  return `<section class="contact" aria-label="Contact">
  <h2>Security questions</h2>
  <p>${email ? `Contact the security team at <a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a>.` : ''}${website ? ` More at <a href="${escapeHtml(website)}">${escapeHtml(website)}</a>.` : ''}${disclosure}</p>
</section>`;
}

function buildStyles(primary?: string): string {
  const accent = /^#[0-9a-fA-F]{6}$/.test(primary ?? '') ? (primary as string) : DEFAULT_PRIMARY;
  return `:root {
  --accent: ${accent};
  --text: #111827;
  --muted: #4b5563;
  --border: #e5e7eb;
  --surface: #f9fafb;
  --implemented: #15803d;
  --partial: #b45309;
  --planned: #475569;
  --in-progress: #1d4ed8;
  --certified: #15803d;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif;
  color: var(--text);
  line-height: 1.55;
  background: #ffffff;
}
.wrap { max-width: 62rem; margin: 0 auto; padding: 0 1.25rem; }
.site-header {
  border-bottom: 1px solid var(--border);
  padding: 2.5rem 0 1.75rem;
  background: var(--surface);
}
.eyebrow { text-transform: uppercase; letter-spacing: 0.08em; font-size: 0.75rem; color: var(--accent); margin: 0 0 0.25rem; }
h1 { margin: 0 0 0.5rem; font-size: 1.9rem; }
.lede { margin: 0; color: var(--muted); max-width: 46rem; }
main { padding: 2rem 0 3rem; }
h2 { font-size: 1.1rem; margin: 0; }
.card {
  border: 1px solid var(--border);
  border-radius: 0.6rem;
  padding: 1.25rem 1.4rem;
  margin-bottom: 1.25rem;
}
.card-head { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; }
.cards { display: grid; gap: 1.25rem; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); }
.framework-controls { margin-top: 2rem; }
.section-title { font-size: 1.25rem; margin: 0 0 1rem; }
.cards .card { margin-bottom: 0; }
.badge {
  display: inline-block;
  font-size: 0.75rem;
  font-weight: 600;
  padding: 0.15rem 0.55rem;
  border-radius: 999px;
  border: 1px solid currentColor;
  color: var(--planned);
  white-space: nowrap;
}
.badge-implemented, .badge-certified { color: var(--implemented); }
.badge-partial { color: var(--partial); }
.badge-planned { color: var(--planned); }
.badge-in-progress { color: var(--in-progress); }
.controls { list-style: none; margin: 0.75rem 0 0; padding: 0; }
.controls li { padding: 0.6rem 0; border-top: 1px solid var(--border); }
.control-title { display: block; font-weight: 600; margin-top: 0.35rem; }
.control-description { display: block; color: var(--muted); font-size: 0.9rem; }
.muted { color: var(--muted); font-size: 0.9rem; }
.provenance, .contact {
  border-top: 1px solid var(--border);
  padding: 1.25rem 0 0;
  margin-top: 1.5rem;
}
.provenance p, .contact p { color: var(--muted); margin: 0.5rem 0 0; }
.plain-list { margin: 0.75rem 0 0; padding-left: 1.1rem; color: var(--text); }
.plain-list li { margin: 0.35rem 0; }
.faq dt { font-weight: 600; margin-top: 0.75rem; }
.faq dd { margin: 0.25rem 0 0; color: var(--muted); }
a { color: var(--accent); }
.site-footer { border-top: 1px solid var(--border); padding: 1.5rem 0 2.5rem; color: var(--muted); font-size: 0.9rem; background: var(--surface); }
.site-footer nav { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
`;
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Defense in depth on top of the sync tool's projection: nothing that can
// identify an account or resource may reach the published page.
const FORBIDDEN_PATTERNS: RegExp[] = [/\b\d{12}\b/, /arn:[a-z0-9-]+:/i, /\bAKIA[0-9A-Z]{16}\b/];

export function assertNoIdentifiers(html: string): void {
  for (const pattern of FORBIDDEN_PATTERNS) {
    const match = html.match(pattern);
    if (match) {
      throw new Error(`rendered trust center contains a forbidden value: ${match[0]}`);
    }
  }
}
