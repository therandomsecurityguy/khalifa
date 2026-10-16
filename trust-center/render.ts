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

export function renderSite(
  config: SiteConfig,
  generated: GeneratedConfig,
  meta: BuildMeta | null,
  now: Date = new Date()
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
${controls.length > 0 ? renderControls(controls) : ''}
${renderProvenance(generatedAt, recordAt)}
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

function renderControls(controls: GeneratedControlDomain[]): string {
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

function renderProvenance(generatedAt: string, recordAt: string | null): string {
  return `<section class="provenance" aria-label="Publication details">
  <h2>Publication details</h2>
  <p>Page generated ${escapeHtml(generatedAt)}${recordAt ? ` from an assessment recorded ${escapeHtml(recordAt)}` : ''}. Requirements appear here only after repeated agreement with the account's Security Hub configuration and an explicit publish allowlist.</p>
</section>`;
}

function renderContact(config: SiteConfig): string {
  const email = config.company.securityEmail?.trim();
  const website = config.company.website?.trim();
  if (!email && !website) return '';
  return `<section class="contact" aria-label="Contact">
  <h2>Security questions</h2>
  <p>${email ? `Contact the security team at <a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a>.` : ''}${website ? ` More at <a href="${escapeHtml(website)}">${escapeHtml(website)}</a>.` : ''}</p>
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
