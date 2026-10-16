import { escapeHtml, renderSite } from './render';
import type { GeneratedConfig, SiteConfig } from './types';

const config: SiteConfig = {
  company: {
    name: 'Example Corp',
    securityEmail: 'security@example.com',
    website: 'https://example.com',
  },
};

const generated: GeneratedConfig = {
  frameworks: [{ name: 'CIS', status: 'in-progress' }],
  controls: [
    { domain: '2. Logging', items: [{ title: 'CloudTrail enabled', status: 'partial' }] },
    { domain: '1. Identity', items: [{ title: 'Root has MFA', status: 'implemented' }] },
  ],
};

describe('renderSite', () => {
  it('renders status labels and orders domains numerically', () => {
    const { 'index.html': html } = renderSite(config, generated, null);
    expect(html).toContain('In progress');
    expect(html).toContain('Implemented');
    expect(html).toContain('Partial');
    expect(html.indexOf('1. Identity')).toBeLessThan(html.indexOf('2. Logging'));
  });

  it('escapes all interpolated content', () => {
    const { 'index.html': html } = renderSite(
      { company: { name: '<script>alert(1)</script>' } },
      { controls: [{ domain: 'x"><img src=x>', items: [{ title: 'a & b', status: 'planned' }] }] },
      null
    );
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('a &amp; b');
    expect(html).not.toContain('"><img');
  });

  it('renders provenance from build-meta and falls back to the build time', () => {
    const withMeta = renderSite(config, generated, {
      generatedAt: '2026-10-16T12:00:00.000Z',
      source: { recordGeneratedAt: '2026-10-16T00:00:00.000Z' },
    })['index.html'];
    expect(withMeta).toContain('Page generated 2026-10-16T12:00:00.000Z');
    expect(withMeta).toContain('recorded 2026-10-16T00:00:00.000Z');

    const withoutMeta = renderSite(config, generated, null, new Date('2026-10-17T00:00:00.000Z'))[
      'index.html'
    ];
    expect(withoutMeta).toContain('Page generated 2026-10-17T00:00:00.000Z');
  });

  it('omits the contact section when no email or website is configured', () => {
    const html = renderSite({ company: { name: 'X' } }, generated, null)['index.html'];
    expect(html).not.toContain('mailto:');
    expect(html).not.toContain('Security questions');
  });

  it('uses the configured accent color and validates it', () => {
    const styles = renderSite({ ...config, theme: { primary: '#123456' } }, generated, null)[
      'styles.css'
    ];
    expect(styles).toContain('--accent: #123456');
    const fallback = renderSite({ ...config, theme: { primary: 'red; }' } }, generated, null)[
      'styles.css'
    ];
    expect(fallback).toContain('--accent: #1e3a8a');
  });

  it('trips on identifiers that must never reach the page', () => {
    expect(() =>
      renderSite(
        config,
        {
          controls: [
            { domain: 'd', items: [{ title: 'Bucket arn:aws:s3:::x', status: 'planned' }] },
          ],
        },
        null
      )
    ).toThrow('forbidden value');
    expect(() =>
      renderSite(
        config,
        { frameworks: [{ name: 'Account 111122223333', status: 'planned' }] },
        null
      )
    ).toThrow('forbidden value');
  });
});

describe('escapeHtml', () => {
  it('escapes the five HTML metacharacters', () => {
    expect(escapeHtml(`&<>"'`)).toBe('&amp;&lt;&gt;&quot;&#39;');
  });
});
