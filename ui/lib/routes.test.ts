import { APP_ROUTES, IDENTITY_ROUTES, activeRoute, principalHref, resourceHref } from './routes';

describe('UI routes', () => {
  it('exposes a discoverable route for every SEC-2940 surface', () => {
    const hrefs = [...APP_ROUTES, ...IDENTITY_ROUTES].map((route) => route.href);
    expect(hrefs).toEqual(
      expect.arrayContaining([
        '/issues',
        '/resources',
        '/identity',
        '/identity/effective-permissions',
        '/identity/escalation-paths',
        '/identity/unused-permissions',
        '/identity/rightsizing',
        '/identity/trust-graph',
        '/least-privilege',
        '/trends',
        '/integrations',
      ])
    );
  });

  it('finds the page a path belongs to, including nested and Identity tool paths', () => {
    expect(activeRoute('/issues/RULE-013-v2-abc')?.label).toBe('Issues');
    expect(activeRoute('/identity/trust-graph')?.label).toBe('Identity');
    expect(activeRoute('/least-privilege')?.label).toBe('Identity');
    expect(activeRoute('/issuesx')).toBeUndefined();
  });

  it('builds deep links for ARNs without dropping path segments', () => {
    const arn = 'arn:aws:iam::111122223333:role/team/Admin';
    expect(resourceHref(arn)).toBe(`/resources?arn=${encodeURIComponent(arn)}`);
    expect(principalHref('/identity/rightsizing', arn)).toBe(
      `/identity/rightsizing?principal=${encodeURIComponent(arn)}`
    );
  });
});
