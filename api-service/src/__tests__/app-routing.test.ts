import app from '../app';

describe('API route registration', () => {
  const stack = (app as unknown as { _router: { stack: any[] } })._router.stack;
  const paths = stack.filter((layer) => layer.route).map((layer) => layer.route.path as string);

  it('registers static routes before overlapping dynamic routes', () => {
    for (const [staticPath, dynamicPath] of [
      ['/issues/summary', '/issues/:id'],
      ['/issues/schedule', '/issues/:id'],
      ['/resources/search', '/resources/:arn(*)'],
      ['/resources/labels', '/resources/:arn(*)'],
      ['/resources/properties', '/resources/:arn(*)'],
      ['/resources/values', '/resources/:arn(*)'],
      ['/resources/graph', '/resources/:arn(*)'],
      [
        '/identity/least-privilege/summary',
        '/identity/least-privilege/:accountId/:principalArn(*)',
      ],
    ]) {
      expect(paths.indexOf(staticPath)).toBeGreaterThanOrEqual(0);
      expect(paths.indexOf(staticPath)).toBeLessThan(paths.indexOf(dynamicPath));
    }
  });

  it('registers the session endpoint used by the UI for role visibility', () => {
    expect(paths).toContain('/session');
  });

  it('registers the rule catalog used by the UI', () => {
    expect(paths).toContain('/rules');
    expect(paths).toContain('/rules/:id');
  });

  it('keeps health and metrics endpoints ahead of authentication', () => {
    const authenticationIndex = stack.findIndex((layer) => layer.name === 'authenticate');
    for (const path of ['/health', '/livez', '/readyz', '/metrics']) {
      const routeIndex = stack.findIndex((layer) => layer.route?.path === path);
      expect(routeIndex).toBeGreaterThanOrEqual(0);
      expect(routeIndex).toBeLessThan(authenticationIndex);
    }
  });

  it('captures an ARN containing resource path slashes as one parameter', () => {
    const layer = stack.find((candidate) => candidate.route?.path === '/resources/:arn(*)');

    expect(layer.match('/resources/arn:aws:iam::123456789012:role/team/Admin')).toBe(true);
    expect(layer.params.arn).toBe('arn:aws:iam::123456789012:role/team/Admin');
  });

  it('registers the data sources route', () => {
    expect(paths).toContain('/data-sources');
  });
});
