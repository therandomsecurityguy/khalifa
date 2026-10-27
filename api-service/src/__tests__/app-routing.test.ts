import app from '../app';
import { requireViewer } from '../middleware/rbac';
import { expensiveRateLimiter } from '../middleware/rate-limit';

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
      ['/secrets/reader-counts', '/secrets/:arn(*)'],
      ['/rules/quality', '/rules/:id'],
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

  it('serves secrets only after authentication, to viewers, behind the expensive-query limit', () => {
    const authenticationIndex = stack.findIndex((layer) => layer.name === 'authenticate');
    const routeIndex = stack.findIndex((layer) => layer.route?.path === '/secrets');
    expect(authenticationIndex).toBeGreaterThanOrEqual(0);
    expect(routeIndex).toBeGreaterThan(authenticationIndex);
    const handlers = stack[routeIndex].route.stack.map((layer: any) => layer.handle);
    expect(handlers[0]).toBe(requireViewer);
    expect(handlers[1]).toBe(expensiveRateLimiter);
  });

  it('serves one secret behind ARN validation and the same checks, after the list route', () => {
    const listIndex = stack.findIndex((layer) => layer.route?.path === '/secrets');
    const detailIndex = stack.findIndex((layer) => layer.route?.path === '/secrets/:arn(*)');
    expect(detailIndex).toBeGreaterThan(listIndex);
    const handlers = stack[detailIndex].route.stack.map((layer: any) => layer.handle);
    expect(handlers).toHaveLength(4);
    expect(handlers[1]).toBe(requireViewer);
    expect(handlers[2]).toBe(expensiveRateLimiter);
    const validate = handlers[0];
    const res: any = { status: jest.fn(() => res), json: jest.fn() };
    const next = jest.fn();
    validate({ params: { arn: 'g.V().drop()' } }, res, next);
    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
    validate(
      { params: { arn: 'arn:aws:secretsmanager:us-west-2:111122223333:secret:prod/key' } },
      res,
      next
    );
    expect(next).toHaveBeenCalledTimes(1);
    const layer = stack[detailIndex];
    expect(layer.match('/secrets/arn:aws:ssm:us-west-2:111122223333:parameter/db/password')).toBe(
      true
    );
    expect(layer.params.arn).toBe('arn:aws:ssm:us-west-2:111122223333:parameter/db/password');
  });

  it('lists attack scenarios to viewers and gates running one behind the expensive limit', () => {
    const listIndex = stack.findIndex((layer) => layer.route?.path === '/attack-scenarios');
    const listHandlers = stack[listIndex].route.stack.map((layer: any) => layer.handle);
    expect(listHandlers[0]).toBe(requireViewer);

    const runIndex = stack.findIndex((layer) => layer.route?.path === '/attack-scenarios/:id');
    expect(runIndex).toBeGreaterThan(listIndex);
    const runHandlers = stack[runIndex].route.stack.map((layer: any) => layer.handle);
    expect(runHandlers[0]).toBe(requireViewer);
    expect(runHandlers[1]).toBe(expensiveRateLimiter);
  });

  it('serves the attack-path simulation to viewers behind the expensive-query limit', () => {
    const authenticationIndex = stack.findIndex((layer) => layer.name === 'authenticate');
    const routeIndex = stack.findIndex((layer) => layer.route?.path === '/attack-paths/simulate');
    expect(routeIndex).toBeGreaterThan(authenticationIndex);
    const handlers = stack[routeIndex].route.stack.map((layer: any) => layer.handle);
    expect(handlers[0]).toBe(requireViewer);
    expect(handlers[1]).toBe(expensiveRateLimiter);
  });

  it('serves reader counts behind the viewer role and the expensive-query limit', () => {
    const layer = stack.find((candidate) => candidate.route?.path === '/secrets/reader-counts');
    const handlers = layer.route.stack.map((entry: any) => entry.handle);
    expect(handlers[0]).toBe(requireViewer);
    expect(handlers[1]).toBe(expensiveRateLimiter);
  });
});
