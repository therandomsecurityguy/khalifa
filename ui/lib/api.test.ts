import {
  ApiError,
  describeError,
  getEffectivePermissions,
  getEscalationPaths,
  getIntegrationsStatus,
  getLeastPrivilegeFinding,
  getResource,
  getRule,
  getResourceGraph,
  getRightsizingRecommendation,
  getSession,
  getTrend,
  getUnusedPermissions,
  isNotFound,
  listTrendMetrics,
  normalizeIssueSummary,
  reopenIssue,
  searchResources,
  suppressIssue,
} from './api';

describe('UI API client', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.resetAllMocks();
  });

  function mockJson(status: number, body: unknown): void {
    global.fetch = jest.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
    });
  }

  it('loads session, resource, identity, trend, and integration endpoints', async () => {
    const calls: string[] = [];
    global.fetch = jest.fn().mockImplementation(async (url: string) => {
      calls.push(url);
      return {
        ok: true,
        status: 200,
        json: async () => ({}),
      };
    });

    await getSession();
    await getRule('RULE-012');
    await searchResources('IAMRole', 'name', 'admin', 50);
    await getResource('arn:aws:iam::111122223333:role/admin');
    await getResourceGraph('arn:aws:iam::111122223333:role/admin', 2);
    await getEffectivePermissions('arn:aws:iam::111122223333:role/admin');
    await getEscalationPaths({ sourceAccount: '111122223333' });
    await getUnusedPermissions('arn:aws:iam::111122223333:role/admin');
    await getRightsizingRecommendation('arn:aws:iam::111122223333:role/admin');
    await getLeastPrivilegeFinding('111122223333', 'arn:aws:iam::111122223333:role/admin');
    await listTrendMetrics();
    await getTrend('openIssuesBySeverity', 30);
    await getIntegrationsStatus();
    await suppressIssue('issue-1', 'accepted risk', '2026-10-30T00:00:00.000Z');
    await reopenIssue('issue-1');

    expect(calls).toEqual([
      '/api/session',
      '/api/rules/RULE-012',
      '/api/resources/search?label=IAMRole&property=name&value=admin&limit=50',
      '/api/resources/arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fadmin?includeNeighbors=true&includeIssues=true',
      '/api/resources/graph?arn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fadmin&depth=2',
      '/api/identity/effective-permissions/arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fadmin',
      '/api/identity/escalation-paths?sourceAccount=111122223333',
      '/api/identity/unused-permissions?principal=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fadmin',
      '/api/identity/rightsizing/arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fadmin',
      '/api/identity/least-privilege/111122223333/arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fadmin',
      '/api/trends',
      '/api/trends/openIssuesBySeverity?days=30',
      '/api/integrations/status',
      '/api/issues/issue-1/suppress',
      '/api/issues/issue-1/reopen',
    ]);
  });

  it('maps missing resources to ApiError 404', async () => {
    mockJson(404, { code: 'NOT_FOUND', message: 'Resource not found' });
    await expect(getResource('arn:aws:iam::1:role/missing')).rejects.toEqual(
      expect.objectContaining({ name: 'ApiError', status: 404 })
    );
    await expect(getResource('arn:aws:iam::1:role/missing')).rejects.toBeInstanceOf(ApiError);
  });

  it('encodes slashes and traversal in path params', async () => {
    const calls: string[] = [];
    global.fetch = jest.fn().mockImplementation(async (url: string) => {
      calls.push(url);
      return { ok: true, status: 200, json: async () => ({}) };
    });

    await getRightsizingRecommendation('arn:aws:iam::1:role/../admin');
    expect(calls[0]).toBe('/api/identity/rightsizing/arn%3Aaws%3Aiam%3A%3A1%3Arole%2F..%2Fadmin');
  });

  it('identifies not-found errors', () => {
    expect(isNotFound(new ApiError(404, 'missing'))).toBe(true);
    expect(isNotFound(new ApiError(403, 'no'))).toBe(false);
    expect(isNotFound(new Error('no'))).toBe(false);
  });

  it.each([
    [401, 'unauthenticated', false],
    [403, 'unauthorized', false],
    [404, 'not-found', false],
    [400, 'client', false],
    [500, 'server', true],
    [502, 'unavailable', true],
    [503, 'unavailable', true],
    [504, 'timeout', true],
  ])('classifies HTTP %i as %s (retryable: %s)', (status, kind, retryable) => {
    const error = new ApiError(status, 'x');
    expect(error.kind).toBe(kind);
    expect(error.retryable).toBe(retryable);
    expect(describeError(error).retryable).toBe(retryable);
  });

  it('maps a failed fetch to a retryable network error and lets aborts through', async () => {
    global.fetch = jest.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    await expect(getSession()).rejects.toMatchObject({ name: 'ApiError', kind: 'network' });

    const abort = new DOMException('The operation was aborted.', 'AbortError');
    global.fetch = jest.fn().mockRejectedValue(abort);
    await expect(getSession()).rejects.toBe(abort);
  });

  it('forwards the abort signal to fetch', async () => {
    const controller = new AbortController();
    global.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200, json: async () => ({}) });
    await getSession({ signal: controller.signal });
    expect(global.fetch).toHaveBeenCalledWith(
      '/api/session',
      expect.objectContaining({ signal: controller.signal })
    );
  });

  it('describes unknown errors as retryable with their message', () => {
    expect(describeError(new Error('socket hang up'))).toMatchObject({
      kind: 'unknown',
      message: 'socket hang up',
      retryable: true,
    });
  });

  it('reads the issue summary grid, treating missing or bad cells as zero', () => {
    expect(
      normalizeIssueSummary({
        counts: {
          critical: { open: 2, resolved: 'x' },
          high: { open: 4, suppressed: 1, resolved: 1 },
        },
      })
    ).toEqual({
      critical: { open: 2, suppressed: 0, resolved: 0 },
      high: { open: 4, suppressed: 1, resolved: 1 },
      medium: { open: 0, suppressed: 0, resolved: 0 },
      low: { open: 0, suppressed: 0, resolved: 0 },
    });
    expect(normalizeIssueSummary(null).low).toEqual({ open: 0, suppressed: 0, resolved: 0 });
  });
});
