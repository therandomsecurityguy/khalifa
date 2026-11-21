import {
  refreshDomainMetrics,
  renderDomainMetrics,
  resetDomainMetricsForTests,
  setDomainMetricsSourcesForTests,
} from '../observability/domain-metrics';

describe('domain metrics', () => {
  afterEach(() => {
    resetDomainMetricsForTests();
    jest.restoreAllMocks();
  });

  it('renders open issues by severity and the reconciliation state', async () => {
    setDomainMetricsSourcesForTests({
      openIssueCounts: async () => ({ critical: 3, high: 1, medium: 0, low: 2 }),
      reconciliation: async () => ({
        status: 'OK',
        generatedAt: new Date(Date.now() - 3600_000).toISOString(),
      }),
    });
    await refreshDomainMetrics();

    const text = renderDomainMetrics().join('\n');
    expect(text).toContain('khalifa_domain_metrics_ok 1');
    expect(text).toContain('khalifa_open_issues{severity="critical"} 3');
    expect(text).toContain('khalifa_open_issues{severity="high"} 1');
    expect(text).toContain('khalifa_open_issues{severity="low"} 2');
    expect(text).toContain('khalifa_reconciliation_ok 1');
    expect(text).toContain('khalifa_reconciliation_status{status="OK"} 1');
    expect(text).toMatch(/khalifa_reconciliation_age_seconds 36\d{2}/);
  });

  it('flags not-OK and missing records without inventing an age', async () => {
    setDomainMetricsSourcesForTests({
      openIssueCounts: async () => ({}),
      reconciliation: async () => null,
    });
    await refreshDomainMetrics();

    const text = renderDomainMetrics().join('\n');
    expect(text).toContain('khalifa_reconciliation_ok 0');
    expect(text).toContain('khalifa_reconciliation_status{status="MISSING"} 1');
    expect(text).not.toContain('khalifa_reconciliation_age_seconds');
    expect(text).toContain('khalifa_open_issues{severity="critical"} 0');
  });

  it('keeps the last values but flips the health gauge when a refresh fails', async () => {
    const errors = jest.spyOn(console, 'error').mockImplementation(() => {});
    setDomainMetricsSourcesForTests({
      openIssueCounts: async () => ({ critical: 5 }),
      reconciliation: async () => ({ status: 'STALE', generatedAt: null }),
    });
    await refreshDomainMetrics();

    setDomainMetricsSourcesForTests({
      openIssueCounts: async () => {
        throw new Error('ddb down');
      },
      reconciliation: async () => {
        throw new Error('ddb down');
      },
    });
    await refreshDomainMetrics();

    const text = renderDomainMetrics().join('\n');
    expect(errors).toHaveBeenCalled();
    expect(text).toContain('khalifa_domain_metrics_ok 0');
    expect(text).toContain('khalifa_open_issues{severity="critical"} 5');
    expect(text).toContain('khalifa_reconciliation_status{status="STALE"} 1');
  });

  it('renders nothing before the first refresh', () => {
    expect(renderDomainMetrics()).toEqual([]);
  });
});
