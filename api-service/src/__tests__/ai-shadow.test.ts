import type { Response } from 'express';

const listShadowAiAnomalies = jest.fn();
const lastCloudTrailAnomalyObservedAt = jest.fn();
const listAiInventory = jest.fn();
const getResource = jest.fn();
const getNeighbors = jest.fn();
const getOpenIssuesByResourceArn = jest.fn();

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({
    listShadowAiAnomalies,
    lastCloudTrailAnomalyObservedAt,
    listAiInventory,
    getResource,
    getNeighbors,
  }),
}));
jest.mock('@khalifa/risk-engine', () => ({
  DynamoDBIssueRepository: jest.fn(() => ({ getOpenIssuesByResourceArn })),
}));

let route: typeof import('../routes/ai');

function call(handler: (req: any, res: Response) => Promise<void>, req: any) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return handler(req, res as Response).then(() => res);
}

const anomalyVertex = {
  id: 'arn:aws:khalifa:anomaly:111122223333:cloudtrail-anomaly/SHADOW_AI_USAGE/abc',
  label: 'CloudTrailAnomaly',
  properties: {
    anomaly_type: 'SHADOW_AI_USAGE',
    principal_arn: 'arn:aws:sts::111122223333:assumed-role/MysteryTeam',
    account_id: '111122223333',
    source_ip: '203.0.113.11',
    event_count: 3,
    first_seen: '2026-11-24T08:00:00Z',
    last_seen: '2026-11-24T09:00:00Z',
    detail: 'CreateNotebookInstance, ListAgents',
    source_updated_at: '2026-11-24T10:00:00Z',
  },
};

describe('GET /ai/shadow', () => {
  beforeEach(async () => {
    jest.resetModules();
    listShadowAiAnomalies.mockReset();
    lastCloudTrailAnomalyObservedAt.mockReset();
    listAiInventory.mockReset();
    getResource.mockReset();
    getNeighbors.mockReset();
    getOpenIssuesByResourceArn.mockReset();
    route = await import('../routes/ai');
  });

  it('serves the anomalies with an explicit management-plane coverage statement', async () => {
    listShadowAiAnomalies.mockResolvedValue([anomalyVertex]);
    lastCloudTrailAnomalyObservedAt.mockResolvedValue(
      new Date(Date.now() - 3_600_000).toISOString()
    );

    const res = await call(route.getShadowAiAnomalies, { query: {} });

    expect(res.statusCode).toBe(200);
    expect(listShadowAiAnomalies).toHaveBeenCalledWith(50);
    expect(res.body.anomalies).toEqual([
      {
        arn: anomalyVertex.id,
        principalArn: 'arn:aws:sts::111122223333:assumed-role/MysteryTeam',
        accountId: '111122223333',
        sourceIp: '203.0.113.11',
        eventCount: 3,
        firstSeen: '2026-11-24T08:00:00Z',
        lastSeen: '2026-11-24T09:00:00Z',
        detail: 'CreateNotebookInstance, ListAgents',
        observedAt: '2026-11-24T10:00:00Z',
      },
    ]);
    expect(res.body.coverage).toMatchObject({
      plane: 'management',
      windowDays: 7,
      freshness: 'fresh',
    });
    expect(res.body.coverage.detail).toContain('data events are enabled');
    expect(res.body.coverage.detail).toContain('OPERATIONAL.md');
    expect(res.body.coverage.detail).toContain('never claims data-plane completeness');
    expect(res.body.coverage.lastAnomalyObservedAt).toEqual(expect.any(String));
  });

  it('reports unknown freshness when the analyzer has left no marker', async () => {
    listShadowAiAnomalies.mockResolvedValue([]);
    lastCloudTrailAnomalyObservedAt.mockResolvedValue(null);

    const res = await call(route.getShadowAiAnomalies, { query: { limit: '5' } });

    expect(res.statusCode).toBe(200);
    expect(listShadowAiAnomalies).toHaveBeenCalledWith(5);
    expect(res.body.anomalies).toEqual([]);
    expect(res.body.coverage).toMatchObject({
      lastAnomalyObservedAt: null,
      freshness: 'unknown',
    });
  });

  it('rejects an out-of-range limit and answers 500 when the read fails', async () => {
    const badLimit = await call(route.getShadowAiAnomalies, { query: { limit: '0' } });
    expect(badLimit.statusCode).toBe(400);

    listShadowAiAnomalies.mockRejectedValue(new Error('nope'));
    lastCloudTrailAnomalyObservedAt.mockResolvedValue(null);
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(route.getShadowAiAnomalies, { query: {} });

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({
      code: 'INTERNAL_ERROR',
      message: 'Failed to list shadow AI anomalies',
    });
    error.mockRestore();
  });

  it('grades freshness against the daily analyzer cadence', () => {
    expect(route.freshnessFor(null)).toBe('unknown');
    expect(route.freshnessFor(Number.NaN)).toBe('unknown');
    expect(route.freshnessFor(1)).toBe('fresh');
    expect(route.freshnessFor(route.SHADOW_FRESH_HOURS)).toBe('fresh');
    expect(route.freshnessFor(route.SHADOW_FRESH_HOURS + 1)).toBe('aging');
    expect(route.freshnessFor(route.SHADOW_STALE_HOURS + 1)).toBe('stale');
  });
});
