import type { Request, Response } from 'express';

const getRuleStatusCounts = jest.fn();

jest.mock('@khalifa/risk-engine', () => ({
  ...jest.requireActual('@khalifa/risk-engine'),
  DynamoDBIssueRepository: jest.fn().mockImplementation(() => ({ getRuleStatusCounts })),
}));

let route: typeof import('../routes/rules');

function call() {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return route.getRuleQuality({} as Request, res as Response).then(() => res);
}

describe('GET /rules/quality', () => {
  beforeAll(async () => {
    route = await import('../routes/rules');
  });
  beforeEach(() => getRuleStatusCounts.mockReset());

  it('joins the lifecycle counts with the catalogue and ranks noisy rules first', async () => {
    getRuleStatusCounts.mockResolvedValue({
      'RULE-006': { open: 40, suppressed: 12, resolved: 8, corroborated: 6, labeled: 10 },
      'RULE-002': { open: 3, suppressed: 1, resolved: 19 },
    });

    const res = await call();

    expect(res.statusCode).toBe(200);
    expect(res.body.rules.map((rule: any) => [rule.ruleId, rule.verdict])).toEqual([
      ['RULE-006', 'noisy'],
      ['RULE-002', 'reliable'],
    ]);
    const noisy = res.body.rules[0];
    expect(noisy).toMatchObject({
      name: 'Cross-Account IAM Trust with Wildcard Resource Access',
      ownerTeam: 'iam-security',
      severityHint: 'critical',
      enabled: true,
      autoTicket: false,
      inCatalogue: true,
      handled: 20,
      dismissalRate: 0.6,
      corroborated: 6,
      labeled: 10,
      corroborationRate: 0.6,
    });
    expect(res.body.thresholds).toEqual({
      minHandled: 10,
      reliableDismissalRate: 0.2,
      noisyDismissalRate: 0.5,
    });
    expect(Date.parse(res.body.generatedAt)).not.toBeNaN();
  });

  it('flags rules that no longer exist in the catalogue', async () => {
    getRuleStatusCounts.mockResolvedValue({
      'RULE-OLD': { open: 0, suppressed: 0, resolved: 4 },
    });

    const res = await call();

    expect(res.body.rules[0]).toMatchObject({
      ruleId: 'RULE-OLD',
      name: 'RULE-OLD',
      inCatalogue: false,
      verdict: 'insufficient-data',
    });
  });

  it('answers 500 when the issue store is unreadable', async () => {
    getRuleStatusCounts.mockRejectedValue(new Error('denied'));
    const res = await call();
    expect(res.statusCode).toBe(500);
  });
});
