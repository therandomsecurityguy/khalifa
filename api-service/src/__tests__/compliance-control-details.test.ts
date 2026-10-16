import type { Request, Response } from 'express';

const getControlResult = jest.fn();
const getOpenIssuesByRule = jest.fn();

jest.mock('../services/compliance-service', () => ({
  ComplianceService: jest.fn().mockImplementation(() => ({ getControlResult })),
}));
jest.mock('@khalifa/risk-engine', () => ({
  ...jest.requireActual('@khalifa/risk-engine'),
  DynamoDBIssueRepository: jest.fn().mockImplementation(() => ({ getOpenIssuesByRule })),
}));

let getControlDetails: typeof import('../routes/compliance').getControlDetails;

function response(): Response & { statusCode: number; body?: any } {
  const res: any = { statusCode: 200 };
  res.status = (statusCode: number) => Object.assign(res, { statusCode });
  res.json = (body: unknown) => Object.assign(res, { body });
  return res;
}

const issue = (id: string, severity: string, riskScore = 50) => ({
  id,
  severity,
  riskScore,
  status: 'open',
  resourcesInvolved: [{ resourceId: `arn:aws:s3:::${id}`, resourceType: 'S3Bucket' }],
});

async function details(relatedRules: string[]) {
  getControlResult.mockResolvedValue({
    control: {
      id: '2.1.4',
      title: 't',
      severity: 'critical',
      relatedRules,
      remediationGuidance: '',
    },
    status: 'FAIL',
    evidence: [],
  });
  const res = response();
  await getControlDetails(
    { params: { framework: 'CIS_AWS_FOUNDATIONS', controlId: '2.1.4' } } as Request<{
      framework: string;
      controlId: string;
    }>,
    res
  );
  return res;
}

// The card used to show every related rule as "open" at the control's
// severity, whether or not the rule had a single finding.
describe('control details: related rules', () => {
  beforeAll(async () => {
    ({ getControlDetails } = await import('../routes/compliance'));
  });
  beforeEach(() => jest.clearAllMocks());

  it('reports a rule with no open issues as zero, not open', async () => {
    getOpenIssuesByRule.mockResolvedValue([]);
    const res = await details(['RULE-007']);

    expect(res.body.relatedIssues).toEqual([
      {
        ruleId: 'RULE-007',
        ruleName: 'Public S3 Buckets with Sensitive Data',
        openCount: 0,
        highestSeverity: null,
        issues: [],
      },
    ]);
  });

  it('counts every open issue, lists the most severe five, and takes severity from issues', async () => {
    getOpenIssuesByRule.mockResolvedValue([
      issue('a', 'low'),
      issue('b', 'high', 10),
      issue('c', 'medium'),
      issue('d', 'high', 90),
      issue('e', 'low'),
      issue('f', 'medium'),
      issue('g', 'low'),
    ]);
    const [rule] = (await details(['RULE-011'])).body.relatedIssues;

    expect(rule.openCount).toBe(7);
    expect(rule.highestSeverity).toBe('high');
    expect(rule.issues.map((i: { id: string }) => i.id)).toEqual(['d', 'b', 'c', 'f', 'a']);
    expect(rule.issues[0].resourceId).toBe('arn:aws:s3:::d');
  });

  // A failed read is unknown, and must not look like "no open issues".
  it('reports an unreadable rule as null without failing the page', async () => {
    getOpenIssuesByRule.mockImplementation(async (id: string) => {
      if (id === 'RULE-011') throw new Error('throttled');
      return [issue('a', 'critical')];
    });
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const res = await details(['RULE-007', 'RULE-011']);
    spy.mockRestore();

    expect(res.statusCode).toBe(200);
    expect(res.body.relatedIssues.map((r: { openCount: number | null }) => r.openCount)).toEqual([
      1,
      null,
    ]);
  });
});
