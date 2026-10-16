import type { Request, Response } from 'express';

const getControlResult = jest.fn();
const getControlEvidence = jest.fn();

jest.mock('../services/compliance-service', () => ({
  ComplianceService: jest.fn().mockImplementation(() => ({ getControlResult, getControlEvidence })),
}));
jest.mock('@khalifa/risk-engine', () => ({
  ...jest.requireActual('@khalifa/risk-engine'),
  DynamoDBIssueRepository: jest
    .fn()
    .mockImplementation(() => ({ getOpenIssuesByRule: jest.fn().mockResolvedValue([]) })),
}));

let getControlDetails: typeof import('../routes/compliance').getControlDetails;

function response(): Response & { statusCode: number; body?: any } {
  const res: any = { statusCode: 200 };
  res.status = (statusCode: number) => Object.assign(res, { statusCode });
  res.json = (body: unknown) => Object.assign(res, { body });
  return res;
}

const canonicalEvidence = {
  controlId: 'KH-2.8',
  resourceId: 'db-1',
  resourceType: 'RdsInstance',
  status: 'FAIL',
  details: { backupRetention: 3 },
  collectedAt: '2026-10-16T00:00:00.000Z',
  collectedBy: 'compliance-engine',
};

async function details(framework: string, controlId: string) {
  const res = response();
  await getControlDetails(
    { params: { framework, controlId } } as Request<{ framework: string; controlId: string }>,
    res
  );
  return res;
}

describe('control details: mapped frameworks', () => {
  beforeAll(async () => {
    ({ getControlDetails } = await import('../routes/compliance'));
  });
  beforeEach(() => jest.clearAllMocks());

  it('returns a mapped requirement with its mapped controls and aggregated evidence', async () => {
    getControlResult.mockResolvedValue({
      control: {
        id: 'CC9.1',
        title: 'Availability is protected',
        severity: 'high',
        relatedRules: [],
        remediationGuidance: 'Address the mapped controls.',
        evidenceRequirements: [],
      },
      status: 'FAIL',
      evidence: [],
      lastEvaluated: '2026-10-16T00:00:00.000Z',
      mappedControls: [
        { controlId: 'KH-2.8', framework: 'KHALIFA_BASELINE', status: 'FAIL', issues: ['3 items'] },
      ],
    });
    getControlEvidence.mockResolvedValue([canonicalEvidence]);

    const res = await details('SOC2', 'CC9.1');

    expect(res.statusCode).toBe(200);
    expect(res.body.mappedControls).toEqual([
      { controlId: 'KH-2.8', framework: 'KHALIFA_BASELINE', status: 'FAIL', issues: ['3 items'] },
    ]);
    expect(res.body.evidence).toEqual([canonicalEvidence]);
    expect(getControlEvidence).toHaveBeenCalledWith('CC9.1', 'SOC2');
    // A mapped requirement id is not a canonical control, so nothing cites it.
    expect(res.body.citedBy).toEqual([]);
  });

  it('returns no evidence rows for a mapped requirement that has no canonical reports yet', async () => {
    getControlResult.mockResolvedValue({
      control: {
        id: 'CC6.1',
        title: 'Logical access',
        severity: 'high',
        relatedRules: [],
        remediationGuidance: '',
        evidenceRequirements: [],
      },
      status: 'NOT_EVALUATED',
      evidence: [],
      lastEvaluated: '2026-10-16T00:00:00.000Z',
      mappedControls: [],
    });
    getControlEvidence.mockResolvedValue([]);

    const res = await details('SOC2', 'CC6.1');
    expect(res.body.evidence).toEqual([]);
    expect(res.body.mappedControls).toEqual([]);
  });

  it('tells a canonical control which framework requirements cite it', async () => {
    getControlResult.mockResolvedValue({
      control: {
        id: '1.5',
        title: 'Root MFA',
        severity: 'critical',
        relatedRules: [],
        remediationGuidance: '',
        evidenceRequirements: [],
      },
      status: 'PASS',
      evidence: [canonicalEvidence],
      lastEvaluated: '2026-10-16T00:00:00.000Z',
    });

    const res = await details('CIS_AWS_FOUNDATIONS', '1.5');

    expect(getControlEvidence).not.toHaveBeenCalled();
    expect(res.body.mappedControls).toBeUndefined();
    const cited = res.body.citedBy.map((c: { framework: string; requirement: string }) => [
      c.framework,
      c.requirement,
    ]);
    expect(cited).toContainEqual(['SOC2', 'CC6.1']);
    expect(cited).toContainEqual(['ISO27001', 'A.5.17']);
    expect(res.body.evidence).toEqual([canonicalEvidence]);
  });

  it('accepts the mapped frameworks and still rejects unknown ones', async () => {
    getControlResult.mockResolvedValue(null);
    const mapped = await details('ISO27001', 'A.8.24');
    expect(mapped.statusCode).toBe(404);

    const unknown = await details('PCI_DSS', '1.1');
    expect(unknown.statusCode).toBe(400);
    expect(unknown.body.code).toBe('INVALID_FRAMEWORK');
  });
});
