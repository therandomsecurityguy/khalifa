import type { Request, Response } from 'express';

const executeStaticQuery = jest.fn();

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({ executeStaticQuery }),
}));

let route: typeof import('../routes/attack-scenarios');

const T_ID = { elementName: 'id' };
const T_LABEL = { elementName: 'label' };

function element(id: string, label: string): Map<unknown, unknown> {
  return new Map<unknown, unknown>([
    [T_ID, id],
    [T_LABEL, label],
  ]);
}

function call(query: Record<string, unknown>, params: Record<string, string> = {}) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  const req = {
    query,
    params,
    user: { sub: 's', email: 'v@example.com', groups: [], tokenUse: 'id' },
  };
  return {
    req: req as unknown as Request,
    res: res as Response & { statusCode: number; body?: any },
  };
}

describe('attack scenarios routes', () => {
  beforeAll(async () => {
    route = await import('../routes/attack-scenarios');
  });
  beforeEach(() => executeStaticQuery.mockReset());

  it('lists curated scenarios with resolved techniques and rule names', async () => {
    const { req, res } = call({});
    await route.listAttackScenarios(req, res);

    expect(res.statusCode).toBe(200);
    const scenario = res.body.scenarios.find((entry: any) => entry.id === 'internet-to-admin');
    expect(scenario.name).toBe('Internet exposure to admin');
    expect(scenario.steps[0]).toMatchObject({
      ruleId: 'RULE-002',
      ruleName: 'Security Groups Open to the Internet on SSH/RDP',
    });
    expect(scenario.techniques.map((t: any) => t.id)).toContain('T1133');
    expect(scenario.techniques[0]).toHaveProperty('tactic');
  });

  it('404s an unknown scenario without querying the graph', async () => {
    const { req, res } = call({}, { id: 'nope' });
    await route.runAttackScenario(req, res);
    expect(res.statusCode).toBe(404);
    expect(executeStaticQuery).not.toHaveBeenCalled();
  });

  it('runs each step against the graph, dedupes, and counts matched steps', async () => {
    executeStaticQuery.mockImplementation(async (query: string) => {
      if (query.includes('loops().is(4)')) {
        return [
          [element('ec2', 'Ec2Instance'), element('e1', 'GRANTS'), element('bucket', 'S3Bucket')],
          [element('ec2', 'Ec2Instance'), element('e1', 'GRANTS'), element('bucket', 'S3Bucket')],
        ];
      }
      return [];
    });

    const { req, res } = call({}, { id: 'leaked-credential-to-data' });
    await route.runAttackScenario(req, res);

    expect(res.statusCode).toBe(200);
    expect(res.body).toMatchObject({
      scenarioId: 'leaked-credential-to-data',
      matchedSteps: 1,
      totalSteps: 4,
    });
    const crown = res.body.steps.find((step: any) => step.ruleId === 'RULE-005');
    expect(crown).toMatchObject({ matchedPaths: 1, truncated: false });
    expect(crown.resources).toEqual(['ec2', 'bucket']);
  });

  it('records a step error and keeps evaluating the rest', async () => {
    executeStaticQuery.mockImplementation(async (query: string) => {
      if (query.includes('SOURCE_IP')) throw new Error('timeout after 5000ms');
      return [[element('ec2', 'Ec2Instance')]];
    });

    const { req, res } = call({}, { id: 'leaked-credential-to-data' });
    await route.runAttackScenario(req, res);

    expect(res.statusCode).toBe(200);
    const failed = res.body.steps.find((step: any) => step.ruleId === 'RULE-021');
    expect(failed.error).toContain('timeout');
    expect(res.body.matchedSteps).toBeGreaterThanOrEqual(1);
  });

  it('500s when every step fails', async () => {
    executeStaticQuery.mockRejectedValue(new Error('denied'));
    const { req, res } = call({}, { id: 'internet-to-admin' });
    await route.runAttackScenario(req, res);
    expect(res.statusCode).toBe(500);
  });
});
