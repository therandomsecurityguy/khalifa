import type { Response } from 'express';

const listAiInventory = jest.fn();
const getResource = jest.fn();
const getNeighbors = jest.fn();
const getOpenIssuesByResourceArn = jest.fn();

jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({ listAiInventory, getResource, getNeighbors }),
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

const agentItem = {
  id: 'agent-1',
  arn: 'arn:aws:bedrock:us-east-1:111122223333:agent/abc',
  name: 'assistant',
  status: 'PREPARED',
  account_id: '111122223333',
  region: 'us-east-1',
  platform: 'bedrock',
  role_arn: 'arn:aws:iam::111122223333:role/agent-role',
  facts: { guardrail: true },
};

describe('GET /ai/bom', () => {
  beforeEach(async () => {
    jest.resetModules();
    listAiInventory.mockReset();
    getResource.mockReset();
    getNeighbors.mockReset();
    getOpenIssuesByResourceArn.mockReset();
    route = await import('../routes/ai');
  });

  it('exports a flat component list with totals and truncation flags', async () => {
    listAiInventory.mockResolvedValue([
      { type: 'agents', label: 'AiAgent', count: 2, items: [agentItem], truncated: false },
      { type: 'models', label: 'AiModel', count: null, items: [], truncated: true },
    ]);

    const res = await call(route.getAiBom, { query: {} });

    expect(res.statusCode).toBe(200);
    expect(listAiInventory).toHaveBeenCalledWith(1000);
    expect(res.body.schemaVersion).toBe('1.0');
    expect(res.body.documentType).toBe('ai-bom');
    expect(res.body.components).toEqual([{ componentType: 'agents', ...agentItem }]);
    // A null total is honest: the grouped count traversal failed, not "zero".
    expect(res.body.totals).toEqual({ agents: 2, models: null });
    expect(res.body.truncatedTypes).toEqual(['models']);
    expect(res.body.scope).toContain('Not a code-level SBOM');
    expect(res.body.scope).toContain('CycloneDX');
    expect(Number.isNaN(Date.parse(res.body.generatedAt))).toBe(false);
  });

  it('answers 500 when the export read fails', async () => {
    listAiInventory.mockRejectedValue(new Error('nope'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(route.getAiBom, { query: {} });

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ code: 'INTERNAL_ERROR', message: 'Failed to export AI BOM' });
    error.mockRestore();
  });
});
