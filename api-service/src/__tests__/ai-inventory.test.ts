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

describe('GET /ai/inventory', () => {
  beforeEach(async () => {
    jest.resetModules();
    listAiInventory.mockReset();
    getResource.mockReset();
    getNeighbors.mockReset();
    getOpenIssuesByResourceArn.mockReset();
    route = await import('../routes/ai');
  });

  it('serves every AI section with the default limit', async () => {
    const sections = [
      { type: 'agents', label: 'AiAgent', count: 3, items: [], truncated: false },
      { type: 'models', label: 'AiModel', count: 0, items: [], truncated: false },
    ];
    listAiInventory.mockResolvedValue(sections);
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(route.getAiInventory, { query: {} });

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ types: sections });
    expect(listAiInventory).toHaveBeenCalledWith(20, undefined);
    error.mockRestore();
  });

  it('narrows to one type and clamps the limit', async () => {
    const section = { type: 'agents', label: 'AiAgent', count: 1, items: [], truncated: false };
    listAiInventory.mockResolvedValue([section]);

    const res = await call(route.getAiInventory, { query: { type: 'agents', limit: '5' } });

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ types: [section] });
    expect(listAiInventory).toHaveBeenCalledWith(5, ['agents']);
  });

  it('rejects an unknown type or an out-of-range limit', async () => {
    const unknownType = await call(route.getAiInventory, { query: { type: 'robots' } });
    expect(unknownType.statusCode).toBe(400);

    // Prototype keys must not pass the key check (Object.hasOwn, not `in`).
    const inheritedKey = await call(route.getAiInventory, { query: { type: 'constructor' } });
    expect(inheritedKey.statusCode).toBe(400);

    const badLimit = await call(route.getAiInventory, { query: { limit: '0' } });
    expect(badLimit.statusCode).toBe(400);
    expect(listAiInventory).not.toHaveBeenCalled();
  });

  it('answers 500 when the inventory read fails', async () => {
    listAiInventory.mockRejectedValue(new Error('nope'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(route.getAiInventory, { query: {} });

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({
      code: 'INTERNAL_ERROR',
      message: 'Failed to list AI inventory',
    });
    error.mockRestore();
  });
});

describe('GET /ai/agents/*arn', () => {
  const agentArn = `arn:aws:bedrock:us-east-1:111122223333:agent/agent-1`;

  beforeEach(async () => {
    jest.resetModules();
    listAiInventory.mockReset();
    getResource.mockReset();
    getNeighbors.mockReset();
    getOpenIssuesByResourceArn.mockReset();
    route = await import('../routes/ai');
  });

  it('groups the agent neighbors by edge label and includes open issues', async () => {
    const roleArn = 'arn:aws:iam::111122223333:role/agent-role';
    const kbArn = `arn:aws:bedrock:us-east-1:111122223333:knowledge-base/kb-1`;
    const guardrailArn = `arn:aws:bedrock:us-east-1:111122223333:guardrail/gr-1`;
    const lambdaArn = 'arn:aws:lambda:us-east-1:111122223333:function:tool';
    const modelArn = `arn:aws:bedrock:us-east-1:111122223333:custom-model/model-1`;
    getResource.mockResolvedValue({
      id: agentArn,
      label: 'AiAgent',
      properties: { name: 'assistant' },
    });
    getNeighbors.mockResolvedValue({
      nodes: [
        { id: roleArn, label: 'IamRole', properties: {} },
        { id: kbArn, label: 'AiKnowledgeBase', properties: {} },
        { id: guardrailArn, label: 'AiGuardrail', properties: {} },
        { id: lambdaArn, label: 'LambdaFunction', properties: {} },
        { id: modelArn, label: 'AiModel', properties: {} },
        { id: 'arn:aws:s3:::unrelated', label: 'S3Bucket', properties: {} },
      ],
      edges: [
        { id: 'e1', label: 'RUNS_AS', from: agentArn, to: roleArn },
        { id: 'e2', label: 'HAS_KB', from: agentArn, to: kbArn },
        { id: 'e3', label: 'HAS_KB', from: agentArn, to: kbArn },
        { id: 'e4', label: 'PROTECTED_BY', from: agentArn, to: guardrailArn },
        // The traversal follows edges in both directions; the neighbor is the
        // other end whichever way the edge was written.
        { id: 'e5', label: 'HAS_ACTION_GROUP', from: lambdaArn, to: agentArn },
        { id: 'e6', label: 'USES_MODEL', from: agentArn, to: modelArn },
        { id: 'e7', label: 'GRANTS', from: agentArn, to: 'arn:aws:s3:::unrelated' },
      ],
    });
    getOpenIssuesByResourceArn.mockResolvedValue([{ id: 'issue-1' }]);

    const res = await call(route.getAiAgent, { params: { arn: agentArn } });

    expect(res.statusCode).toBe(200);
    expect(res.body.agent.id).toBe(agentArn);
    expect(res.body.role.id).toBe(roleArn);
    expect(res.body.knowledgeBases.map((node: { id: string }) => node.id)).toEqual([kbArn]);
    expect(res.body.guardrail.id).toBe(guardrailArn);
    expect(res.body.tools.map((node: { id: string }) => node.id)).toEqual([lambdaArn]);
    expect(res.body.model.id).toBe(modelArn);
    expect(res.body.issues).toEqual([{ id: 'issue-1' }]);
    expect(getOpenIssuesByResourceArn).toHaveBeenCalledWith(agentArn);
  });

  it('answers 404 for a missing vertex or one that is not an AI agent', async () => {
    getResource.mockResolvedValueOnce(null);
    const missing = await call(route.getAiAgent, { params: { arn: agentArn } });
    expect(missing.statusCode).toBe(404);

    getResource.mockResolvedValueOnce({
      id: agentArn,
      label: 'LambdaFunction',
      properties: {},
    });
    const wrongLabel = await call(route.getAiAgent, { params: { arn: agentArn } });
    expect(wrongLabel.statusCode).toBe(404);
    expect(getNeighbors).not.toHaveBeenCalled();
  });

  it('answers 500 when the neighbor read fails', async () => {
    getResource.mockResolvedValue({ id: agentArn, label: 'AiAgent', properties: {} });
    getNeighbors.mockRejectedValue(new Error('nope'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(route.getAiAgent, { params: { arn: agentArn } });

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ code: 'INTERNAL_ERROR', message: 'Failed to get AI agent' });
    error.mockRestore();
  });
});
