import type { Request, Response } from 'express';

const listUseCases = jest.fn();
const getUseCase = jest.fn();
const createUseCase = jest.fn();
const updateUseCase = jest.fn();
const deleteUseCase = jest.fn();
const listAiInventory = jest.fn();

jest.mock('../services/ai-use-case-store', () => ({
  ...jest.requireActual('../services/ai-use-case-store'),
  AiUseCaseStore: jest.fn(() => ({
    listUseCases,
    getUseCase,
    createUseCase,
    updateUseCase,
    deleteUseCase,
  })),
}));
jest.mock('../services/api-dependencies', () => ({
  getApiNeptuneClient: () => ({ listAiInventory }),
}));

import {
  createAiUseCase,
  deleteAiUseCase,
  getAiUseCase,
  getAiUseCaseCoverage,
  listAiUseCases,
  updateAiUseCase,
} from '../routes/ai-use-cases';

const ANALYST = { user: { email: 'analyst@example.com' } };

function call(handler: (req: any, res: Response) => Promise<void>, req: any) {
  const res: any = { statusCode: 200 };
  res.status = (code: number) => Object.assign(res, { statusCode: code });
  res.json = (body: unknown) => Object.assign(res, { body });
  return handler(req, res as Response).then(() => res);
}

const useCase = {
  id: 'support',
  name: 'Support',
  description: '',
  owner: 'team-ai',
  status: 'draft',
  assets: ['arn:aws:bedrock:us-east-1:111122223333:agent/a'],
  dataClasses: [],
  assessment: null,
  createdAt: '2026-11-01T00:00:00.000Z',
  createdBy: 'team-ai',
  updatedAt: '2026-11-01T00:00:00.000Z',
  updatedBy: 'team-ai',
};

beforeEach(() => {
  listUseCases.mockReset();
  getUseCase.mockReset();
  createUseCase.mockReset();
  updateUseCase.mockReset();
  deleteUseCase.mockReset();
  listAiInventory.mockReset();
});

describe('AI use-case routes', () => {
  it('lists use cases with the truncation flag', async () => {
    listUseCases.mockResolvedValue({ items: [useCase], truncated: false });

    const res = await call(listAiUseCases, {});

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ items: [useCase], truncated: false });
  });

  it('creates with a slug id derived from the name', async () => {
    createUseCase.mockImplementation(async (id, fields) => ({ ...useCase, id, ...fields }));

    const res = await call(createAiUseCase, {
      ...ANALYST,
      body: { name: 'Support Assistant', owner: 'team-ai' },
    });

    expect(res.statusCode).toBe(200);
    expect(createUseCase).toHaveBeenCalledWith(
      'support-assistant',
      expect.objectContaining({ name: 'Support Assistant', owner: 'team-ai' }),
      'analyst@example.com'
    );
  });

  it('answers 409 when the id is taken and 400 on invalid input', async () => {
    createUseCase.mockResolvedValue(null);
    const conflict = await call(createAiUseCase, {
      ...ANALYST,
      body: { id: 'support', name: 'x' },
    });
    expect(conflict.statusCode).toBe(409);

    const invalid = await call(createAiUseCase, { ...ANALYST, body: { name: '' } });
    expect(invalid.statusCode).toBe(400);

    const badId = await call(createAiUseCase, {
      ...ANALYST,
      body: { id: 'Not A Slug', name: 'x' },
    });
    expect(badId.statusCode).toBe(400);
    expect(createUseCase).toHaveBeenCalledTimes(1);
  });

  it('answers 401 without a verified actor', async () => {
    const res = await call(createAiUseCase, { body: { name: 'x' } });

    expect(res.statusCode).toBe(401);
    expect(createUseCase).not.toHaveBeenCalled();
  });

  it('gets one use case and 404s for invalid or missing ids', async () => {
    getUseCase.mockResolvedValue(useCase);
    const found = await call(getAiUseCase, { params: { id: 'support' } });
    expect(found.body).toEqual({ useCase });

    getUseCase.mockResolvedValue(null);
    const missing = await call(getAiUseCase, { params: { id: 'support' } });
    expect(missing.statusCode).toBe(404);

    const invalid = await call(getAiUseCase, { params: { id: '../etc' } });
    expect(invalid.statusCode).toBe(404);
    expect(getUseCase).toHaveBeenCalledTimes(2);
  });

  it('updates and answers 404 when the id is gone', async () => {
    updateUseCase.mockResolvedValue({ ...useCase, name: 'Renamed' });
    const updated = await call(updateAiUseCase, {
      ...ANALYST,
      params: { id: 'support' },
      body: { name: 'Renamed', owner: 'team-ai' },
    });
    expect(updated.body.useCase.name).toBe('Renamed');

    updateUseCase.mockResolvedValue(null);
    const missing = await call(updateAiUseCase, {
      ...ANALYST,
      params: { id: 'support' },
      body: { name: 'Renamed' },
    });
    expect(missing.statusCode).toBe(404);
  });

  it('deletes and answers 404 for an unknown id', async () => {
    deleteUseCase.mockResolvedValue(true);
    const deleted = await call(deleteAiUseCase, { params: { id: 'support' } });
    expect(deleted.body).toEqual({ id: 'support', deleted: true });

    deleteUseCase.mockResolvedValue(false);
    const missing = await call(deleteAiUseCase, { params: { id: 'support' } });
    expect(missing.statusCode).toBe(404);
  });

  it('computes coverage from the registry and the collected estate', async () => {
    listUseCases.mockResolvedValue({ items: [useCase], truncated: false });
    listAiInventory.mockResolvedValue([
      {
        type: 'agents',
        label: 'AiAgent',
        count: 2,
        truncated: false,
        items: [
          {
            id: 'a',
            arn: 'arn:aws:bedrock:us-east-1:111122223333:agent/a',
            name: 'a',
            status: 'PREPARED',
            account_id: '111122223333',
            region: 'us-east-1',
            platform: 'bedrock',
            role_arn: null,
            facts: {},
          },
          {
            id: 'ghost',
            arn: 'arn:aws:bedrock:us-east-1:111122223333:agent/ghost',
            name: 'ghost',
            status: 'PREPARED',
            account_id: '111122223333',
            region: 'us-east-1',
            platform: 'bedrock',
            role_arn: null,
            facts: {},
          },
        ],
      },
    ]);

    const res = await call(getAiUseCaseCoverage, {});

    expect(res.statusCode).toBe(200);
    expect(res.body.useCaseCount).toBe(1);
    expect(res.body.registeredAssets).toBe(1);
    expect(res.body.unregistered.map((asset: { arn: string }) => asset.arn)).toEqual([
      'arn:aws:bedrock:us-east-1:111122223333:agent/ghost',
    ]);
    expect(res.body.missing).toEqual([]);
    expect(res.body.truncated).toBe(false);
  });

  it('flags truncation and missing registered assets honestly', async () => {
    listUseCases.mockResolvedValue({
      items: [{ ...useCase, assets: ['arn:aws:bedrock:us-east-1:111122223333:agent/gone'] }],
      truncated: true,
    });
    listAiInventory.mockResolvedValue([
      { type: 'agents', label: 'AiAgent', count: 0, truncated: true, items: [] },
    ]);

    const res = await call(getAiUseCaseCoverage, {});

    expect(res.body.missing).toEqual([
      { arn: 'arn:aws:bedrock:us-east-1:111122223333:agent/gone', useCaseId: 'support' },
    ]);
    expect(res.body.truncated).toBe(true);
  });

  it('answers 500 when a dependency fails', async () => {
    listUseCases.mockRejectedValue(new Error('nope'));
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const res = await call(listAiUseCases, {});

    expect(res.statusCode).toBe(500);
    expect(res.body).toEqual({ code: 'INTERNAL_ERROR', message: 'Failed to list AI use cases' });
    error.mockRestore();
  });
});
