import type { Request, Response, NextFunction } from 'express';
import { validateGremlinSelectors } from '../middleware/gremlin-validator';

function makeReq(query: Record<string, unknown>): Request {
  return { query } as unknown as Request;
}

function makeRes(): Response {
  const res: any = {
    statusCode: 200,
    body: undefined,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: any) {
      this.body = payload;
      return this;
    },
  };
  return res as Response;
}

describe('validateGremlinSelectors', () => {
  it('accepts valid label', () => {
    const next = jest.fn();
    const res = makeRes();
    validateGremlinSelectors(makeReq({ label: 'EC2Instance' }), res, next);
    expect(next).toHaveBeenCalled();
    expect(res.statusCode).toBe(200);
  });

  it('rejects label with Gremlin injection attempt', () => {
    const next = jest.fn();
    const res = makeRes();
    validateGremlinSelectors(makeReq({ label: "EC2'); g.drop()--" }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
    expect((res as any).body.code).toBe('INVALID_SELECTOR');
  });

  it('rejects label starting with a number', () => {
    const next = jest.fn();
    const res = makeRes();
    validateGremlinSelectors(makeReq({ label: '123' }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('rejects fromSelector injection', () => {
    const next = jest.fn();
    const res = makeRes();
    validateGremlinSelectors(makeReq({ fromSelector: 'Internet&.drop()' }), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(400);
  });

  it('skips validation when query params not provided', () => {
    const next = jest.fn();
    const res = makeRes();
    validateGremlinSelectors(makeReq({}), res, next);
    expect(next).toHaveBeenCalled();
  });
});
