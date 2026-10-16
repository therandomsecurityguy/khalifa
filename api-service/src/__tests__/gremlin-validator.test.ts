import type { Request, Response } from 'express';
import {
  parseBoundedInteger,
  validateArnPathParam,
  validateGremlinSelectors,
} from '../middleware/gremlin-validator';

function response(): Response {
  const value: any = { statusCode: 200 };
  value.status = (statusCode: number) => Object.assign(value, { statusCode });
  value.json = (body: unknown) => Object.assign(value, { body });
  return value;
}

describe('Gremlin input validation', () => {
  it.each([
    [{ label: 'EC2Instance' }, true],
    [{ arn: 'arn:aws:iam::123456789012:role/team/Admin' }, true],
    [{ label: "EC2'); g.drop()--" }, false],
    [{ label: '*' }, true],
    [{ label: '**' }, false],
    [{ property: '*' }, false],
    [{ fromSelector: '*' }, false],
    [{ fromSelector: 'Internet&.drop()' }, false],
    [{ arn: 'arn:evil' }, false],
  ])('validates %p', (query, accepted) => {
    const next = jest.fn();
    const res = response();
    validateGremlinSelectors({ query } as unknown as Request, res, next);
    expect(next).toHaveBeenCalledTimes(accepted ? 1 : 0);
    expect(res.statusCode).toBe(accepted ? 200 : 400);
  });

  it('accepts a slash-containing ARN path parameter', () => {
    const next = jest.fn();
    validateArnPathParam('principal')(
      {
        params: { principal: 'arn:aws:iam::123456789012:role/team/Admin' },
      } as unknown as Request,
      response(),
      next
    );
    expect(next).toHaveBeenCalledTimes(1);
  });

  it.each(['1.5', '-1', '1e2', '201', ['10']])('rejects bounded integer %p', (value) => {
    expect(() => parseBoundedInteger(value, 10, 1, 200, 'limit')).toThrow(
      'limit must be an integer between 1 and 200'
    );
  });
});
