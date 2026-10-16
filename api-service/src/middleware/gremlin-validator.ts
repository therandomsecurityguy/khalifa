import type { Request, Response, NextFunction } from 'express';
import { ALL_LABELS } from '../services/neptune-client';

const LABEL_PATTERN = /^[A-Za-z][A-Za-z0-9_]*$/;
const ARN_PATTERN =
  /^arn:(aws|aws-us-gov|aws-cn|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f|aws-eusc):[a-z0-9-]+:[^:]*:(?:\d{12})?:.+$/;
const ACCOUNT_ID_PATTERN = /^\d{12}$/;

const LABEL_PARAMS = [
  'fromSelector',
  'toSelector',
  'label',
  'property',
  'escalationType',
  'riskLevel',
];
const ARN_PARAMS = ['arn', 'principal', 'sourceAccount', 'targetRole', 'account'];

export function validateGremlinSelectors(req: Request, res: Response, next: NextFunction): void {
  for (const param of LABEL_PARAMS) {
    const value = req.query[param];
    if (value === undefined) continue;
    // The resource explorer's "All labels"; the resources routes never put it in a query.
    if (param === 'label' && value === ALL_LABELS) continue;
    if (typeof value !== 'string' || !LABEL_PATTERN.test(value)) {
      res.status(400).json({
        code: 'INVALID_SELECTOR',
        message: `Query parameter '${param}' must match ${LABEL_PATTERN} (alphanumeric + underscore)`,
      });
      return;
    }
  }

  for (const param of ARN_PARAMS) {
    const value = req.query[param];
    if (value === undefined) continue;
    if (
      typeof value !== 'string' ||
      (!ARN_PATTERN.test(value) && !ACCOUNT_ID_PATTERN.test(value))
    ) {
      res.status(400).json({
        code: 'INVALID_ARN_PARAM',
        message: `Query parameter '${param}' must be a valid AWS ARN or account ID`,
      });
      return;
    }
  }

  next();
}

export function validateArnPathParam(
  parameter: string
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction): void => {
    const arn = req.params[parameter];
    if (!arn) {
      next();
      return;
    }
    if (!ARN_PATTERN.test(arn)) {
      res.status(400).json({
        code: 'INVALID_ARN',
        message: `Path parameter :${parameter} must be a valid AWS ARN`,
      });
      return;
    }
    next();
  };
}

export function parseBoundedInteger(
  value: unknown,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string
): number {
  if (value === undefined) {
    return fallback;
  }
  if (typeof value !== 'string' || !/^\d+$/.test(value)) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}
