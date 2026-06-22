import type { Request, Response, NextFunction } from 'express';

const LABEL_PATTERN = /^[A-Za-z][A-Za-z0-9_]*$/;
const ARN_PATTERN = /^arn:aws[a-z-]*:[a-z]+:[a-z0-9-]+:\d{12}:.+$|^\d{12}$|^\*$/;

const LABEL_PARAMS = [
  'fromSelector',
  'toSelector',
  'label',
  'property',
  'escalationType',
  'riskLevel',
];
const ARN_PARAMS = ['principal', 'sourceAccount', 'targetRole'];

export function validateGremlinSelectors(req: Request, res: Response, next: NextFunction): void {
  for (const param of LABEL_PARAMS) {
    const value = req.query[param];
    if (value === undefined) continue;
    const candidates = Array.isArray(value) ? value : [value];
    for (const candidate of candidates) {
      if (typeof candidate !== 'string') continue;
      if (!LABEL_PATTERN.test(candidate)) {
        res.status(400).json({
          code: 'INVALID_SELECTOR',
          message: `Query parameter '${param}' must match ${LABEL_PATTERN} (alphanumeric + underscore)`,
        });
        return;
      }
    }
  }

  for (const param of ARN_PARAMS) {
    const value = req.query[param];
    if (value === undefined) continue;
    const candidates = Array.isArray(value) ? value : [value];
    for (const candidate of candidates) {
      if (typeof candidate !== 'string') continue;
      if (!ARN_PATTERN.test(candidate)) {
        res.status(400).json({
          code: 'INVALID_ARN_PARAM',
          message: `Query parameter '${param}' must be a valid AWS ARN, account ID, or '*'`,
        });
        return;
      }
    }
  }

  next();
}

export function validateArnParam(req: Request, res: Response, next: NextFunction): void {
  const arn = req.params.arn;
  if (!arn) {
    next();
    return;
  }
  if (typeof arn !== 'string' || !arn.startsWith('arn:')) {
    res.status(400).json({
      code: 'INVALID_ARN',
      message: 'Path parameter :arn must be a valid AWS ARN',
    });
    return;
  }
  next();
}
