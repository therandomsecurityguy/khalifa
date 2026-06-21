import type { Request, Response, NextFunction } from 'express';

const LABEL_PATTERN = /^[A-Za-z][A-Za-z0-9_]*$/;

const QUERY_PARAMS_TO_VALIDATE = ['fromSelector', 'toSelector', 'label', 'property'];

export function validateGremlinSelectors(req: Request, res: Response, next: NextFunction): void {
  for (const param of QUERY_PARAMS_TO_VALIDATE) {
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
