import type { Request, Response } from 'express';
import { isTrustedEmail } from '../middleware/auth';
import { hasRole, Role, userRole } from '../middleware/rbac';

export function getSession(req: Request, res: Response): void {
  const current = userRole(req);
  const canManageIssues = hasRole(req, Role.Analyst);
  const role =
    current ??
    (canManageIssues ? Role.Analyst : isTrustedEmail(req.user?.email) ? Role.Viewer : null);

  res.json({
    email: req.user?.email ?? null,
    role,
    canManageIssues,
  });
}
