import type { Request, Response, NextFunction } from 'express';
import { isTrustedEmail } from './auth';

export enum Role {
  Admin = 'Admin',
  Analyst = 'Analyst',
  Viewer = 'Viewer',
}

export const ROLE_HIERARCHY: Record<Role, Role[]> = {
  [Role.Admin]: [Role.Admin, Role.Analyst, Role.Viewer],
  [Role.Analyst]: [Role.Analyst, Role.Viewer],
  [Role.Viewer]: [Role.Viewer],
};

const COGNITO_GROUP_TO_ROLE: Record<string, Role> = {
  'khalifa-admin': Role.Admin,
  'khalifa-analyst': Role.Analyst,
  'khalifa-viewer': Role.Viewer,
};

export function userRole(req: Request): Role | null {
  if (!req.user) return null;
  const groups = req.user.groups;
  for (const group of groups) {
    if (COGNITO_GROUP_TO_ROLE[group] === Role.Admin) return Role.Admin;
  }
  for (const group of groups) {
    if (COGNITO_GROUP_TO_ROLE[group] === Role.Analyst) return Role.Analyst;
  }
  for (const group of groups) {
    if (COGNITO_GROUP_TO_ROLE[group] === Role.Viewer) return Role.Viewer;
  }
  return null;
}

export function hasRole(req: Request, role: Role): boolean {
  const current = userRole(req);
  if (current && ROLE_HIERARCHY[current].includes(role)) {
    return true;
  }
  // A verified email is the authentication floor (Viewer); elevated roles
  // (Analyst/Admin) require an explicit Cognito group, not just an email domain.
  if (isTrustedEmail(req.user?.email)) {
    return role === Role.Viewer;
  }
  return false;
}

export function requireRole(role: Role) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!hasRole(req, role)) {
      res.status(403).json({
        code: 'FORBIDDEN',
        message: 'Insufficient role',
      });
      return;
    }
    next();
  };
}

export const requireViewer = requireRole(Role.Viewer);
export const requireAnalyst = requireRole(Role.Analyst);
export const requireAdmin = requireRole(Role.Admin);

// The trust-center sync's service token, and nothing else: staff roles do not
// grant it, so the endpoint stays a machine interface with one caller.
export function requireTrustCenterSync(req: Request, res: Response, next: NextFunction): void {
  if (req.user?.serviceToken !== true) {
    res.status(403).json({ code: 'FORBIDDEN', message: 'Trust-center sync token required' });
    return;
  }
  next();
}
