import type { Request, Response, NextFunction } from 'express';

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
  if (!current) return false;
  return ROLE_HIERARCHY[current].includes(role);
}

export function requireRole(role: Role) {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!hasRole(req, role)) {
      res.status(403).json({
        code: 'FORBIDDEN',
        message: `Requires ${role} role (cognito group khalifa-${role.toLowerCase()})`,
      });
      return;
    }
    next();
  };
}

export const requireViewer = requireRole(Role.Viewer);
export const requireAnalyst = requireRole(Role.Analyst);
export const requireAdmin = requireRole(Role.Admin);