import type { Request } from 'express';
import { hasRole, requireRole, Role } from '../middleware/rbac';

function makeReq(groups: string[]): Request {
  return { user: { sub: 'user', groups, tokenUse: 'id' as const } } as unknown as Request;
}

describe('RBAC', () => {
  it('Admin user has Admin/Analyst/Viewer role', () => {
    expect(hasRole(makeReq(['khalifa-admin']), Role.Admin)).toBe(true);
    expect(hasRole(makeReq(['khalifa-admin']), Role.Analyst)).toBe(true);
    expect(hasRole(makeReq(['khalifa-admin']), Role.Viewer)).toBe(true);
  });

  it('Analyst user has Analyst/Viewer role', () => {
    expect(hasRole(makeReq(['khalifa-analyst']), Role.Admin)).toBe(false);
    expect(hasRole(makeReq(['khalifa-analyst']), Role.Analyst)).toBe(true);
    expect(hasRole(makeReq(['khalifa-analyst']), Role.Viewer)).toBe(true);
  });

  it('Viewer user has only Viewer role', () => {
    expect(hasRole(makeReq(['khalifa-viewer']), Role.Admin)).toBe(false);
    expect(hasRole(makeReq(['khalifa-viewer']), Role.Analyst)).toBe(false);
    expect(hasRole(makeReq(['khalifa-viewer']), Role.Viewer)).toBe(true);
  });

  it('User with no cognito groups has no role', () => {
    expect(hasRole(makeReq([]), Role.Viewer)).toBe(false);
    expect(hasRole(makeReq([]), Role.Analyst)).toBe(false);
    expect(hasRole(makeReq([]), Role.Admin)).toBe(false);
  });

  it('requireRole rejects without role', () => {
    const middleware = requireRole(Role.Viewer);
    const next = jest.fn();
    const res: any = {
      statusCode: 200,
      status(code: number) {
        this.statusCode = code;
        return this;
      },
      json(b: any) {
        this.body = b;
        return this;
      },
    };
    middleware(makeReq([]), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });

  it('requireRole allows Admin to access lower-role gate', () => {
    const middleware = requireRole(Role.Viewer);
    const next = jest.fn();
    const res: any = {
      status: () => res,
      json: () => res,
    };
    middleware(makeReq(['khalifa-admin']), res, next);
    expect(next).toHaveBeenCalled();
  });
});