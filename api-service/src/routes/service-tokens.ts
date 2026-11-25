import type { Request, Response } from 'express';
import { ServiceTokenStore, parseServiceTokenInput } from '../services/service-token-store';

const store = new ServiceTokenStore();
const TOKEN_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

// The actor always comes from the verified token, never from the request body.
function actor(req: Request): string | null {
  return req.user?.email || req.user?.sub || null;
}

function badRequest(res: Response, message: string): void {
  res.status(400).json({ code: 'BAD_REQUEST', message });
}

export async function createServiceToken(req: Request, res: Response): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseServiceTokenInput(body);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    const created = await store.createToken(parsed.input, caller);
    // The plaintext token exists only in this response: it is never stored,
    // never listed, and never logged.
    res.json({ token: created.token, tokenRecord: created.record });
  } catch (error) {
    console.error('Error creating service token:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to create service token' });
  }
}

export async function listServiceTokens(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ items: await store.listTokens() });
  } catch (error) {
    console.error('Error listing service tokens:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list service tokens' });
  }
}

export async function revokeServiceToken(
  req: Request<{ id: string }>,
  res: Response
): Promise<void> {
  try {
    const { id } = req.params;
    const revoked = TOKEN_ID_PATTERN.test(id) ? await store.revokeToken(id) : false;
    if (!revoked) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Service token not found: ${id}` });
      return;
    }
    res.json({ id, revoked: true });
  } catch (error) {
    console.error('Error revoking service token:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to revoke service token' });
  }
}
