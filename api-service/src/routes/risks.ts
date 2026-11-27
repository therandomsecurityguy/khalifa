import type { Request, Response } from 'express';
import { getAllControls } from '@khalifa/risk-engine';
import {
  RiskRegisterStore,
  parseRiskFields,
  slugify,
  RISK_ID_PATTERN,
} from '../services/risk-register-store';

const store = new RiskRegisterStore();
// Linked controls are validated against the canonical catalogue so a register
// entry cannot point at a control id nothing else in the product knows.
const KNOWN_CONTROLS = new Set(getAllControls().map((control) => control.id));

// The actor always comes from the verified token, never from the request body.
function actor(req: Request): string | null {
  return req.user?.email || req.user?.sub || null;
}

function badRequest(res: Response, message: string): void {
  res.status(400).json({ code: 'BAD_REQUEST', message });
}

export async function listRisks(_req: Request, res: Response): Promise<void> {
  try {
    const { items, truncated } = await store.listRisks();
    res.json({ items, truncated });
  } catch (error) {
    console.error('Error listing risks:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list risks' });
  }
}

export async function createRisk(req: Request, res: Response): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseRiskFields(body, caller, KNOWN_CONTROLS);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    let id: string;
    if (body.id !== undefined) {
      if (typeof body.id !== 'string' || !RISK_ID_PATTERN.test(body.id)) {
        badRequest(res, 'id must match ^[a-z0-9][a-z0-9-]{0,63}$');
        return;
      }
      id = body.id;
    } else {
      id = slugify(parsed.fields.title);
      if (!id) {
        badRequest(res, 'title must contain at least one alphanumeric character');
        return;
      }
    }
    const created = await store.createRisk(id, parsed.fields, caller);
    if (!created) {
      res.status(409).json({ code: 'CONFLICT', message: `Risk already exists: ${id}` });
      return;
    }
    res.json({ risk: created });
  } catch (error) {
    console.error('Error creating risk:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to create risk' });
  }
}

export async function getRisk(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const risk = RISK_ID_PATTERN.test(id) ? await store.getRisk(id) : null;
    if (!risk) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Risk not found: ${id}` });
      return;
    }
    res.json({ risk });
  } catch (error) {
    console.error('Error getting risk:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get risk' });
  }
}

export async function updateRisk(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const { id } = req.params;
    if (!RISK_ID_PATTERN.test(id)) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Risk not found: ${id}` });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseRiskFields(body, caller, KNOWN_CONTROLS);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    const updated = await store.updateRisk(id, parsed.fields, caller);
    if (!updated) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Risk not found: ${id}` });
      return;
    }
    res.json({ risk: updated });
  } catch (error) {
    console.error('Error updating risk:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to update risk' });
  }
}

export async function deleteRisk(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const deleted = RISK_ID_PATTERN.test(id) ? await store.deleteRisk(id) : false;
    if (!deleted) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Risk not found: ${id}` });
      return;
    }
    res.json({ id, deleted: true });
  } catch (error) {
    console.error('Error deleting risk:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to delete risk' });
  }
}
