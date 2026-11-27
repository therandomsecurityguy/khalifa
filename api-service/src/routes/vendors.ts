import type { Request, Response } from 'express';
import {
  VendorRegisterStore,
  parseVendorFields,
  slugify,
  VENDOR_ID_PATTERN,
} from '../services/vendor-register-store';

const store = new VendorRegisterStore();

// The actor always comes from the verified token, never from the request body.
function actor(req: Request): string | null {
  return req.user?.email || req.user?.sub || null;
}

function badRequest(res: Response, message: string): void {
  res.status(400).json({ code: 'BAD_REQUEST', message });
}

export async function listVendors(_req: Request, res: Response): Promise<void> {
  try {
    const { items, truncated } = await store.listVendors();
    res.json({ items, truncated });
  } catch (error) {
    console.error('Error listing vendors:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list vendors' });
  }
}

export async function createVendor(req: Request, res: Response): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseVendorFields(body, caller);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    let id: string;
    if (body.id !== undefined) {
      if (typeof body.id !== 'string' || !VENDOR_ID_PATTERN.test(body.id)) {
        badRequest(res, 'id must match ^[a-z0-9][a-z0-9-]{0,63}$');
        return;
      }
      id = body.id;
    } else {
      id = slugify(parsed.fields.name);
      if (!id) {
        badRequest(res, 'name must contain at least one alphanumeric character');
        return;
      }
    }
    const created = await store.createVendor(id, parsed.fields, caller);
    if (!created) {
      res.status(409).json({ code: 'CONFLICT', message: `Vendor already exists: ${id}` });
      return;
    }
    res.json({ vendor: created });
  } catch (error) {
    console.error('Error creating vendor:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to create vendor' });
  }
}

export async function getVendor(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const vendor = VENDOR_ID_PATTERN.test(id) ? await store.getVendor(id) : null;
    if (!vendor) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Vendor not found: ${id}` });
      return;
    }
    res.json({ vendor });
  } catch (error) {
    console.error('Error getting vendor:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get vendor' });
  }
}

export async function updateVendor(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const { id } = req.params;
    if (!VENDOR_ID_PATTERN.test(id)) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Vendor not found: ${id}` });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseVendorFields(body, caller);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    const updated = await store.updateVendor(id, parsed.fields, caller);
    if (!updated) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Vendor not found: ${id}` });
      return;
    }
    res.json({ vendor: updated });
  } catch (error) {
    console.error('Error updating vendor:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to update vendor' });
  }
}

export async function deleteVendor(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const deleted = VENDOR_ID_PATTERN.test(id) ? await store.deleteVendor(id) : false;
    if (!deleted) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Vendor not found: ${id}` });
      return;
    }
    res.json({ id, deleted: true });
  } catch (error) {
    console.error('Error deleting vendor:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to delete vendor' });
  }
}
