import type { Request, Response } from 'express';
import { getApiNeptuneClient } from '../services/api-dependencies';
import {
  AiUseCaseStore,
  parseUseCaseFields,
  slugify,
  USE_CASE_ID_PATTERN,
  type AiUseCase,
} from '../services/ai-use-case-store';

const store = new AiUseCaseStore();
const neptuneClient = getApiNeptuneClient();
// Coverage joins the hand-maintained registry against the collected AI
// estate; the estate is the larger side, so the inventory read is capped and
// the response says when it was.
const COVERAGE_INVENTORY_LIMIT = 200;

// The actor always comes from the verified token, never from the request body.
function actor(req: Request): string | null {
  return req.user?.email || req.user?.sub || null;
}

function badRequest(res: Response, message: string): void {
  res.status(400).json({ code: 'BAD_REQUEST', message });
}

export async function listAiUseCases(_req: Request, res: Response): Promise<void> {
  try {
    const { items, truncated } = await store.listUseCases();
    res.json({ items, truncated });
  } catch (error) {
    console.error('Error listing AI use cases:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list AI use cases' });
  }
}

export async function createAiUseCase(req: Request, res: Response): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseUseCaseFields(body, caller);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    let id: string;
    if (body.id !== undefined) {
      if (typeof body.id !== 'string' || !USE_CASE_ID_PATTERN.test(body.id)) {
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
    const created = await store.createUseCase(id, parsed.fields, caller);
    if (!created) {
      res.status(409).json({ code: 'CONFLICT', message: `Use case already exists: ${id}` });
      return;
    }
    res.json({ useCase: created });
  } catch (error) {
    console.error('Error creating AI use case:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to create AI use case' });
  }
}

export async function getAiUseCase(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const useCase = USE_CASE_ID_PATTERN.test(id) ? await store.getUseCase(id) : null;
    if (!useCase) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Use case not found: ${id}` });
      return;
    }
    res.json({ useCase });
  } catch (error) {
    console.error('Error getting AI use case:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get AI use case' });
  }
}

export async function updateAiUseCase(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const { id } = req.params;
    if (!USE_CASE_ID_PATTERN.test(id)) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Use case not found: ${id}` });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseUseCaseFields(body, caller);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    const updated = await store.updateUseCase(id, parsed.fields, caller);
    if (!updated) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Use case not found: ${id}` });
      return;
    }
    res.json({ useCase: updated });
  } catch (error) {
    console.error('Error updating AI use case:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to update AI use case' });
  }
}

export async function deleteAiUseCase(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const deleted = USE_CASE_ID_PATTERN.test(id) ? await store.deleteUseCase(id) : false;
    if (!deleted) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Use case not found: ${id}` });
      return;
    }
    res.json({ id, deleted: true });
  } catch (error) {
    console.error('Error deleting AI use case:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to delete AI use case' });
  }
}

interface UnregisteredAsset {
  arn: string;
  type: string;
  label: string;
  name: string | null;
  account_id: string | null;
  region: string | null;
}

/**
 * Registry against graph: which collected AI assets no use case covers
 * (unregistered), and which registered assets are missing from the graph
 * (deleted, or in an account/region the collector does not cover). Coverage
 * is only as fresh as the graph, and the response flags truncation instead of
 * pretending the estate is fully listed.
 */
export async function getAiUseCaseCoverage(_req: Request, res: Response): Promise<void> {
  try {
    const [{ items, truncated: registryTruncated }, inventory] = await Promise.all([
      store.listUseCases(),
      neptuneClient.listAiInventory(COVERAGE_INVENTORY_LIMIT),
    ]);

    const registeredByAsset = new Map<string, string>();
    for (const useCase of items) {
      for (const asset of useCase.assets) {
        if (!registeredByAsset.has(asset)) registeredByAsset.set(asset, useCase.id);
      }
    }

    let inventoryTruncated = false;
    const unregistered: UnregisteredAsset[] = [];
    const inventoryArns = new Set<string>();
    for (const section of inventory) {
      if (section.truncated) inventoryTruncated = true;
      for (const item of section.items) {
        inventoryArns.add(item.arn);
        if (!registeredByAsset.has(item.arn)) {
          unregistered.push({
            arn: item.arn,
            type: section.type,
            label: section.label,
            name: item.name,
            account_id: item.account_id,
            region: item.region,
          });
        }
      }
    }
    unregistered.sort((a, b) => a.arn.localeCompare(b.arn, 'en'));

    const missing = items
      .flatMap((useCase: AiUseCase) =>
        useCase.assets
          .filter((asset) => !inventoryArns.has(asset))
          .map((asset) => ({ arn: asset, useCaseId: useCase.id }))
      )
      .sort((a, b) => a.arn.localeCompare(b.arn, 'en'));

    res.json({
      useCaseCount: items.length,
      registeredAssets: registeredByAsset.size,
      unregistered,
      missing,
      truncated: inventoryTruncated || registryTruncated,
    });
  } catch (error) {
    console.error('Error getting AI use-case coverage:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get AI use-case coverage' });
  }
}
