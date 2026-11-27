import type { Request, Response } from 'express';
import { getApiNeptuneClient } from '../services/api-dependencies';
import {
  AccessReviewStore,
  parseAccessReviewFields,
  parseReviewDecision,
  slugify,
  summarizeCompletion,
  REVIEW_ID_PATTERN,
} from '../services/access-review-store';

const store = new AccessReviewStore();
const neptuneClient = getApiNeptuneClient();

// The actor always comes from the verified token, never from the request body.
function actor(req: Request): string | null {
  return req.user?.email || req.user?.sub || null;
}

function badRequest(res: Response, message: string): void {
  res.status(400).json({ code: 'BAD_REQUEST', message });
}

function notFound(res: Response, id: string): void {
  res.status(404).json({ code: 'NOT_FOUND', message: `Access review not found: ${id}` });
}

export async function listAccessReviews(_req: Request, res: Response): Promise<void> {
  try {
    const { items, truncated } = await store.listReviews();
    res.json({ items, truncated });
  } catch (error) {
    console.error('Error listing access reviews:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list access reviews' });
  }
}

export async function createAccessReview(req: Request, res: Response): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseAccessReviewFields(body);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    let id: string;
    if (body.id !== undefined) {
      if (typeof body.id !== 'string' || !REVIEW_ID_PATTERN.test(body.id)) {
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
    const created = await store.createReview(id, parsed.fields, caller);
    if (!created) {
      res.status(409).json({ code: 'CONFLICT', message: `Access review already exists: ${id}` });
      return;
    }
    res.json({ review: created });
  } catch (error) {
    console.error('Error creating access review:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to create access review' });
  }
}

export async function getAccessReview(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const review = REVIEW_ID_PATTERN.test(id) ? await store.getReview(id) : null;
    if (!review) {
      notFound(res, id);
      return;
    }
    res.json({ review });
  } catch (error) {
    console.error('Error getting access review:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get access review' });
  }
}

export async function updateAccessReview(
  req: Request<{ id: string }>,
  res: Response
): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const { id } = req.params;
    if (!REVIEW_ID_PATTERN.test(id)) {
      notFound(res, id);
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseAccessReviewFields(body);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    const existing = await store.getReview(id);
    if (!existing) {
      notFound(res, id);
      return;
    }

    // Completing the review captures the evidence snapshot: what the graph
    // holds for every covered principal at this moment, plus decision counts.
    // A graph read failure fails the completion (no snapshot, no completion)
    // rather than storing a hollow summary.
    let completion: Parameters<typeof store.updateReview>[3];
    if (parsed.fields.status === 'completed' && existing.status !== 'completed') {
      const vertices = await neptuneClient.getResources(parsed.fields.principals);
      const carried = existing.decisions.filter((decision) =>
        parsed.fields.principals.includes(decision.principalArn)
      );
      completion = summarizeCompletion(
        parsed.fields.principals,
        carried,
        vertices,
        caller,
        new Date().toISOString()
      );
    }

    const updated = await store.updateReview(id, parsed.fields, caller, completion);
    if (!updated) {
      notFound(res, id);
      return;
    }
    res.json({ review: updated });
  } catch (error) {
    console.error('Error updating access review:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to update access review' });
  }
}

export async function recordAccessReviewDecision(
  req: Request<{ id: string }>,
  res: Response
): Promise<void> {
  try {
    const caller = actor(req);
    if (!caller) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const { id } = req.params;
    if (!REVIEW_ID_PATTERN.test(id)) {
      notFound(res, id);
      return;
    }
    const review = await store.getReview(id);
    if (!review) {
      notFound(res, id);
      return;
    }
    // Decisions are only meaningful while the review is running.
    if (review.status !== 'active') {
      res.status(409).json({
        code: 'CONFLICT',
        message: `Access review is not active (status: ${review.status})`,
      });
      return;
    }
    const body = (req.body || {}) as Record<string, unknown>;
    const parsed = parseReviewDecision(body);
    if ('error' in parsed) {
      badRequest(res, parsed.error);
      return;
    }
    if (!review.principals.includes(parsed.decision.principalArn)) {
      badRequest(res, 'principalArn is not covered by this review');
      return;
    }
    const updated = await store.recordDecision(id, parsed.decision, caller);
    if (!updated) {
      notFound(res, id);
      return;
    }
    res.json({ review: updated });
  } catch (error) {
    console.error('Error recording access review decision:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to record decision' });
  }
}

export async function deleteAccessReview(
  req: Request<{ id: string }>,
  res: Response
): Promise<void> {
  try {
    const { id } = req.params;
    const deleted = REVIEW_ID_PATTERN.test(id) ? await store.deleteReview(id) : false;
    if (!deleted) {
      notFound(res, id);
      return;
    }
    res.json({ id, deleted: true });
  } catch (error) {
    console.error('Error deleting access review:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to delete access review' });
  }
}
