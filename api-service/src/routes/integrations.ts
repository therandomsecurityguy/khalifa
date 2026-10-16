import type { Request, Response } from 'express';
import { IssueIntegrationsOrchestrator } from '@khalifa/integrations';
import { DynamoDBIssueRepository } from '@khalifa/risk-engine';

const issueStore = new DynamoDBIssueRepository();

export const MAX_SUPPRESSION_DAYS = 90;
export const MAX_REASON_LENGTH = 500;
const DAY_MS = 24 * 60 * 60 * 1000;

export async function getIntegrationsStatus(_req: Request, res: Response): Promise<void> {
  try {
    const orchestrator = new IssueIntegrationsOrchestrator();
    const health = await orchestrator.healthCheck();
    res.json({
      configuredSinks: orchestrator.configuredSinks,
      health,
    });
  } catch (error) {
    console.error('Error getting integrations status:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get integrations status',
    });
  }
}

// The actor always comes from the verified token, never from the request body.
function actor(req: Request): string | null {
  return req.user?.email || req.user?.sub || null;
}

function parseReason(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const reason = value.trim();
  return reason && reason.length <= MAX_REASON_LENGTH ? reason : null;
}

function parseExpiry(value: unknown, now: number): string | null {
  if (typeof value !== 'string') return null;
  const expiry = Date.parse(value);
  if (Number.isNaN(expiry) || expiry <= now || expiry > now + MAX_SUPPRESSION_DAYS * DAY_MS) {
    return null;
  }
  return new Date(expiry).toISOString();
}

function badRequest(res: Response, message: string): void {
  res.status(400).json({ code: 'BAD_REQUEST', message });
}

export async function suppressIssue(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const body = (req.body || {}) as Record<string, unknown>;
    const by = actor(req);
    if (!by) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    const reason = parseReason(body.reason);
    if (!reason) {
      badRequest(res, `reason is required (1-${MAX_REASON_LENGTH} characters)`);
      return;
    }
    const until = parseExpiry(body.expiresAt, Date.now());
    if (!until) {
      badRequest(res, `expiresAt must be a future time within ${MAX_SUPPRESSION_DAYS} days`);
      return;
    }

    const existing = await issueStore.getIssueById(id);
    if (!existing) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Issue not found: ${id}` });
      return;
    }

    const updated = await issueStore.suppressIssue(existing, { by, reason, until });
    if (!updated) {
      res.status(409).json({ code: 'CONFLICT', message: `Issue state changed: ${id}` });
      return;
    }
    res.json({ id, status: 'suppressed', reason, expiresAt: until });
  } catch (error) {
    console.error('Error suppressing issue:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to suppress issue',
    });
  }
}

export async function reopenIssue(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const body = (req.body || {}) as Record<string, unknown>;
    const by = actor(req);
    if (!by) {
      res.status(401).json({ code: 'UNAUTHORIZED', message: 'Unknown caller' });
      return;
    }
    let reason = 'Reopened manually';
    if (body.reason !== undefined && body.reason !== '') {
      const parsed = parseReason(body.reason);
      if (!parsed) {
        badRequest(res, `reason must be 1-${MAX_REASON_LENGTH} characters`);
        return;
      }
      reason = parsed;
    }

    const existing = await issueStore.getIssueById(id);
    if (!existing) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Issue not found: ${id}` });
      return;
    }

    const updated = await issueStore.reopenIssue(existing, { by, reason });
    if (!updated) {
      res.status(409).json({ code: 'CONFLICT', message: `Issue state changed: ${id}` });
      return;
    }
    res.json({ id, status: 'open' });
  } catch (error) {
    console.error('Error reopening issue:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to reopen issue',
    });
  }
}
