import type { Request, Response } from 'express';
import { IssueIntegrationsOrchestrator } from '@khalifa/integrations';
import { IssueStore } from '../services/issue-store';

const issueStore = new IssueStore();

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

export async function suppressIssue(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const { reason } = req.body || {};

    const existing = await issueStore.getIssue(id);
    if (!existing) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Issue not found: ${id}` });
      return;
    }

    await issueStore.updateStatus(id, 'suppressed');
    res.json({ id, status: 'suppressed', reason: reason || null });
  } catch (error) {
    console.error('Error suppressing issue:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to suppress issue',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function reopenIssue(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;

    const existing = await issueStore.getIssue(id);
    if (!existing) {
      res.status(404).json({ code: 'NOT_FOUND', message: `Issue not found: ${id}` });
      return;
    }

    await issueStore.updateStatus(id, 'open');
    res.json({ id, status: 'open' });
  } catch (error) {
    console.error('Error reopening issue:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to reopen issue',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}
