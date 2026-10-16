import type { Request, Response } from 'express';
import { getRuleById, riskRules } from '@khalifa/risk-engine';

function publicRule(rule: (typeof riskRules)[number]) {
  return {
    id: rule.id,
    name: rule.name,
    description: rule.description,
    severityHint: rule.severityHint,
    ownerTeam: rule.ownerTeam,
    enabled: rule.enabled,
  };
}

export async function listRules(_req: Request, res: Response): Promise<void> {
  res.json({ rules: riskRules.map(publicRule) });
}

export async function getRule(req: Request, res: Response): Promise<void> {
  const rule = getRuleById(req.params.id);
  if (!rule) {
    res.status(404).json({ code: 'NOT_FOUND', message: `Unknown rule ${req.params.id}` });
    return;
  }
  res.json(publicRule(rule));
}
