import type { Request, Response } from 'express';
import {
  buildRuleQuality,
  DynamoDBIssueRepository,
  getRuleById,
  riskRules,
  RULE_QUALITY_MIN_HANDLED,
  RULE_QUALITY_NOISY_DISMISSAL_RATE,
  RULE_QUALITY_RELIABLE_DISMISSAL_RATE,
} from '@khalifa/risk-engine';
import type { RuleQualityResponse } from '../types';

const issueStore = new DynamoDBIssueRepository();

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

// Per-rule quality: the human outcome of every issue a rule ever raised. A
// suppressed issue was judged not worth fixing; a resolved one stopped
// matching. dismissalRate is the noise proxy the verdict and, later, the
// auto-ticket decision read. Bounded by the same StatusIndex reads the issue
// summary uses.
export async function getRuleQuality(_req: Request, res: Response): Promise<void> {
  try {
    const counts = await issueStore.getRuleStatusCounts();
    const rules = buildRuleQuality(counts).map((quality) => {
      const rule = getRuleById(quality.ruleId);
      return {
        ...quality,
        name: rule?.name ?? quality.ruleId,
        ownerTeam: rule?.ownerTeam ?? '',
        severityHint: rule?.severityHint ?? null,
        enabled: rule?.enabled ?? false,
        autoTicket: rule?.autoTicketConfig?.enabled ?? false,
        inCatalogue: Boolean(rule),
      };
    });
    const body: RuleQualityResponse = {
      rules,
      thresholds: {
        minHandled: RULE_QUALITY_MIN_HANDLED,
        reliableDismissalRate: RULE_QUALITY_RELIABLE_DISMISSAL_RATE,
        noisyDismissalRate: RULE_QUALITY_NOISY_DISMISSAL_RATE,
      },
      generatedAt: new Date().toISOString(),
    };
    res.json(body);
  } catch (error) {
    console.error('Error building rule quality:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to build rule quality' });
  }
}

export async function getRule(req: Request, res: Response): Promise<void> {
  const rule = getRuleById(req.params.id);
  if (!rule) {
    res.status(404).json({ code: 'NOT_FOUND', message: `Unknown rule ${req.params.id}` });
    return;
  }
  res.json(publicRule(rule));
}
