import { RiskRuleRunner } from './runner';
import type { RuleExecutionResult } from './types';

interface Runner {
  initialize(): Promise<void>;
  runAllRules(): Promise<RuleExecutionResult[]>;
  shutdown(): Promise<void>;
}

export interface RunSummary {
  rulesRun: number;
  issuesCreated: number;
  issuesResolved: number;
}

export async function runOnce(
  neptuneEndpoint: string,
  createRunner: (endpoint: string) => Runner = (endpoint) => new RiskRuleRunner(endpoint)
): Promise<RunSummary> {
  if (!neptuneEndpoint.trim()) {
    throw new Error('NEPTUNE_ENDPOINT is required');
  }

  const runner = createRunner(neptuneEndpoint);
  try {
    await runner.initialize();
    const results = await runner.runAllRules();
    const errors = results.flatMap((result) =>
      (result.errors || []).map((error) => `${result.ruleId}: ${error}`)
    );

    if (errors.length > 0) {
      throw new Error(`Risk assessment failed: ${errors.join('; ')}`);
    }

    return results.reduce<RunSummary>(
      (summary, result) => ({
        rulesRun: summary.rulesRun + 1,
        issuesCreated: summary.issuesCreated + result.issuesCreated,
        issuesResolved: summary.issuesResolved + result.issuesResolved,
      }),
      { rulesRun: 0, issuesCreated: 0, issuesResolved: 0 }
    );
  } finally {
    await runner.shutdown();
  }
}

export async function handler(): Promise<RunSummary> {
  return runOnce(process.env.NEPTUNE_ENDPOINT || '');
}
