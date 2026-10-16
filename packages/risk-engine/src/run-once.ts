import { RiskRuleRunner } from './runner';

export interface RunOnceSummary {
  rulesRun: number;
  issuesCreated: number;
  issuesResolved: number;
}

export async function runOnce(
  neptuneEndpoint: string,
  createRunner: (endpoint: string) => RiskRuleRunner = (endpoint) => new RiskRuleRunner(endpoint)
): Promise<RunOnceSummary> {
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
    return results.reduce(
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
