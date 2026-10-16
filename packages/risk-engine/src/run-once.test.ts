import { RiskRuleRunner } from './runner';
import { runOnce } from './run-once';

interface FakeRunner {
  initialize: jest.Mock;
  runAllRules: jest.Mock;
  shutdown: jest.Mock;
}

function fakeRunner(results: unknown[]): FakeRunner {
  return {
    initialize: jest.fn(async () => undefined),
    runAllRules: jest.fn(async () => results),
    shutdown: jest.fn(async () => undefined),
  };
}

function asRunner(runner: FakeRunner): RiskRuleRunner {
  return runner as unknown as RiskRuleRunner;
}

describe('runOnce', () => {
  it('rejects an empty endpoint', async () => {
    await expect(runOnce('  ')).rejects.toThrow('NEPTUNE_ENDPOINT is required');
  });

  it('aggregates the per-rule results', async () => {
    const runner = fakeRunner([
      { ruleId: 'RULE-001', executionTime: 1, matches: [], issuesCreated: 2, issuesResolved: 1 },
      { ruleId: 'RULE-002', executionTime: 1, matches: [], issuesCreated: 1, issuesResolved: 0 },
    ]);

    await expect(runOnce('wss://cluster/gremlin', () => asRunner(runner))).resolves.toEqual({
      rulesRun: 2,
      issuesCreated: 3,
      issuesResolved: 1,
    });
    expect(runner.initialize).toHaveBeenCalledTimes(1);
    expect(runner.shutdown).toHaveBeenCalledTimes(1);
  });

  it('fails with the collected rule errors and still shuts down', async () => {
    const runner = fakeRunner([
      {
        ruleId: 'RULE-001',
        executionTime: 1,
        matches: [],
        issuesCreated: 0,
        issuesResolved: 0,
        errors: ['boom'],
      },
      {
        ruleId: 'RULE-002',
        executionTime: 1,
        matches: [],
        issuesCreated: 0,
        issuesResolved: 0,
        errors: ['bang'],
      },
    ]);

    await expect(runOnce('wss://cluster/gremlin', () => asRunner(runner))).rejects.toThrow(
      'Risk assessment failed: RULE-001: boom; RULE-002: bang'
    );
    expect(runner.shutdown).toHaveBeenCalledTimes(1);
  });
});
