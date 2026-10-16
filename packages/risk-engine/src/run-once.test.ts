import { runOnce } from './run-once';
import type { RuleExecutionResult } from './types';

function createRunner(results: RuleExecutionResult[]) {
  return {
    initialize: jest.fn().mockResolvedValue(undefined),
    runAllRules: jest.fn().mockResolvedValue(results),
    shutdown: jest.fn().mockResolvedValue(undefined),
  };
}

describe('runOnce', () => {
  it('returns an aggregate summary and closes the runner', async () => {
    const runner = createRunner([
      {
        ruleId: 'RULE-001',
        executionTime: 10,
        matches: [],
        issuesCreated: 2,
        issuesResolved: 1,
      },
      {
        ruleId: 'RULE-002',
        executionTime: 20,
        matches: [],
        issuesCreated: 3,
        issuesResolved: 4,
      },
    ]);

    await expect(runOnce('neptune:8182', () => runner)).resolves.toEqual({
      rulesRun: 2,
      issuesCreated: 5,
      issuesResolved: 5,
    });
    expect(runner.initialize).toHaveBeenCalledTimes(1);
    expect(runner.shutdown).toHaveBeenCalledTimes(1);
  });

  it('fails the job when a rule reports an error and still closes the runner', async () => {
    const runner = createRunner([
      {
        ruleId: 'RULE-001',
        executionTime: 10,
        matches: [],
        issuesCreated: 0,
        issuesResolved: 0,
        errors: ['query failed'],
      },
    ]);

    await expect(runOnce('neptune:8182', () => runner)).rejects.toThrow(
      'Risk assessment failed: RULE-001: query failed'
    );
    expect(runner.shutdown).toHaveBeenCalledTimes(1);
  });

  it('closes the runner when initialization fails', async () => {
    const runner = createRunner([]);
    runner.initialize.mockRejectedValue(new Error('connection failed'));

    await expect(runOnce('neptune:8182', () => runner)).rejects.toThrow('connection failed');
    expect(runner.shutdown).toHaveBeenCalledTimes(1);
  });

  it('rejects an empty Neptune endpoint before creating a runner', async () => {
    const createRunner = jest.fn();

    await expect(runOnce(' ', createRunner)).rejects.toThrow('NEPTUNE_ENDPOINT is required');
    expect(createRunner).not.toHaveBeenCalled();
  });
});
