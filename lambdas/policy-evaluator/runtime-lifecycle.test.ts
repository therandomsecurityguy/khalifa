import { NeptuneRuntimeClient } from '@khalifa/risk-engine';
import { runPolicyEvaluation } from './index';

jest.mock('@khalifa/risk-engine', () => {
  const actual = jest.requireActual('@khalifa/risk-engine');
  return { ...actual, NeptuneRuntimeClient: jest.fn() };
});

const ClientMock = NeptuneRuntimeClient as unknown as jest.Mock;

describe('policy-evaluator EKS lifecycle', () => {
  beforeEach(() => {
    ClientMock.mockReset();
    ClientMock.mockImplementation(() => ({
      submit: jest.fn(async () => ({ toArray: () => [] })),
      close: jest.fn(async () => undefined),
    }));
  });

  it('closes the Neptune client so the one-shot runtime can exit', async () => {
    // Without the close, the SigV4 WebSocket keeps the process alive and the
    // CronJob pod never terminates.
    const result = await runPolicyEvaluation({}, {
      NEPTUNE_ENDPOINT: 'wss://cluster:8182/gremlin',
    } as NodeJS.ProcessEnv);

    expect(result).toEqual({ permissionsEvaluated: 0, escalationPaths: 0 });
    const instance = ClientMock.mock.results[0].value as { close: jest.Mock };
    expect(instance.close).toHaveBeenCalledTimes(1);
  });
});
