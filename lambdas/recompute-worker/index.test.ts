import { recomputeMinIntervalSeconds, runRecomputeWorker } from './index';

const environment = {
  AWS_REGION: 'us-west-2',
  RECOMPUTE_QUEUE_URL: 'https://sqs.us-west-2.amazonaws.com/111122223333/khalifa-recompute.fifo',
  NEPTUNE_ENDPOINT: 'cluster:8182',
};

// Serves scripted receive batches, then aborts the loop so the test ends.
function sqsWithBatches(
  batches: { Messages?: { ReceiptHandle?: string }[] }[],
  controller: AbortController
): any {
  const received: number[] = [];
  return {
    received,
    send: jest.fn(
      async (command: { constructor: { name: string }; input: Record<string, unknown> }) => {
        if (command.constructor.name === 'ReceiveMessageCommand') {
          const batch = batches.shift();
          if (!batch) {
            controller.abort();
            return { Messages: [] };
          }
          received.push(batch.Messages?.length ?? 0);
          return batch;
        }
        return {};
      }
    ),
  };
}

const message = (id: string) => ({ ReceiptHandle: `handle-${id}` });

describe('recomputeMinIntervalSeconds', () => {
  it('defaults to fifteen minutes and validates bounds', () => {
    expect(recomputeMinIntervalSeconds({})).toBe(900);
    expect(recomputeMinIntervalSeconds({ RECOMPUTE_MIN_INTERVAL_SECONDS: '300' })).toBe(300);
    expect(recomputeMinIntervalSeconds({ RECOMPUTE_MIN_INTERVAL_SECONDS: '0' })).toBe(0);
    expect(() => recomputeMinIntervalSeconds({ RECOMPUTE_MIN_INTERVAL_SECONDS: 'x' })).toThrow(
      'RECOMPUTE_MIN_INTERVAL_SECONDS must be an integer between 0 and 86400'
    );
    expect(() => recomputeMinIntervalSeconds({ RECOMPUTE_MIN_INTERVAL_SECONDS: '90000' })).toThrow(
      'between 0 and 86400'
    );
  });
});

describe('runRecomputeWorker', () => {
  it('evaluates once per interval, deleting covered messages', async () => {
    const controller = new AbortController();
    const sqs = sqsWithBatches(
      [{ Messages: [message('1'), message('2')] }, { Messages: [message('3')] }],
      controller
    );
    const clock = Date.parse('2026-10-27T12:00:00Z');
    const evaluate = jest.fn().mockResolvedValue({});

    const result = await runRecomputeWorker(environment, {
      sqsClient: sqs,
      evaluate: evaluate as never,
      now: () => new Date(clock),
      signal: controller.signal,
    });

    expect(result).toEqual({ messages: 3, evaluations: 1, skipped: 1 });
    expect(evaluate).toHaveBeenCalledWith({}, environment);
    const deletes = sqs.send.mock.calls.filter(
      ([command]: [{ constructor: { name: string } }]) =>
        command.constructor.name === 'DeleteMessageCommand'
    );
    expect(deletes).toHaveLength(3);
  });

  it('evaluates again once the interval has elapsed', async () => {
    const controller = new AbortController();
    const sqs = sqsWithBatches(
      [{ Messages: [message('1')] }, { Messages: [message('2')] }],
      controller
    );
    let clock = Date.parse('2026-10-27T12:00:00Z');
    const evaluate = jest.fn().mockImplementation(async () => {
      clock += 901_000; // next batch lands outside the 900s interval
    });

    const result = await runRecomputeWorker(environment, {
      sqsClient: sqs,
      evaluate: evaluate as never,
      now: () => new Date(clock),
      signal: controller.signal,
    });

    expect(result.evaluations).toBe(2);
    expect(result.skipped).toBe(0);
  });

  it('leaves messages for redelivery when evaluation fails', async () => {
    const controller = new AbortController();
    const sqs = sqsWithBatches([{ Messages: [message('1')] }], controller);
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);
    const evaluate = jest.fn().mockRejectedValue(new Error('Neptune unavailable'));
    const current = Date.now();
    const now = () => new Date(current);

    const result = await runRecomputeWorker(environment, {
      sqsClient: sqs,
      evaluate: evaluate as never,
      now,
      signal: controller.signal,
    });

    error.mockRestore();
    expect(result).toEqual({ messages: 1, evaluations: 0, skipped: 0 });
    const deletes = sqs.send.mock.calls.filter(
      ([command]: [{ constructor: { name: string } }]) =>
        command.constructor.name === 'DeleteMessageCommand'
    );
    expect(deletes).toHaveLength(0);
  });

  it('requires the queue url', async () => {
    await expect(runRecomputeWorker({}, {})).rejects.toThrow('RECOMPUTE_QUEUE_URL is required');
  });
});
