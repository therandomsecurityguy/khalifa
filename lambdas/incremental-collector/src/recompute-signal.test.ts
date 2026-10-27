import { signalRecompute } from '../index';

const environment = {
  RECOMPUTE_QUEUE_URL: 'https://sqs.us-west-2.amazonaws.com/111122223333/khalifa-recompute.fifo',
};
const role = { id: 'arn:aws:iam::111122223333:role/app', label: 'IamRole', properties: {} };
const bucket = { id: 'arn:aws:s3:::data', label: 'S3Bucket', properties: {} };
const now = new Date('2026-10-27T12:03:00Z');

describe('signalRecompute', () => {
  it('queues one message for an IAM-sensitive batch, with a five-minute dedup id', async () => {
    const send = jest.fn().mockResolvedValue({});
    await expect(
      signalRecompute(
        { send } as never,
        environment,
        [role],
        [{ from: 'r', to: 'ext', label: 'TRUSTS' }],
        now
      )
    ).resolves.toBe(true);

    expect(send).toHaveBeenCalledTimes(1);
    const input = send.mock.calls[0][0].input;
    expect(input.QueueUrl).toBe(environment.RECOMPUTE_QUEUE_URL);
    expect(input.MessageGroupId).toBe('recompute');
    expect(input.MessageDeduplicationId).toMatch(/^recompute-\d+$/);
    expect(JSON.parse(input.MessageBody)).toMatchObject({
      reasons: ['IamRole', 'TRUSTS'],
      requestedAt: '2026-10-27T12:03:00.000Z',
    });
  });

  it('sends nothing for non-IAM batches or without a queue', async () => {
    const send = jest.fn().mockResolvedValue({});
    await expect(signalRecompute({ send } as never, environment, [bucket], [], now)).resolves.toBe(
      false
    );
    await expect(signalRecompute({ send } as never, {}, [role], [], now)).resolves.toBe(false);
    expect(send).not.toHaveBeenCalled();
  });

  it('never fails collection when the signal cannot be sent', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const send = jest.fn().mockRejectedValue(new Error('AccessDenied'));
    await expect(signalRecompute({ send } as never, environment, [role], [], now)).resolves.toBe(
      false
    );
    warn.mockRestore();
  });
});
