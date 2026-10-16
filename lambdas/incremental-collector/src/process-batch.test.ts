import { DeleteMessageCommand, ReceiveMessageCommand, type SQSClient } from '@aws-sdk/client-sqs';
import type { OrganizationsReader } from '../../shared/account-inventory';
import { processBatch } from '../index';

const environment = {
  AWS_REGION: 'us-west-2',
  COLLECTION_ACCOUNT_IDS: '111122223333',
  COLLECTION_REGIONS: 'us-west-2',
  HOME_ACCOUNT_ID: '111122223333',
  SQS_QUEUE_URL: 'https://sqs.us-west-2.amazonaws.com/111122223333/incremental.fifo',
};

const event = {
  account: '111122223333',
  region: 'us-west-2',
  source: 'aws.s3',
  'detail-type': 'AWS API Call via CloudTrail',
  detail: {
    eventSource: 's3.amazonaws.com',
    awsRegion: 'us-west-2',
    recipientAccountId: '111122223333',
    eventTime: '2026-09-11T00:00:00.000Z',
    requestParameters: { bucketName: 'runtime-test-bucket' },
  },
};

function dependencies(writeGraph: jest.Mock, receiptHandle: string | null = 'receipt-1') {
  const send = jest.fn(async (command) => {
    if (command instanceof ReceiveMessageCommand) {
      return {
        Messages: [{ Body: JSON.stringify(event), ReceiptHandle: receiptHandle || undefined }],
      };
    }
    if (command instanceof DeleteMessageCommand) return {};
    throw new Error('Unexpected SQS command');
  });
  const organizationsClient = {
    send: jest.fn().mockResolvedValue({
      Accounts: [{ Id: '111122223333', State: 'ACTIVE' }],
    }),
  } as unknown as OrganizationsReader;
  return {
    send,
    options: {
      sqsClient: { send } as unknown as SQSClient,
      organizationsClient,
      writeGraph,
      environment,
    },
  };
}

describe('incremental process batch', () => {
  it('deletes a message only after its graph mutation persists', async () => {
    const writeGraph = jest.fn().mockResolvedValue({ success: true, written: 1 });
    const { send, options } = dependencies(writeGraph);

    await expect(processBatch(options)).resolves.toEqual({ processed: 1, failed: 0 });
    expect(writeGraph).toHaveBeenCalledWith(
      expect.objectContaining({ observedAt: '2026-09-11T00:00:00.000Z' })
    );
    expect(options.organizationsClient.send).not.toHaveBeenCalled();
    expect(send.mock.calls[1][0]).toBeInstanceOf(DeleteMessageCommand);
  });

  it('leaves a failed message for SQS redelivery', async () => {
    const writeGraph = jest.fn().mockRejectedValue(new Error('graph unavailable'));
    const { send, options } = dependencies(writeGraph);

    await expect(processBatch(options)).resolves.toEqual({ processed: 0, failed: 1 });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('rejects messages that cannot be acknowledged', async () => {
    const writeGraph = jest.fn();
    const { send, options } = dependencies(writeGraph, null);

    await expect(processBatch(options)).resolves.toEqual({ processed: 0, failed: 1 });
    expect(writeGraph).not.toHaveBeenCalled();
    expect(send).toHaveBeenCalledTimes(1);
  });
});
