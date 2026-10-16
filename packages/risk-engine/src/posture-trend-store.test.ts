import { PutItemCommand, UpdateItemCommand } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import { PostureTrendStore } from './posture-trend-store';

function storeWithSend() {
  const store = new PostureTrendStore('PostureTrends');
  const send = jest.fn().mockResolvedValue({});
  (store as any).docClient = { send };
  return { store, send };
}

describe('PostureTrendStore.recordMany', () => {
  test('stores each point’s sample on its row', async () => {
    const { store, send } = storeWithSend();

    await store.recordMany([
      {
        metric: 'openIssuesBySeverity',
        value: 3,
        accountIds: [],
        sample: { bySeverity: { critical: 1, high: 2, medium: 0, low: 0 } },
      },
      { metric: 'publicBuckets', value: 1, accountIds: [] },
    ]);

    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0][0]).toBeInstanceOf(PutItemCommand);
    expect(unmarshall(send.mock.calls[0][0].input.Item).sample).toEqual({
      bySeverity: { critical: 1, high: 2, medium: 0, low: 0 },
    });
    expect(unmarshall(send.mock.calls[1][0].input.Item).sample).toEqual({});
  });
});

describe('PostureTrendStore.increment', () => {
  beforeEach(() => {
    jest.useFakeTimers().setSystemTime(new Date('2026-09-29T08:00:00.000Z'));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  test('adds to the day row instead of replacing it', async () => {
    const { store, send } = storeWithSend();

    await store.increment('issuesCreated', 7);

    const command = send.mock.calls[0][0];
    expect(command).toBeInstanceOf(UpdateItemCommand);
    expect(command).not.toBeInstanceOf(PutItemCommand);
    expect(command.input.TableName).toBe('PostureTrends');
    expect(unmarshall(command.input.Key)).toEqual({
      metric: 'issuesCreated',
      date: '2026-09-29',
    });
    expect(command.input.UpdateExpression).toMatch(/^ADD #value :amount /);
    expect(command.input.ExpressionAttributeNames).toEqual({ '#value': 'value' });
    expect(unmarshall(command.input.ExpressionAttributeValues)).toEqual({
      ':amount': 7,
      ':recordedAt': '2026-09-29T08:00:00.000Z',
      ':noAccounts': [],
    });
  });

  test('keeps accountIds on an existing row', async () => {
    const { store, send } = storeWithSend();

    await store.increment('issuesResolved', 0);

    expect(send.mock.calls[0][0].input.UpdateExpression).toContain(
      'accountIds = if_not_exists(accountIds, :noAccounts)'
    );
  });
});

describe('PostureTrendStore.getLatest', () => {
  test('reads the newest row for a metric', async () => {
    const { store, send } = storeWithSend();
    send.mockResolvedValue({
      Items: [
        {
          metric: { S: 'openIssuesBySeverity' },
          date: { S: '2026-10-06' },
          value: { N: '767' },
          recordedAt: { S: '2026-10-06T10:30:00Z' },
        },
      ],
    });

    await expect(store.getLatest('openIssuesBySeverity')).resolves.toMatchObject({
      value: 767,
      recordedAt: '2026-10-06T10:30:00Z',
    });
    expect(send.mock.calls[0][0].input).toMatchObject({ ScanIndexForward: false, Limit: 1 });
  });

  test('returns null when the metric has no rows', async () => {
    const { store, send } = storeWithSend();
    send.mockResolvedValue({ Items: [] });
    await expect(store.getLatest('openIssuesBySeverity')).resolves.toBeNull();
  });
});
