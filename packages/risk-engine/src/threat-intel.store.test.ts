import { ThreatIndicatorStore } from './threat-intel';

function clientReturning(...responses: unknown[]): any {
  const send = jest.fn();
  for (const response of responses) send.mockResolvedValueOnce(response);
  return { send };
}

describe('ThreatIndicatorStore', () => {
  it('writes indicators with a TTL from the import time', async () => {
    const client = clientReturning({});
    const store = new ThreatIndicatorStore('ThreatIndicators', client);
    const now = new Date('2026-10-26T00:00:00Z');

    const written = await store.put(
      [{ type: 'ip', value: '203.0.113.7', source: 's3://lists/ips.txt' }],
      90,
      now
    );

    expect(written).toBe(1);
    const item =
      client.send.mock.calls[0][0].input.RequestItems.ThreatIndicators[0].PutRequest.Item;
    expect(item.indicator).toEqual({ S: 'ip#203.0.113.7' });
    expect(item.expires_at).toEqual({
      N: String(Math.floor(now.getTime() / 1000) + 90 * 86_400),
    });
  });

  it('fails when DynamoDB leaves items unprocessed', async () => {
    const client = clientReturning({ UnprocessedItems: { ThreatIndicators: [{}] } });
    const store = new ThreatIndicatorStore('ThreatIndicators', client);
    await expect(
      store.put([{ type: 'account', value: '222233334444', source: 'x' }])
    ).rejects.toThrow('re-run the import');
  });

  it('finds stored indicators among the candidates, bounded and deduped', async () => {
    const client = clientReturning({
      Responses: {
        ThreatIndicators: [
          {
            indicator: { S: 'ip#203.0.113.7' },
            type: { S: 'ip' },
            value: { S: '203.0.113.7' },
            source: { S: 'list' },
          },
        ],
      },
    });
    const store = new ThreatIndicatorStore('ThreatIndicators', client);

    const found = await store.find([
      { type: 'ip', value: '203.0.113.7' },
      { type: 'ip', value: '203.0.113.7' },
      { type: 'account', value: '222233334444' },
    ]);

    expect(found).toEqual([{ type: 'ip', value: '203.0.113.7', source: 'list' }]);
    expect(client.send.mock.calls[0][0].input.RequestItems.ThreatIndicators.Keys).toHaveLength(2);
  });

  it('returns nothing for no candidates without calling DynamoDB', async () => {
    const client = clientReturning({});
    const store = new ThreatIndicatorStore('ThreatIndicators', client);
    await expect(store.find([])).resolves.toEqual([]);
    expect(client.send).not.toHaveBeenCalled();
  });
});
