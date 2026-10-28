import {
  instanceObservation,
  loadTrafficObservations,
  MAX_INSTANCE_ENDPOINTS,
} from './observations';

function clientReturning(...responses: unknown[]): any {
  const send = jest.fn();
  for (const response of responses) send.mockResolvedValueOnce(response);
  return { send };
}

describe('loadTrafficObservations', () => {
  it('reads observations for the interfaces in bounded chunks', async () => {
    const ids = Array.from({ length: 150 }, (_, index) => `eni-${index}`);
    const client = clientReturning(
      { Responses: { TrafficObservations: [] } },
      { Responses: { TrafficObservations: [] } }
    );

    await loadTrafficObservations(client, 'TrafficObservations', ids);

    expect(client.send).toHaveBeenCalledTimes(2);
    expect(client.send.mock.calls[0][0].input.RequestItems.TrafficObservations.Keys).toHaveLength(
      100
    );
    expect(client.send.mock.calls[1][0].input.RequestItems.TrafficObservations.Keys).toHaveLength(
      50
    );
  });

  it('maps the returned items and skips duplicates', async () => {
    const client = clientReturning({
      Responses: {
        TrafficObservations: [
          {
            interface_id: { S: 'eni-1' },
            packets: { N: '12' },
            bytes: { N: '4096' },
            last_seen: { S: '2026-10-19T02:00:00Z' },
            endpoints: {
              L: [
                {
                  M: {
                    address: { S: '203.0.113.7' },
                    bytes: { N: '2048' },
                    flows: { N: '2' },
                    last_seen: { S: '2026-10-19T01:30:00Z' },
                  },
                },
                { M: { address: { S: '198.51.100.9' }, bytes: { N: '1' }, flows: { N: '1' } } },
              ],
            },
          },
        ],
      },
    });

    const observations = await loadTrafficObservations(client, 'TrafficObservations', [
      'eni-1',
      'eni-1',
      '',
    ]);

    expect(observations.get('eni-1')).toEqual({
      interfaceId: 'eni-1',
      packets: 12,
      bytes: 4096,
      lastSeen: '2026-10-19T02:00:00Z',
      endpoints: [
        {
          address: '203.0.113.7',
          bytes: 2048,
          flows: 2,
          lastSeen: '2026-10-19T01:30:00Z',
        },
        { address: '198.51.100.9', bytes: 1, flows: 1 },
      ],
    });
  });

  it('treats a malformed endpoint list as no citations', async () => {
    const client = clientReturning({
      Responses: {
        TrafficObservations: [
          {
            interface_id: { S: 'eni-1' },
            packets: { N: '1' },
            bytes: { N: '1' },
            endpoints: { L: [{ M: { flows: { N: '2' } } }, { S: 'junk' }] },
          },
        ],
      },
    });

    const observations = await loadTrafficObservations(client, 'TrafficObservations', ['eni-1']);
    expect(observations.get('eni-1')?.endpoints).toBeUndefined();
  });

  it('caps the lookups per run', async () => {
    const ids = Array.from({ length: 700 }, (_, index) => `eni-${index}`);
    const client = clientReturning(
      ...Array.from({ length: 5 }, () => ({ Responses: { TrafficObservations: [] } }))
    );

    await loadTrafficObservations(client, 'TrafficObservations', ids);

    expect(client.send).toHaveBeenCalledTimes(5);
  });

  it('treats an unreadable table as no observed traffic', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const client = {
      send: jest.fn().mockRejectedValue(new Error('ResourceNotFoundException')),
    } as any;

    const observations = await loadTrafficObservations(client, 'Missing', ['eni-1']);

    warn.mockRestore();
    expect(observations.size).toBe(0);
  });
});

describe('instanceObservation', () => {
  const observations = new Map([
    ['eni-1', { interfaceId: 'eni-1', packets: 1, bytes: 2, lastSeen: '2026-10-19T01:00:00Z' }],
    ['eni-2', { interfaceId: 'eni-2', packets: 1, bytes: 2, lastSeen: '2026-10-19T03:00:00Z' }],
  ]);

  it('is observed when any interface has traffic, with the latest timestamp', () => {
    expect(instanceObservation(['eni-1', 'eni-2'], observations)).toEqual({
      trafficObserved: true,
      lastSeen: '2026-10-19T03:00:00Z',
    });
  });

  it('is undefined without a match, and tolerates missing ids', () => {
    expect(instanceObservation(['eni-9', undefined], observations)).toBeUndefined();
    expect(instanceObservation([], observations)).toBeUndefined();
  });

  it('merges endpoints across interfaces, biggest senders first, capped', () => {
    const withEndpoints = new Map([
      [
        'eni-1',
        {
          interfaceId: 'eni-1',
          packets: 1,
          bytes: 2,
          endpoints: [
            { address: '203.0.113.7', bytes: 1024, flows: 2 },
            { address: '198.51.100.9', bytes: 512, flows: 1 },
          ],
        },
      ],
      [
        'eni-2',
        {
          interfaceId: 'eni-2',
          packets: 1,
          bytes: 2,
          endpoints: [
            { address: '203.0.113.7', bytes: 4096, flows: 8 },
            { address: '192.0.2.10', bytes: 256, flows: 1 },
          ],
        },
      ],
    ]);

    const observation = instanceObservation(['eni-1', 'eni-2'], withEndpoints);

    expect(observation?.endpoints).toEqual([
      { address: '203.0.113.7', bytes: 4096, flows: 8 },
      { address: '198.51.100.9', bytes: 512, flows: 1 },
      { address: '192.0.2.10', bytes: 256, flows: 1 },
    ]);
  });

  it('caps the endpoint citations per instance', () => {
    const many = new Map([
      [
        'eni-1',
        {
          interfaceId: 'eni-1',
          packets: 1,
          bytes: 1,
          endpoints: Array.from({ length: 9 }, (_, index) => ({
            address: `203.0.113.${index}`,
            bytes: 100 - index,
            flows: 1,
          })),
        },
      ],
    ]);

    const observation = instanceObservation(['eni-1'], many);
    expect(observation?.endpoints).toHaveLength(MAX_INSTANCE_ENDPOINTS);
    expect(observation?.endpoints?.[0].address).toBe('203.0.113.0');
  });
});
