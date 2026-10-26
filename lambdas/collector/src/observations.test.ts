import { instanceObservation, loadTrafficObservations } from './observations';

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
    });
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
});
