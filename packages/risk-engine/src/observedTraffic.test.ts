import { observedTrafficFromPath, parseObservedEndpoints } from './observedTraffic';
import type { GraphVertex } from './types';

const vertex = (id: string, properties: Record<string, unknown> = {}): GraphVertex =>
  ({ id, label: 'Ec2Instance', properties }) as GraphVertex;

describe('parseObservedEndpoints', () => {
  it('parses a JSON string or array, keeping known fields', () => {
    expect(
      parseObservedEndpoints(
        JSON.stringify([
          { address: '203.0.113.7', bytes: 2048, flows: 3, lastSeen: '2026-10-19T02:00:00Z' },
          { address: '198.51.100.9' },
        ])
      )
    ).toEqual([
      { address: '203.0.113.7', bytes: 2048, flows: 3, lastSeen: '2026-10-19T02:00:00Z' },
      { address: '198.51.100.9' },
    ]);
  });

  it('is empty for junk, oversized lists or entries without an address', () => {
    expect(parseObservedEndpoints('not json')).toEqual([]);
    expect(parseObservedEndpoints(undefined)).toEqual([]);
    expect(parseObservedEndpoints(JSON.stringify([{ bytes: 1 }, { address: '' }]))).toEqual([]);
    expect(
      parseObservedEndpoints(
        Array.from({ length: 9 }, (_, index) => ({ address: `203.0.113.${index}` }))
      )
    ).toHaveLength(5);
  });
});

describe('observedTrafficFromPath', () => {
  it('cites the hop that arrives at an observed vertex', () => {
    const citations = observedTrafficFromPath([
      vertex('internet'),
      vertex('i-1', {
        traffic_observed: true,
        observed_endpoints: JSON.stringify([{ address: '203.0.113.7', bytes: 2048 }]),
      }),
      vertex('bucket'),
    ]);

    expect(citations).toEqual([
      {
        hop: 1,
        vertexId: 'i-1',
        endpoints: [{ address: '203.0.113.7', bytes: 2048 }],
      },
    ]);
  });

  it('cites a hop even without endpoint detail, and ignores the entry vertex', () => {
    const citations = observedTrafficFromPath([
      vertex('internet', { traffic_observed: true }),
      vertex('i-1', { traffic_observed: true }),
    ]);

    expect(citations).toEqual([{ hop: 1, vertexId: 'i-1', endpoints: [] }]);
  });

  it('is empty for paths with no observed traffic', () => {
    expect(observedTrafficFromPath([vertex('internet'), vertex('i-1')])).toEqual([]);
  });
});
