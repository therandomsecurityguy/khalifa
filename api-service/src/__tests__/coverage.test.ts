import { coverageFromVertices, graphCoverage } from '../services/coverage';
import type { GraphVertex } from '../types';

const NOW = new Date('2026-10-27T12:00:00Z');

function coverage(completedAt: string, extra: Record<string, unknown> = {}): GraphVertex {
  return {
    id: `coverage/${completedAt}`,
    label: 'CollectionCoverage',
    properties: {
      service: 'resource-inventory',
      status: 'SUCCEEDED',
      completed_at: completedAt,
      ...extra,
    },
  };
}

describe('coverageFromVertices', () => {
  it('grades the newest successful collection', () => {
    expect(coverageFromVertices([coverage('2026-10-27T09:00:00Z')], NOW)).toMatchObject({
      level: 'fresh',
      ageHours: 3,
      latestSuccessAt: '2026-10-27T09:00:00.000Z',
    });
    expect(coverageFromVertices([coverage('2026-10-26T12:00:00Z')], NOW).level).toBe('aging');
    expect(coverageFromVertices([coverage('2026-10-20T12:00:00Z')], NOW).level).toBe('stale');
  });

  it('ignores failed or skipped collections and other services', () => {
    const statement = coverageFromVertices(
      [
        coverage('2026-10-27T11:00:00Z', { status: 'FAILED' }),
        coverage('2026-10-27T11:30:00Z', { service: 'iam' }),
        coverage('2026-10-27T10:00:00Z'),
      ],
      NOW
    );
    expect(statement.ageHours).toBe(2);
  });

  it('is unknown without a successful collection', () => {
    expect(coverageFromVertices([], NOW)).toMatchObject({ level: 'unknown' });
    expect(coverageFromVertices([coverage('not-a-date')], NOW).level).toBe('unknown');
  });
});

describe('graphCoverage', () => {
  it('reads through the client and degrades to unknown on failure', async () => {
    const client = {
      listCollectionCoverage: jest.fn().mockResolvedValue([coverage('2026-10-27T09:00:00Z')]),
    };
    expect((await graphCoverage(client, NOW)).level).toBe('fresh');

    client.listCollectionCoverage.mockRejectedValue(new Error('denied'));
    expect(await graphCoverage(client, NOW)).toMatchObject({ level: 'unknown' });
  });
});
