import { secretAgeProperties } from './secret-ages';

const NOW = new Date('2026-10-22T12:00:00.000Z');
const daysAgo = (days: number) => new Date(NOW.getTime() - days * 86_400_000);

describe('secretAgeProperties', () => {
  it('ages rotation from the last rotation', () => {
    expect(
      secretAgeProperties(
        { CreatedDate: daysAgo(400), LastRotatedDate: daysAgo(10), LastAccessedDate: daysAgo(3) },
        NOW
      )
    ).toEqual({
      created_at: daysAgo(400).toISOString(),
      last_accessed: daysAgo(3).toISOString(),
      days_since_rotation: 10,
      days_since_access: 3,
    });
  });

  it('ages a never-rotated secret from its creation, and leaves access age unset when never read', () => {
    expect(secretAgeProperties({ CreatedDate: daysAgo(120) }, NOW)).toMatchObject({
      days_since_rotation: 120,
      days_since_access: undefined,
      last_accessed: undefined,
    });
  });

  it('ignores a missing or invalid date rather than throwing', () => {
    expect(secretAgeProperties({ CreatedDate: new Date('not a date') }, NOW)).toEqual({
      created_at: undefined,
      last_accessed: undefined,
      days_since_rotation: undefined,
      days_since_access: undefined,
    });
  });
});
