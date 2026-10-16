import { mapBounded } from './concurrency';

describe('mapBounded', () => {
  it('returns results in input order', async () => {
    const results = await mapBounded([1, 2, 3, 4, 5], 2, async (item) => {
      await new Promise((resolve) => setTimeout(resolve, (6 - item) * 2));
      return item * 10;
    });

    expect(results).toEqual([10, 20, 30, 40, 50]);
  });

  it('never exceeds the configured concurrency', async () => {
    let active = 0;
    let peak = 0;
    await mapBounded(
      Array.from({ length: 20 }, (_, index) => index),
      3,
      async () => {
        active += 1;
        peak = Math.max(peak, active);
        await new Promise((resolve) => setTimeout(resolve, 1));
        active -= 1;
        return null;
      }
    );

    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1);
  });

  it('handles an empty input without scheduling work', async () => {
    const operation = jest.fn();
    await expect(mapBounded([], 4, operation)).resolves.toEqual([]);
    expect(operation).not.toHaveBeenCalled();
  });

  it('fails fast on the first rejection', async () => {
    const operation = jest.fn(async (item: number) => {
      if (item === 2) throw new Error(`boom ${item}`);
      return item;
    });

    await expect(mapBounded([1, 2, 3], 1, operation)).rejects.toThrow('boom 2');
  });

  it('rejects invalid concurrency', async () => {
    await expect(mapBounded([1], 0, async () => null)).rejects.toThrow(
      'Concurrency must be an integer between 1 and 64'
    );
    await expect(mapBounded([1], 65, async () => null)).rejects.toThrow('between 1 and 64');
    await expect(mapBounded([1], 1.5, async () => null)).rejects.toThrow('between 1 and 64');
  });
});
