import { appendAll } from './arrays';

describe('appendAll', () => {
  it('appends every item in order', () => {
    expect(appendAll([1], [2, 3])).toEqual([1, 2, 3]);
    expect(appendAll(['a'], new Set(['b']))).toEqual(['a', 'b']);
  });

  it('handles lists far past the argument limit that a spread push overflows', () => {
    const items = Array.from({ length: 1_000_000 }, (_, index) => index);
    const target: number[] = [];
    expect(() => target.push(...items)).toThrow(RangeError);
    expect(appendAll(target, items)).toHaveLength(1_000_000);
    expect(target[999_999]).toBe(999_999);
  });
});
