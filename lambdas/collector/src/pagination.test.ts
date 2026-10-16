import { collectPaginated, collectPaginatedBounded } from '../../shared/pagination';

describe('collectPaginatedBounded', () => {
  it('stops at the page bound and reports truncation', async () => {
    const load = jest.fn(async (token?: string) => ({
      values: [token ?? 'first'],
      next: `after-${token ?? 'first'}`,
    }));

    await expect(
      collectPaginatedBounded(
        load,
        (page) => page.values,
        (page) => page.next,
        2
      )
    ).resolves.toEqual({ items: ['first', 'after-first'], truncated: true });
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('reports no truncation when the pages run out first', async () => {
    await expect(
      collectPaginatedBounded(
        async () => ({ values: [1], next: undefined }),
        (page) => page.values,
        (page) => page.next,
        5
      )
    ).resolves.toEqual({ items: [1], truncated: false });
  });
});

describe('collectPaginated', () => {
  it('collects every page', async () => {
    const load = jest.fn(async (token?: string) =>
      token ? { values: [2], next: undefined } : { values: [1], next: 'page-2' }
    );

    await expect(
      collectPaginated(
        load,
        (page) => page.values,
        (page) => page.next
      )
    ).resolves.toEqual([1, 2]);
  });

  it('rejects repeated tokens', async () => {
    await expect(
      collectPaginated(
        async () => ({ values: [], next: 'same' }),
        (page) => page.values,
        (page) => page.next
      )
    ).rejects.toThrow('Pagination returned a repeated token');
  });

  it('enforces a page bound', async () => {
    await expect(
      collectPaginated(
        async (token) => ({ values: [], next: token === undefined ? 'one' : 'two' }),
        (page) => page.values,
        (page) => page.next,
        1
      )
    ).rejects.toThrow('Pagination exceeded 1 pages');
  });
});
