import { appendAll } from './arrays';

const DEFAULT_MAX_PAGES = 1000;

export async function collectPaginatedBounded<TPage, TItem>(
  load: (token?: string) => Promise<TPage>,
  items: (page: TPage) => readonly TItem[] | undefined,
  nextToken: (page: TPage) => string | undefined,
  maxPages: number
): Promise<{ items: TItem[]; truncated: boolean }> {
  if (!Number.isSafeInteger(maxPages) || maxPages < 1) {
    throw new Error('maxPages must be a positive integer');
  }

  const result: TItem[] = [];
  const seenTokens = new Set<string>();
  let token: string | undefined;
  for (let pageNumber = 0; pageNumber < maxPages; pageNumber += 1) {
    const page = await load(token);
    appendAll(result, items(page) || []);
    token = nextToken(page);
    if (!token) return { items: result, truncated: false };
    if (seenTokens.has(token)) throw new Error('Pagination returned a repeated token');
    seenTokens.add(token);
  }
  return { items: result, truncated: true };
}

export async function collectPaginated<TPage, TItem>(
  load: (token?: string) => Promise<TPage>,
  items: (page: TPage) => readonly TItem[] | undefined,
  nextToken: (page: TPage) => string | undefined,
  maxPages = DEFAULT_MAX_PAGES
): Promise<TItem[]> {
  const page = await collectPaginatedBounded(load, items, nextToken, maxPages);
  if (page.truncated) throw new Error(`Pagination exceeded ${maxPages} pages`);
  return page.items;
}
