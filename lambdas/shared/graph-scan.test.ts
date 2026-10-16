import { enumerateGraph, type GraphSubmitter } from './graph-scan';

function pagesClient(pages: unknown[][]): {
  client: GraphSubmitter;
  queries: string[];
} {
  const queries: string[] = [];
  const client: GraphSubmitter = {
    submit: jest.fn(async (query: string) => {
      queries.push(query);
      const page = pages.shift() ?? [];
      return { toArray: () => page };
    }),
  };
  return { client, queries };
}

describe('enumerateGraph', () => {
  it('pages with range(low, high) until a short page', async () => {
    const { client, queries } = pagesClient([new Array(2).fill('a'), new Array(1).fill('b')]);

    const items = await enumerateGraph(
      client,
      (start, end) => `g.V().hasLabel('X').range(${start}, ${end})`,
      { label: 'test', pageSize: 2 }
    );

    expect(items).toEqual(['a', 'a', 'b']);
    expect(queries).toEqual(["g.V().hasLabel('X').range(0, 2)", "g.V().hasLabel('X').range(2, 4)"]);
  });

  it('stops at the item cap and warns', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const { client } = pagesClient([new Array(2).fill('x'), new Array(2).fill('y')]);

    const items = await enumerateGraph(client, (start, end) => `range(${start}, ${end})`, {
      label: 'capped',
      pageSize: 2,
      maxItems: 2,
    });

    expect(items).toEqual(['x', 'x']);
    expect(warn).toHaveBeenCalled();
    expect(JSON.parse(warn.mock.calls[0][0] as string)).toMatchObject({
      message: expect.stringContaining('item cap'),
      label: 'capped',
      maxItems: 2,
    });
    warn.mockRestore();
  });

  it('accepts a plain array result set', async () => {
    const client: GraphSubmitter = { submit: jest.fn(async () => ['arn:1']) };
    await expect(enumerateGraph(client, () => 'g.V()', { label: 'array' })).resolves.toEqual([
      'arn:1',
    ]);
  });

  it('validates page and cap sizes', async () => {
    const client: GraphSubmitter = { submit: jest.fn() };
    await expect(
      enumerateGraph(client, () => 'g.V()', { label: 'bad', pageSize: 0 })
    ).rejects.toThrow('pageSize must be a positive integer');
    await expect(
      enumerateGraph(client, () => 'g.V()', { label: 'bad', maxItems: -1 })
    ).rejects.toThrow('maxItems must be a positive integer');
  });
});
