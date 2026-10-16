import { listBucketsFromGraph } from './graph-inventory';
import type { GraphSubmitter } from '../../shared/graph-scan';

function submitter(rows: unknown[]): GraphSubmitter {
  return { submit: jest.fn(async () => ({ toArray: () => rows })) };
}

describe('listBucketsFromGraph', () => {
  it('maps S3Bucket rows to bucket refs with their account', async () => {
    const refs = await listBucketsFromGraph(
      submitter([
        new Map([
          ['name', 'prod-bucket'],
          ['accountId', '111122223333'],
        ]),
        new Map([
          ['name', 'security-bucket'],
          ['accountId', '222233334444'],
        ]),
      ])
    );

    expect(refs).toEqual([
      { name: 'prod-bucket', accountId: '111122223333' },
      { name: 'security-bucket', accountId: '222233334444' },
    ]);
  });

  it('drops rows without a name', async () => {
    const refs = await listBucketsFromGraph(
      submitter([
        new Map([
          ['name', ''],
          ['accountId', '111122223333'],
        ]),
      ])
    );

    expect(refs).toEqual([]);
  });
});
