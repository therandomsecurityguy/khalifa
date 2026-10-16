import { MacieClassifier } from './macie-classifier';

function macieClient(send: jest.Mock) {
  return { send } as never;
}

describe('MacieClassifier.hasCoverage', () => {
  it('returns true when the bucket is MONITORED', async () => {
    const send = jest.fn().mockResolvedValue({
      buckets: [
        { bucketName: 'monitored-bucket', automatedDiscoveryMonitoringStatus: 'MONITORED' },
      ],
    });
    const classifier = new MacieClassifier();
    (classifier as unknown as { client: unknown }).client = macieClient(send);

    await expect(classifier.hasCoverage('monitored-bucket')).resolves.toBe(true);
    expect(send.mock.calls[0][0].input.criteria).toEqual({
      bucketName: { eq: ['monitored-bucket'] },
    });
  });

  it('returns false when the bucket is NOT_MONITORED', async () => {
    const send = jest.fn().mockResolvedValue({
      buckets: [
        { bucketName: 'unmonitored-bucket', automatedDiscoveryMonitoringStatus: 'NOT_MONITORED' },
      ],
    });
    const classifier = new MacieClassifier();
    (classifier as unknown as { client: unknown }).client = macieClient(send);

    await expect(classifier.hasCoverage('unmonitored-bucket')).resolves.toBe(false);
  });

  it('returns false when the bucket is absent or the API errors', async () => {
    const empty = new MacieClassifier();
    (empty as unknown as { client: unknown }).client = macieClient(
      jest.fn().mockResolvedValue({ buckets: [] })
    );
    await expect(empty.hasCoverage('missing-bucket')).resolves.toBe(false);

    const failing = new MacieClassifier();
    (failing as unknown as { client: unknown }).client = macieClient(
      jest.fn().mockRejectedValue(new Error('AccessDenied'))
    );
    await expect(failing.hasCoverage('denied-bucket')).resolves.toBe(false);
  });
});

describe('MacieClassifier.listBuckets', () => {
  it('pages DescribeBuckets and maps bucket name + account', async () => {
    const send = jest
      .fn()
      .mockResolvedValueOnce({
        buckets: [{ bucketName: 'a', accountId: '111122223333' }],
        nextToken: 'tok',
      })
      .mockResolvedValueOnce({ buckets: [{ bucketName: 'b', accountId: '444455556666' }] });
    const classifier = new MacieClassifier();
    (classifier as unknown as { client: unknown }).client = macieClient(send);

    await expect(classifier.listBuckets()).resolves.toEqual([
      { name: 'a', accountId: '111122223333' },
      { name: 'b', accountId: '444455556666' },
    ]);
    // DescribeBuckets caps maxResults at 50.
    expect(send.mock.calls[0][0].input.maxResults).toBe(50);
    expect(send.mock.calls[1][0].input.nextToken).toBe('tok');
  });
});
