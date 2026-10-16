import { S3Client } from '@aws-sdk/client-s3';
import type { Classifier } from './classifier';
import type { MacieScanner } from './macie-classifier';
import { isKmsError, scanBuckets } from './s3-sampler';

const noopClassifier: Classifier = {
  name: 'noop',
  classify: jest.fn().mockResolvedValue([]),
};

function macieScanner(overrides: Partial<MacieScanner> = {}): MacieScanner {
  return {
    getFindingsForBucket: jest.fn().mockResolvedValue([]),
    hasCoverage: jest.fn().mockResolvedValue(false),
    listBuckets: jest.fn().mockResolvedValue([]),
    ...overrides,
  };
}

describe('isKmsError', () => {
  it('detects KMS error names and messages', () => {
    const kmsNamed = new Error('denied');
    kmsNamed.name = 'KMS.AccessDeniedException';
    expect(isKmsError(kmsNamed)).toBe(true);

    expect(isKmsError(new Error('The ciphertext refers to a customer master key'))).toBe(true);
    expect(isKmsError(new Error('Access to KMS key is denied'))).toBe(true);
  });

  it('does not flag unrelated errors', () => {
    expect(isKmsError(new Error('AccessDenied'))).toBe(false);
    expect(isKmsError(new Error('NoSuchKey'))).toBe(false);
    expect(isKmsError('not an error')).toBe(false);
  });
});

describe('scanBuckets tagged-only gate', () => {
  function client(tags: Record<string, Array<{ Key: string; Value: string }> | undefined>) {
    const send = jest.fn(async (command: { constructor: { name: string }; input: any }) => {
      switch (command.constructor.name) {
        case 'ListBucketsCommand':
          return { Buckets: Object.keys(tags).map((Name) => ({ Name })) };
        case 'GetBucketTaggingCommand': {
          const set = tags[command.input.Bucket];
          if (!set) throw Object.assign(new Error('no tags'), { name: 'NoSuchTagSet' });
          return { TagSet: set };
        }
        case 'ListObjectsV2Command':
          return { Contents: [] };
      }
      throw new Error(`Unexpected command: ${command.constructor.name}`);
    });
    return { send } as unknown as S3Client & { send: jest.Mock };
  }

  it('samples only buckets tagged dspm-scan=true', async () => {
    const s3Client = client({
      'opted-in': [{ Key: 'dspm-scan', Value: 'true' }],
      untagged: undefined,
      'opted-out': [{ Key: 'dspm-scan', Value: 'false' }],
    });

    const results = await scanBuckets(s3Client, [noopClassifier], 'tagged-only');

    expect(results.map((r) => [r.bucketName, r.result !== null])).toEqual([
      ['opted-in', true],
      ['untagged', false],
      ['opted-out', false],
    ]);
    expect(
      s3Client.send.mock.calls.filter(([c]) => c.constructor.name === 'ListObjectsV2Command')
    ).toHaveLength(1);
  });

  it("does not read tags in 'all' mode", async () => {
    const s3Client = client({ any: undefined });

    await scanBuckets(s3Client, [noopClassifier], 'all');

    expect(
      s3Client.send.mock.calls.some(([c]) => c.constructor.name === 'GetBucketTaggingCommand')
    ).toBe(false);
  });
});

describe('scanBuckets KMS skip tracking', () => {
  it('counts KMS-encrypted objects as skippedKms rather than scanned', async () => {
    const s3Client = {
      send: jest.fn(async (command: { constructor: { name: string } }) => {
        if (command.constructor.name === 'ListBucketsCommand') {
          return { Buckets: [{ Name: 'kms-bucket' }] };
        }
        if (command.constructor.name === 'ListObjectsV2Command') {
          return { Contents: [{ Key: 'secret.txt', Size: 10 }] };
        }
        if (command.constructor.name === 'GetObjectCommand') {
          const error = new Error('The ciphertext refers to a customer master key');
          error.name = 'KMS.AccessDeniedException';
          throw error;
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    } as unknown as S3Client;

    const results = await scanBuckets(s3Client, [noopClassifier], 'all');

    expect(results).toHaveLength(1);
    expect(results[0].result).toMatchObject({
      sampleSize: 0,
      skippedKms: 1,
      secretCount: 0,
    });
  });

  it('counts non-KMS read failures as scanned, not skippedKms', async () => {
    const s3Client = {
      send: jest.fn(async (command: { constructor: { name: string } }) => {
        if (command.constructor.name === 'ListBucketsCommand') {
          return { Buckets: [{ Name: 'denied-bucket' }] };
        }
        if (command.constructor.name === 'ListObjectsV2Command') {
          return { Contents: [{ Key: 'secret.txt', Size: 10 }] };
        }
        if (command.constructor.name === 'GetObjectCommand') {
          throw new Error('AccessDenied');
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    } as unknown as S3Client;

    const results = await scanBuckets(s3Client, [noopClassifier], 'all');

    expect(results[0].result).toMatchObject({
      sampleSize: 1,
      skippedKms: 0,
    });
  });
});

describe('scanBucket transfer and budget guardrails', () => {
  it('reads objects with a byte range so transfer is capped at the sample size', async () => {
    const s3Client = {
      send: jest.fn(async (command: { constructor: { name: string } }) => {
        if (command.constructor.name === 'ListBucketsCommand') {
          return { Buckets: [{ Name: 'content-bucket' }] };
        }
        if (command.constructor.name === 'GetObjectCommand') {
          return {
            Body: { transformToString: jest.fn().mockResolvedValue('AKIACI2FM6E2XRLIB2GU') },
          };
        }
        if (command.constructor.name === 'ListObjectsV2Command') {
          return { Contents: [{ Key: 'creds.txt', Size: 500 }] };
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    } as unknown as S3Client;

    const results = await scanBuckets(s3Client, [noopClassifier], 'all');

    expect(results[0].result).toMatchObject({ sampleSize: 1 });
    const send = s3Client.send as unknown as jest.Mock;
    const getObject = send.mock.calls.find(
      ([command]: [{ input: { Range?: string } }]) =>
        command.constructor.name === 'GetObjectCommand'
    );
    expect((getObject![0] as { input: { Range?: string } }).input.Range).toBe('bytes=0-262143');
  });

  it('skips an object whose ContentRange total exceeds the large-object cap', async () => {
    const s3Client = {
      send: jest.fn(async (command: { constructor: { name: string } }) => {
        if (command.constructor.name === 'ListBucketsCommand') {
          return { Buckets: [{ Name: 'big-bucket' }] };
        }
        if (command.constructor.name === 'GetObjectCommand') {
          return {
            Body: { transformToString: jest.fn().mockResolvedValue('partial') },
            ContentRange: 'bytes 0-262143/5000000',
          };
        }
        if (command.constructor.name === 'ListObjectsV2Command') {
          return { Contents: [{ Key: 'big.txt', Size: 262144 }] };
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    } as unknown as S3Client;

    const results = await scanBuckets(s3Client, [noopClassifier], 'all');

    expect(results[0].result).toMatchObject({ sampleSize: 1, skippedKms: 0 });
    expect(results[0].result?.piiTypes).toHaveLength(0);
  });

  it('stops sampling once the classification budget deadline has passed', async () => {
    let getObjectCalls = 0;
    const s3Client = {
      send: jest.fn(async (command: { constructor: { name: string } }) => {
        if (command.constructor.name === 'ListBucketsCommand') {
          return { Buckets: [{ Name: 'budget-bucket' }] };
        }
        if (command.constructor.name === 'GetObjectCommand') {
          getObjectCalls++;
          return { Body: { transformToString: jest.fn().mockResolvedValue('clean text') } };
        }
        if (command.constructor.name === 'ListObjectsV2Command') {
          return {
            Contents: [
              { Key: 'a', Size: 1 },
              { Key: 'b', Size: 1 },
              { Key: 'c', Size: 1 },
            ],
          };
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    } as unknown as S3Client;

    const results = await scanBuckets(s3Client, [noopClassifier], 'all', undefined, {
      deadlineAt: Date.now() - 1,
    });

    expect(getObjectCalls).toBe(0);
    expect(results[0].result).toMatchObject({ sampleSize: 0 });
  });
});

describe('scanBuckets coverage classification', () => {
  function client(
    names: string[],
    tags: Record<string, Array<{ Key: string; Value: string }>> = {}
  ) {
    return {
      send: jest.fn(async (command: { constructor: { name: string }; input: any }) => {
        if (command.constructor.name === 'ListBucketsCommand') {
          return { Buckets: names.map((Name) => ({ Name })) };
        }
        if (command.constructor.name === 'GetBucketTaggingCommand') {
          const set = tags[command.input.Bucket];
          if (!set) throw Object.assign(new Error('no tags'), { name: 'NoSuchTagSet' });
          return { TagSet: set };
        }
        if (command.constructor.name === 'ListObjectsV2Command') return { Contents: [] };
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    } as unknown as S3Client & { send: jest.Mock };
  }

  it('scans an untagged Macie-covered bucket in tagged-only mode without reading objects', async () => {
    const scanner = macieScanner({
      hasCoverage: jest.fn().mockResolvedValue(true),
      getFindingsForBucket: jest
        .fn()
        .mockResolvedValue([{ piiType: 'ssn', count: 1, confidence: 0.95 }]),
    });
    const s3Client = client(['prod-data']);

    const results = await scanBuckets(s3Client, [noopClassifier], 'tagged-only', scanner);

    expect(results[0]).toMatchObject({
      bucketName: 'prod-data',
      engine: 'macie',
      macieCovered: true,
      optedIn: false,
    });
    expect(scanner.getFindingsForBucket).toHaveBeenCalledWith('prod-data');
    expect(
      s3Client.send.mock.calls.some(([c]) => c.constructor.name === 'ListObjectsV2Command')
    ).toBe(false);
  });

  it('classifies a bucket that is neither covered nor tagged as uncovered', async () => {
    const s3Client = client(['orphan']);

    const results = await scanBuckets(s3Client, [noopClassifier], 'tagged-only');

    expect(results[0]).toMatchObject({
      bucketName: 'orphan',
      engine: 'none',
      macieCovered: false,
      optedIn: false,
      result: null,
    });
  });
});

describe('scanBuckets Macie-primary routing', () => {
  it('uses Macie findings only and never downloads objects for covered buckets', async () => {
    const getObject = jest.fn();
    const s3Client = {
      send: jest.fn(async (command: { constructor: { name: string } }) => {
        if (command.constructor.name === 'ListBucketsCommand') {
          return { Buckets: [{ Name: 'macie-bucket' }] };
        }
        if (command.constructor.name === 'GetObjectCommand') {
          getObject();
          return { Body: { transformToString: jest.fn().mockResolvedValue('secret') } };
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    } as unknown as S3Client;

    const scanner = macieScanner({
      hasCoverage: jest.fn().mockResolvedValue(true),
      getFindingsForBucket: jest
        .fn()
        .mockResolvedValue([{ piiType: 'aws_access_key', count: 3, confidence: 0.95 }]),
    });

    const results = await scanBuckets(s3Client, [noopClassifier], 'all', scanner);

    expect(results).toHaveLength(1);
    expect(results[0].result).toMatchObject({
      piiTypes: ['aws_access_key'],
      sampleSize: 0,
      classifier: 'macie',
    });
    expect(scanner.hasCoverage).toHaveBeenCalledWith('macie-bucket');
    // Exactly once: a second check inside scanBucket let a transient
    // DescribeBuckets failure fall through to the regex path.
    expect(scanner.hasCoverage).toHaveBeenCalledTimes(1);
    expect(scanner.getFindingsForBucket).toHaveBeenCalledWith('macie-bucket');
    expect(getObject).not.toHaveBeenCalled();
  });

  it('falls back to the regex sampler for buckets Macie does not cover', async () => {
    const s3Client = {
      send: jest.fn(async (command: { constructor: { name: string } }) => {
        if (command.constructor.name === 'ListBucketsCommand') {
          return { Buckets: [{ Name: 'uncovered-bucket' }] };
        }
        if (command.constructor.name === 'ListObjectsV2Command') {
          return { Contents: [{ Key: 'secret.txt', Size: 10 }] };
        }
        if (command.constructor.name === 'GetObjectCommand') {
          return {
            Body: { transformToString: jest.fn().mockResolvedValue('AKIAIOSFODNN7EXAMPLE') },
          };
        }
        throw new Error(`Unexpected command: ${command.constructor.name}`);
      }),
    } as unknown as S3Client;

    const scanner = macieScanner({ hasCoverage: jest.fn().mockResolvedValue(false) });

    const results = await scanBuckets(s3Client, [noopClassifier], 'all', scanner);

    expect(results[0].result).toMatchObject({
      sampleSize: 1,
      classifier: 'noop',
    });
    expect(scanner.getFindingsForBucket).not.toHaveBeenCalled();
  });
});
