import { importThreatIntel, parseS3Uri, validateTtlDays } from './index';

const environment = {
  THREAT_INDICATORS_TABLE: 'ThreatIndicators',
  THREAT_INTEL_IP_LIST_S3_URI: 's3://lists.example.com/threat/ips.txt',
  THREAT_INTEL_ACCOUNT_LIST_S3_URI: 's3://lists.example.com/threat/accounts.txt',
};

function s3Returning(texts: Record<string, string>): any {
  return {
    send: jest.fn(async (command: { input: { Bucket: string; Key: string } }) => {
      const key = `${command.input.Bucket}/${command.input.Key}`;
      const text = texts[key];
      if (text === undefined) throw new Error(`NoSuchKey: ${key}`);
      return { Body: { transformToString: async () => text } };
    }),
  };
}

describe('validateTtlDays / parseS3Uri', () => {
  it('validates the TTL bounds', () => {
    expect(validateTtlDays('90')).toBe(90);
    expect(() => validateTtlDays('0')).toThrow(
      'THREAT_INTEL_TTL_DAYS must be an integer between 1 and 365'
    );
    expect(() => validateTtlDays('400')).toThrow('between 1 and 365');
  });

  it('parses s3 URIs and rejects anything else', () => {
    expect(parseS3Uri('s3://bucket/path/ips.txt')).toEqual({
      bucket: 'bucket',
      key: 'path/ips.txt',
    });
    expect(() => parseS3Uri('https://example.com/ips.txt')).toThrow('must be s3://bucket/key');
    expect(() => parseS3Uri('s3://bucket')).toThrow('must be s3://bucket/key');
  });
});

describe('importThreatIntel', () => {
  it('imports each configured list with its own type and records the summary', async () => {
    const s3Client = s3Returning({
      'lists.example.com/threat/ips.txt': ['# watchlist', '203.0.113.7', 'nope'].join('\n'),
      'lists.example.com/threat/accounts.txt': '222233334444\n',
    });
    const put = jest.fn().mockResolvedValue(2);
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);

    const result = await importThreatIntel(
      {},
      {
        s3Client,
        store: { put } as never,
        now: () => new Date('2026-10-26T00:00:00Z'),
      },
      environment
    );

    warn.mockRestore();
    expect(result.written).toBe(4);
    expect(result.lists).toEqual([
      expect.objectContaining({ type: 'ip', indicators: 1, invalid: 1, truncated: false }),
      expect.objectContaining({ type: 'account', indicators: 1, invalid: 0 }),
    ]);
    expect(put).toHaveBeenNthCalledWith(
      1,
      [{ type: 'ip', value: '203.0.113.7', source: 's3://lists.example.com/threat/ips.txt' }],
      90,
      expect.any(Date)
    );
  });

  it('requires at least one list', async () => {
    await expect(importThreatIntel({}, {}, {})).rejects.toThrow(
      'At least one of THREAT_INTEL_IP_LIST_S3_URI, THREAT_INTEL_ACCOUNT_LIST_S3_URI, THREAT_INTEL_CVE_LIST_S3_URI or THREAT_INTEL_EPSS_LIST_S3_URI is required'
    );
  });

  it('fails when a list object is unreadable so the job is retried', async () => {
    const s3Client = s3Returning({});
    await expect(
      importThreatIntel(
        {},
        { s3Client, store: { put: jest.fn() } as never },
        { ...environment, THREAT_INTEL_ACCOUNT_LIST_S3_URI: '' }
      )
    ).rejects.toThrow('NoSuchKey');
  });
});
