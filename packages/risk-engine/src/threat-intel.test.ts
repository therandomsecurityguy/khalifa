import {
  indicatorKey,
  isValidIndicator,
  parseIndicatorList,
  pathIndicators,
  THREAT_INDICATOR_MAX_LINES,
} from './threat-intel';

describe('isValidIndicator', () => {
  it('accepts IPs of either family and 12-digit accounts', () => {
    expect(isValidIndicator('ip', '203.0.113.7')).toBe(true);
    expect(isValidIndicator('ip', '2001:db8::1')).toBe(true);
    expect(isValidIndicator('account', '111122223333')).toBe(true);
    expect(isValidIndicator('ip', 'not-an-ip')).toBe(false);
    expect(isValidIndicator('ip', '203.0.113.7/24')).toBe(false);
    expect(isValidIndicator('account', '123')).toBe(false);
  });
});

describe('parseIndicatorList', () => {
  it('parses lines, skips comments and blanks, dedupes, and counts invalid', () => {
    const parsed = parseIndicatorList(
      [
        '# our watchlist',
        '203.0.113.7',
        '',
        '203.0.113.7',
        '  198.51.100.9  ',
        '198.51.100.9 # trailing comment',
        'not-an-ip',
      ].join('\n'),
      'ip',
      's3://lists/ips.txt'
    );

    expect(parsed.invalid).toBe(1);
    expect(parsed.truncated).toBe(false);
    expect(parsed.indicators).toEqual([
      { type: 'ip', value: '203.0.113.7', source: 's3://lists/ips.txt' },
      { type: 'ip', value: '198.51.100.9', source: 's3://lists/ips.txt' },
    ]);
  });

  it('caps the list and reports the truncation', () => {
    const lines = Array.from({ length: THREAT_INDICATOR_MAX_LINES + 10 }, (_, index) => {
      const b = index % 256;
      const c = Math.floor(index / 256) % 256;
      return `10.${c}.${b}.1`;
    });
    const parsed = parseIndicatorList(lines.join('\n'), 'ip', 's3://lists/ips.txt');
    expect(parsed.indicators).toHaveLength(THREAT_INDICATOR_MAX_LINES);
    expect(parsed.truncated).toBe(true);
  });
});

describe('pathIndicators', () => {
  it('reads anomaly source IPs and trusted external accounts', () => {
    const candidates = pathIndicators({
      vertices: [
        { label: 'Internet', properties: {} },
        { label: 'CloudTrailAnomaly', properties: { source_ip: '203.0.113.7' } },
        { label: 'ExternalAccount', properties: { account_id: '222233334444' } },
        { label: 'IamRole', properties: { arn: 'arn:aws:iam::111122223333:role/x' } },
      ],
    });
    expect(candidates).toEqual([
      { type: 'ip', value: '203.0.113.7' },
      { type: 'account', value: '222233334444' },
    ]);
  });

  it('ignores malformed or unrelated values', () => {
    expect(
      pathIndicators({
        vertices: [
          { label: 'CloudTrailAnomaly', properties: { source_ip: '-' } },
          { label: 'ExternalAccount', properties: { account_id: 'unknown' } },
        ],
      })
    ).toEqual([]);
  });

  it('keys are stable', () => {
    expect(indicatorKey('ip', '203.0.113.7')).toBe('ip#203.0.113.7');
  });
});

describe('CVE and EPSS indicators', () => {
  it('accepts CVE ids (either case) for known-exploited and EPSS lists', () => {
    expect(isValidIndicator('cve', 'CVE-2024-1234')).toBe(true);
    expect(isValidIndicator('cve', 'cve-2024-12345')).toBe(true);
    expect(isValidIndicator('epss', 'CVE-2021-44228')).toBe(true);
    expect(isValidIndicator('cve', 'RHSA-2024:1234')).toBe(false);
    expect(isValidIndicator('epss', 'CVE-24-1')).toBe(false);
  });

  it('parses EPSS lines as "cve,score" and uppercases ids', () => {
    const parsed = parseIndicatorList(
      [
        'cve-2024-1234,0.97',
        'CVE-2021-44228, 0.5  # a comment',
        'CVE-2020-0001 # no score: unusable',
        'CVE-2019-0001,1.4 # out of range',
        '',
      ].join('\n'),
      'epss',
      's3://lists.example.com/epss.csv'
    );

    expect(parsed.indicators).toEqual([
      {
        type: 'epss',
        value: 'CVE-2024-1234',
        source: 's3://lists.example.com/epss.csv',
        score: 0.97,
      },
      {
        type: 'epss',
        value: 'CVE-2021-44228',
        source: 's3://lists.example.com/epss.csv',
        score: 0.5,
      },
    ]);
    expect(parsed.invalid).toBe(2);
  });

  it('parses a plain known-exploited CVE list', () => {
    const parsed = parseIndicatorList('CVE-2023-1111\nCVE-2023-1111\njunk\n', 'cve', 'kev.txt');
    expect(parsed.indicators).toEqual([{ type: 'cve', value: 'CVE-2023-1111', source: 'kev.txt' }]);
    expect(parsed.invalid).toBe(1);
  });

  it('candidates a vulnerability CVE for both the KEV and EPSS lookups', () => {
    const candidates = pathIndicators({
      vertices: [
        {
          label: 'Vulnerability',
          properties: { cve_id: 'cve-2024-9999' },
        },
      ],
    });
    expect(candidates).toEqual([
      { type: 'cve', value: 'CVE-2024-9999' },
      { type: 'epss', value: 'CVE-2024-9999' },
    ]);
  });
});
