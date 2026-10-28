import {
  buildEndpointQuery,
  buildTrafficQuery,
  ENDPOINTS_PER_INTERFACE,
  MAX_OBSERVATION_DAYS,
  MAX_ENDPOINT_ROWS,
  parseEndpointRow,
  parseTrafficRow,
  validateEndpointsPerInterface,
  validateObservationDays,
} from './queries';

const DATABASE = 'khalifa_cloudtrail_db';

describe('validateObservationDays', () => {
  it('accepts integers in range, including strings from env', () => {
    expect(validateObservationDays(7)).toBe(7);
    expect(validateObservationDays('14')).toBe(14);
    expect(validateObservationDays(MAX_OBSERVATION_DAYS)).toBe(MAX_OBSERVATION_DAYS);
  });

  it.each([0, 32, 1.5, 'x', ''])('rejects %p', (value) => {
    expect(() => validateObservationDays(value)).toThrow(
      `FLOW_LOG_DAYS must be an integer between 1 and ${MAX_OBSERVATION_DAYS}`
    );
  });
});

describe('buildTrafficQuery', () => {
  it('aggregates accepted flows per interface with the window bounded', () => {
    const sql = buildTrafficQuery(DATABASE, 7);

    expect(sql).toContain(`${DATABASE}.vpc_flow_logs`);
    expect(sql).toContain("action = 'ACCEPT'");
    expect(sql).toContain("log_date >= date_format(current_date - interval '7' day, '%Y/%m/%d')");
    expect(sql).toContain("from_unixtime(start) >= current_timestamp - interval '7' day");
    expect(sql).toContain('GROUP BY account_id, region, interface_id');
    expect(sql).toContain("interface_id <> '-'");
    expect(sql).not.toContain('${');
  });

  it('rejects an unsafe database identifier', () => {
    expect(() => buildTrafficQuery('db; DROP TABLE logs', 7)).toThrow(
      'ATHENA_DATABASE must be an unquoted Athena identifier'
    );
  });
});

describe('parseTrafficRow', () => {
  const data = (values: string[]) => values.map((VarCharValue) => ({ VarCharValue }));

  it('parses a well-formed row', () => {
    expect(
      parseTrafficRow(
        data([
          '111122223333',
          'us-west-2',
          'eni-0abc',
          '1200',
          '65536',
          '14',
          '2026-10-19T01:00:00Z',
          '2026-10-19T04:00:00Z',
        ]),
        2
      )
    ).toEqual({
      accountId: '111122223333',
      region: 'us-west-2',
      interfaceId: 'eni-0abc',
      packets: 1200,
      bytes: 65536,
      flows: 14,
      firstSeen: '2026-10-19T01:00:00Z',
      lastSeen: '2026-10-19T04:00:00Z',
    });
  });

  it.each([
    ['short row', data(['111122223333', 'us-west-2', 'eni-0abc'])],
    ['bad account', data(['123', 'us-west-2', 'eni-0abc', '1', '1', '1', 'x', 'x'])],
    [
      'non-numeric packets',
      data(['111122223333', 'us-west-2', 'eni-0abc', 'many', '1', '1', 'x', 'x']),
    ],
    ['empty interface', data(['111122223333', 'us-west-2', '  ', '1', '1', '1', 'x', 'x'])],
    ['bad timestamp', data(['111122223333', 'us-west-2', 'eni-0abc', '1', '1', '1', 'nope', 'x'])],
  ])('rejects %s', (_label, values) => {
    expect(() => parseTrafficRow(values, 3)).toThrow('Invalid Athena traffic row 3');
  });
});

describe('buildEndpointQuery', () => {
  it('ranks accepted remote senders per interface with the window and cap bounded', () => {
    const sql = buildEndpointQuery(DATABASE, 7);

    expect(sql).toContain(`${DATABASE}.vpc_flow_logs`);
    expect(sql).toContain("action = 'ACCEPT'");
    expect(sql).toContain('SUM(bytes)');
    expect(sql).toContain('ROW_NUMBER() OVER (PARTITION BY interface_id ORDER BY SUM(bytes) DESC');
    expect(sql).toContain(`endpoint_rank <= ${ENDPOINTS_PER_INTERFACE}`);
    expect(sql).toContain("log_date >= date_format(current_date - interval '7' day, '%Y/%m/%d')");
    expect(sql).toContain("srcaddr <> '-'");
    expect(sql).toContain('GROUP BY account_id, region, interface_id, srcaddr');
    expect(sql).not.toContain('${');
  });

  it('validates the per-interface cap and database identifier', () => {
    expect(() => validateEndpointsPerInterface(0)).toThrow(
      'ENDPOINTS_PER_INTERFACE must be an integer between 1 and 20'
    );
    expect(() => validateEndpointsPerInterface(21)).toThrow(
      'ENDPOINTS_PER_INTERFACE must be an integer between 1 and 20'
    );
    expect(() => buildEndpointQuery('db; DROP TABLE logs', 7)).toThrow(
      'ATHENA_DATABASE must be an unquoted Athena identifier'
    );
  });
});

describe('parseEndpointRow', () => {
  const data = (values: string[]) => values.map((VarCharValue) => ({ VarCharValue }));

  it('parses a well-formed row', () => {
    expect(
      parseEndpointRow(
        data([
          'eni-0abc',
          '111122223333',
          'us-west-2',
          '203.0.113.7',
          '42',
          '4096',
          '2',
          '2026-10-19T04:00:00Z',
        ]),
        2
      )
    ).toEqual({
      interfaceId: 'eni-0abc',
      accountId: '111122223333',
      region: 'us-west-2',
      remoteAddress: '203.0.113.7',
      packets: 42,
      bytes: 4096,
      flows: 2,
      lastSeen: '2026-10-19T04:00:00Z',
    });
  });

  it.each([
    [['eni-1']],
    [['eni-1', '111122223333', 'us-west-2', 'not-an-ip', '1', '1', '1', '2026-10-19T04:00:00Z']],
    [['eni-1', '123', 'us-west-2', '203.0.113.7', '1', '1', '1', '2026-10-19T04:00:00Z']],
  ])('rejects malformed row %#', (values) => {
    expect(() => parseEndpointRow(data(values as string[]), 3)).toThrow(
      /Invalid Athena endpoint row/
    );
  });

  it('bounds what the analyzer will parse', () => {
    expect(MAX_ENDPOINT_ROWS).toBeGreaterThan(MAX_OBSERVATION_DAYS);
  });
});
