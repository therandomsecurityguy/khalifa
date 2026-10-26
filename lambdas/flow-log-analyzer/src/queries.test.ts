import {
  buildTrafficQuery,
  MAX_OBSERVATION_DAYS,
  parseTrafficRow,
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
