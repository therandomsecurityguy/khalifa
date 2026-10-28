import {
  ACCESS_DENIED_SPIKE_THRESHOLD,
  anomalyAccountId,
  assertAthenaDatabase,
  assertAnomalyQueryDays,
  buildAnomalyNodes,
  buildAnomalyQueries,
  parseAnomalyRow,
  parseCanaryPrincipalArns,
  reconcileAnomalies,
} from './anomalies';

const DATABASE = 'khalifa_cloudtrail_db';

describe('buildAnomalyQueries input guards', () => {
  it.each(['db; DROP TABLE logs', "db'; --", 'db name with spaces', 'db"', 'db`'])(
    'rejects unsafe database identifier %s',
    (database) => {
      expect(() => buildAnomalyQueries(database, 90)).toThrow(
        'ATHENA_DATABASE must be an unquoted Athena identifier'
      );
    }
  );

  it('rejects untrimmed or malformed database identifiers', () => {
    expect(() => assertAthenaDatabase(' padded_db ')).toThrow('unquoted Athena identifier');
    expect(assertAthenaDatabase('khalifa_cloudtrail_db')).toBe('khalifa_cloudtrail_db');
  });

  it.each([0, 366, 1.5, Number.NaN, '90'])('rejects unsafe days value %p', (days) => {
    expect(() => buildAnomalyQueries(DATABASE, days as number)).toThrow(
      'Anomaly query days must be an integer between 1 and 365'
    );
    expect(() => assertAnomalyQueryDays(days as number)).toThrow(
      'Anomaly query days must be an integer between 1 and 365'
    );
  });

  it('interpolates only the validated values into the SQL', () => {
    const queries = buildAnomalyQueries(DATABASE, 30);
    for (const query of queries) {
      expect(query.sql).not.toContain('${');
      expect(query.sql).not.toContain(';');
    }
    // Root usage follows the caller's window; the two baseline queries scan
    // their fixed windows (7 + 30 days) instead.
    expect(queries[0].sql).toContain("interval '30' day");
    expect(queries[1].sql).toContain("interval '37' day");
    expect(queries[2].sql).toContain("interval '37' day");
  });
});

describe('buildAnomalyQueries', () => {
  it('builds the five detection queries with the database and window bound in', () => {
    const queries = buildAnomalyQueries(DATABASE, 90);

    expect(queries.map((q) => q.type)).toEqual([
      'ROOT_USAGE',
      'SECRET_READ_NEW_SOURCE_IP',
      'NEW_API_FOR_PRINCIPAL',
      'UNUSUAL_HOUR_ACTIVITY',
      'ACCESS_DENIED_SPIKE',
    ]);

    for (const query of queries) {
      expect(query.sql).toContain(`${DATABASE}.cloudtrail_logs`);
      expect(query.sql).not.toContain('undefined');
    }

    expect(queries[0].sql).toContain("useridentity.arn LIKE '%:root'");
    expect(queries[0].sql).toContain("interval '90' day");
    expect(queries[0].sql).toContain(
      "log_date >= date_format(current_date - interval '90' day, '%Y/%m/%d')"
    );

    // Secret reads: the DISTINCT source IPs in the baseline window, joined
    // left — an IP absent from the set is a new source for the principal.
    expect(queries[1].sql).toContain("'GetSecretValue', 'BatchGetSecretValue'");
    expect(queries[1].sql).toContain('WITH baseline_ips AS');
    expect(queries[1].sql).toContain('LEFT JOIN baseline_ips');
    expect(queries[1].sql).toContain('WHERE baseline_ips.principal_arn IS NULL');
    expect(queries[1].sql).toContain("interval '7' day");
    expect(queries[1].sql).not.toContain('principal_first_seen');

    // Denied spikes: daily counts for the baseline evaluator, no fixed
    // threshold in SQL.
    expect(queries[4].sql).toContain("errorcode = 'AccessDenied'");
    expect(queries[4].sql).toContain('AS day');
    expect(queries[4].sql).toContain("'%Y-%m-%d'");
    expect(queries[4].sql).not.toContain('HAVING');
    expect(queries[4].sql).not.toContain(`>= ${ACCESS_DENIED_SPIKE_THRESHOLD}`);
  });

  it('parses a detail-bearing row and caps an oversized detail', () => {
    const data = (values: string[]) => values.map((VarCharValue) => ({ VarCharValue }));
    const record = parseAnomalyRow(
      'NEW_API_FOR_PRINCIPAL',
      data([
        'arn:aws:iam::111122223333:user/deploy',
        '203.0.113.9',
        '4',
        '2026-09-10T02:00:00Z',
        '2026-09-10T02:30:00Z',
        'CreateUser, AttachUserPolicy',
      ]),
      2
    );
    expect(record.detail).toBe('CreateUser, AttachUserPolicy');

    const long = parseAnomalyRow(
      'UNUSUAL_HOUR_ACTIVITY',
      data([
        'arn:aws:iam::111122223333:user/deploy',
        '203.0.113.9',
        '4',
        '2026-09-10T02:00:00Z',
        '2026-09-10T02:30:00Z',
        'x'.repeat(500),
      ]),
      3
    );
    expect(long.detail).toHaveLength(200);
    expect(long.detail?.endsWith('…')).toBe(true);
  });

  it('still requires five columns for the older query types', () => {
    const data = (values: string[]) => values.map((VarCharValue) => ({ VarCharValue }));
    expect(() =>
      parseAnomalyRow(
        'ROOT_USAGE',
        data([
          'arn:aws:iam::111122223333:root',
          '203.0.113.50',
          '5',
          '2026-09-09T10:00:00Z',
          '2026-09-10T10:00:00Z',
          'unexpected',
        ]),
        2
      )
    ).toThrow('expected 5 columns');
    expect(() =>
      parseAnomalyRow(
        'NEW_API_FOR_PRINCIPAL',
        data([
          'arn:aws:iam::111122223333:user/deploy',
          '203.0.113.9',
          '4',
          '2026-09-10T02:00:00Z',
          '2026-09-10T02:30:00Z',
        ]),
        2
      )
    ).toThrow('expected 6 columns');
  });

  it('adds a CANARY_USED query only when canary principals are configured', () => {
    const canaryArn = 'arn:aws:iam::111122223333:user/khalifa-canary-1';
    const queries = buildAnomalyQueries(DATABASE, 90, [
      canaryArn,
      'arn:aws:iam::111122223333:user/khalifa-canary-2',
    ]);

    expect(queries).toHaveLength(6);
    expect(queries[5].type).toBe('CANARY_USED');
    expect(queries[5].sql).toContain(
      "useridentity.arn IN ('arn:aws:iam::111122223333:user/khalifa-canary-1', 'arn:aws:iam::111122223333:user/khalifa-canary-2')"
    );
    expect(queries[5].sql).toContain("interval '90' day");
  });

  it('never emits a CANARY_USED query without canary principals', () => {
    expect(buildAnomalyQueries(DATABASE, 90)).toHaveLength(5);
    expect(buildAnomalyQueries(DATABASE, 90, [])).toHaveLength(5);
  });

  it('bounds the behavioural-breadth queries with their own baseline window', () => {
    const queries = buildAnomalyQueries(DATABASE, 90);
    const newApi = queries.find((query) => query.type === 'NEW_API_FOR_PRINCIPAL')!;
    const hour = queries.find((query) => query.type === 'UNUSUAL_HOUR_ACTIVITY')!;

    for (const query of [newApi, hour]) {
      expect(query.sql).toContain('WITH baseline_');
      expect(query.sql).toContain('SELECT DISTINCT');
      expect(query.sql).toContain("interval '7' day");
      expect(query.sql).toContain("interval '37' day");
      expect(query.sql).toContain('LEFT JOIN baseline_');
      expect(query.sql).toContain('WHERE baseline_');
      expect(query.sql).toContain(
        "'elasticloadbalancing.amazonaws.com', 'monitoring.amazonaws.com', 'logs.amazonaws.com'"
      );
    }
    expect(newApi.sql).toContain('AND reads.eventname = baseline_events.eventname');
    expect(hour.sql).toContain('hour(from_iso8601_timestamp(eventtime)) AS activity_hour');
    expect(hour.sql).toContain(
      'array_join(array_agg(DISTINCT CAST(reads.activity_hour AS varchar))'
    );
  });
});

describe('parseCanaryPrincipalArns', () => {
  it('parses a trimmed comma-separated list', () => {
    expect(
      parseCanaryPrincipalArns(
        ' arn:aws:iam::111122223333:user/khalifa-canary-1 , arn:aws:iam::111122223333:user/khalifa-canary-2 '
      )
    ).toEqual([
      'arn:aws:iam::111122223333:user/khalifa-canary-1',
      'arn:aws:iam::111122223333:user/khalifa-canary-2',
    ]);
  });

  it('returns an empty list for empty input', () => {
    expect(parseCanaryPrincipalArns(undefined)).toEqual([]);
    expect(parseCanaryPrincipalArns('')).toEqual([]);
    expect(parseCanaryPrincipalArns('   ')).toEqual([]);
  });

  it.each([
    "arn:aws:iam::111122223333:user/khalifa-canary-1'; DROP TABLE logs",
    'arn:aws:iam::111122223333:role/Admin',
    'arn:aws:iam::111:user/x',
    'not-an-arn',
  ])('rejects invalid canary ARN %s', (arn) => {
    expect(() => parseCanaryPrincipalArns(arn)).toThrow(
      'CANARY_PRINCIPAL_ARNS contains an invalid IAM user ARN'
    );
  });
});

describe('parseAnomalyRow', () => {
  function dataRow(values: string[]) {
    return values.map((VarCharValue) => ({ VarCharValue }));
  }

  it('parses a well-formed row', () => {
    const record = parseAnomalyRow(
      'ROOT_USAGE',
      dataRow([
        'arn:aws:iam::111122223333:root',
        '203.0.113.50',
        '5',
        '2026-09-09T10:00:00Z',
        '2026-09-10T10:00:00Z',
      ]),
      2
    );
    expect(record).toEqual({
      type: 'ROOT_USAGE',
      principalArn: 'arn:aws:iam::111122223333:root',
      sourceIp: '203.0.113.50',
      eventCount: 5,
      firstSeen: '2026-09-09T10:00:00Z',
      lastSeen: '2026-09-10T10:00:00Z',
    });
  });

  it.each([
    ['wrong column count', []],
    [
      'missing principal',
      dataRow(['', '1.2.3.4', '5', '2026-09-09T10:00:00Z', '2026-09-10T10:00:00Z']),
    ],
    [
      'non-numeric count',
      dataRow([
        'arn:aws:iam::111122223333:root',
        '1.2.3.4',
        'x',
        '2026-09-09T10:00:00Z',
        '2026-09-10T10:00:00Z',
      ]),
    ],
    [
      'bad timestamp',
      dataRow([
        'arn:aws:iam::111122223333:root',
        '1.2.3.4',
        '5',
        'not-a-time',
        '2026-09-10T10:00:00Z',
      ]),
    ],
  ])('rejects %s', (_name, data) => {
    expect(() => parseAnomalyRow('ROOT_USAGE', data as never, 2)).toThrow(
      /Invalid Athena anomaly row/
    );
  });
});

describe('anomalyAccountId', () => {
  it('extracts the account from iam and sts principals', () => {
    expect(anomalyAccountId('arn:aws:iam::111122223333:root')).toBe('111122223333');
    expect(anomalyAccountId('arn:aws:sts::999999999999:assumed-role/Admin/session')).toBe(
      '999999999999'
    );
    expect(anomalyAccountId('not-an-arn')).toBe('unknown');
  });
});

describe('buildAnomalyNodes', () => {
  const observedAt = '2026-09-10T12:00:00.000Z';

  it('emits deterministic CloudTrailAnomaly vertices scoped for reconciliation', () => {
    const nodes = buildAnomalyNodes(
      [
        {
          type: 'SECRET_READ_NEW_SOURCE_IP',
          principalArn: 'arn:aws:iam::111122223333:role/Admin',
          sourceIp: '203.0.113.50',
          eventCount: 12,
          firstSeen: '2026-09-10T00:00:00Z',
          lastSeen: '2026-09-10T11:00:00Z',
        },
      ],
      'run-1',
      observedAt
    );

    expect(nodes).toHaveLength(1);
    const node = nodes[0];
    expect(node.label).toBe('CloudTrailAnomaly');
    expect(node.id).toBe(
      'arn:aws:khalifa:anomaly:111122223333:cloudtrail-anomaly/SECRET_READ_NEW_SOURCE_IP/023e46a1d22406ece8db98d1'
    );
    expect(node.observedAt).toBe(observedAt);
    expect(node.properties).toMatchObject({
      anomaly_type: 'SECRET_READ_NEW_SOURCE_IP',
      principal_arn: 'arn:aws:iam::111122223333:role/Admin',
      source_ip: '203.0.113.50',
      event_count: 12,
      collection_scope: 'cloudtrail-anomalies',
      collection_run_id: 'run-1',
      active: true,
    });
  });

  it('produces the same node id for the same identity and different ids for different sources', () => {
    const record = {
      type: 'ROOT_USAGE' as const,
      principalArn: 'arn:aws:iam::111122223333:root',
      sourceIp: '203.0.113.50',
      eventCount: 1,
      firstSeen: '2026-09-09T10:00:00Z',
      lastSeen: '2026-09-10T10:00:00Z',
    };
    const [first] = buildAnomalyNodes([record], 'run-1', observedAt);
    const [again] = buildAnomalyNodes([{ ...record, eventCount: 99 }], 'run-2', observedAt);
    const [other] = buildAnomalyNodes(
      [{ ...record, sourceIp: '198.51.100.7' }],
      'run-1',
      observedAt
    );

    expect(again.id).toBe(first.id);
    expect(other.id).not.toBe(first.id);
  });
});

describe('reconcileAnomalies', () => {
  it('scopes tombstoning to the anomaly collection scope', () => {
    expect(reconcileAnomalies('run-1', '2026-09-10T12:00:00.000Z')).toEqual({
      scope: 'cloudtrail-anomalies',
      runId: 'run-1',
      observedAt: '2026-09-10T12:00:00.000Z',
    });
  });
});
