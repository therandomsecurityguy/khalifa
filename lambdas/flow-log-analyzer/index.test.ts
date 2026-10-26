import {
  analyzeFlowLogs,
  normalizeAthenaResultsLocation,
  observationItems,
  OBSERVATION_TTL_DAYS,
} from './index';

const environment = {
  ATHENA_DATABASE: 'khalifa_cloudtrail_db',
  ATHENA_WORKGROUP: 'khalifa-cloudtrail-analysis',
  ATHENA_RESULTS_S3_LOCATION: 's3://khalifa-athena-results/results/',
  TRAFFIC_OBSERVATIONS_TABLE: 'TrafficObservations',
};

function athena(rows: string[][]) {
  const send = jest.fn();
  send.mockImplementation(async (command: { constructor: { name: string } }) => {
    if (command.constructor.name === 'StartQueryExecutionCommand') {
      return { QueryExecutionId: 'exec-1' };
    }
    if (command.constructor.name === 'GetQueryExecutionCommand') {
      return { QueryExecution: { Status: { State: 'SUCCEEDED' } } };
    }
    const headers = [
      'account_id',
      'region',
      'interface_id',
      'packets',
      'bytes',
      'flows',
      'first_seen',
      'last_seen',
    ];
    return {
      ResultSet: {
        Rows: [
          { Data: headers.map((VarCharValue) => ({ VarCharValue })) },
          ...rows.map((row) => ({ Data: row.map((VarCharValue) => ({ VarCharValue })) })),
        ],
      },
    };
  });
  return send;
}

function row(interfaceId: string) {
  return [
    '111122223333',
    'us-west-2',
    interfaceId,
    '10',
    '1000',
    '3',
    '2026-10-19T01:00:00Z',
    '2026-10-19T02:00:00Z',
  ];
}

describe('normalizeAthenaResultsLocation', () => {
  it('normalizes and validates the results location', () => {
    expect(normalizeAthenaResultsLocation('s3://bucket/results')).toBe('s3://bucket/results/');
    expect(() => normalizeAthenaResultsLocation(undefined)).toThrow(
      'ATHENA_RESULTS_S3_LOCATION is required'
    );
    expect(() => normalizeAthenaResultsLocation('https://example.com/x')).toThrow(
      'must be a valid s3:// URI'
    );
  });
});

describe('observationItems', () => {
  it('keys by interface and stamps a TTL', () => {
    const observedAt = new Date('2026-10-19T06:00:00Z');
    const [item] = observationItems(
      [
        {
          accountId: '111122223333',
          region: 'us-west-2',
          interfaceId: 'eni-0abc',
          packets: 10,
          bytes: 1000,
          flows: 3,
          firstSeen: '2026-10-19T01:00:00Z',
          lastSeen: '2026-10-19T02:00:00Z',
        },
      ],
      7,
      observedAt
    );
    expect(item.interface_id).toEqual({ S: 'eni-0abc' });
    expect(item.observed_at).toEqual({ S: '2026-10-19T06:00:00.000Z' });
    expect(item.expires_at).toEqual({
      N: String(Math.floor(observedAt.getTime() / 1000) + OBSERVATION_TTL_DAYS * 86_400),
    });
  });
});

describe('analyzeFlowLogs', () => {
  it('queries Athena, parses rows and writes batch puts to DynamoDB', async () => {
    const athenaSend = athena([row('eni-1'), row('eni-2')]);
    const dynamoSend = jest.fn().mockResolvedValue({});

    const result = await analyzeFlowLogs(
      {},
      {
        athenaClient: { send: athenaSend } as any,
        dynamoClient: { send: dynamoSend } as any,
        now: () => new Date('2026-10-19T06:00:00Z'),
        sleep: jest.fn().mockResolvedValue(undefined),
      },
      environment
    );

    expect(result).toEqual({ observations: 2, truncated: false, queryExecutionId: 'exec-1' });
    expect(athenaSend.mock.calls[0][0].input.QueryString).toContain(
      'khalifa_cloudtrail_db.vpc_flow_logs'
    );
    const items = dynamoSend.mock.calls[0][0].input.RequestItems.TrafficObservations;
    expect(items).toHaveLength(2);
    expect(items[0].PutRequest.Item.interface_id).toEqual({ S: 'eni-1' });
  });

  it('retries when DynamoDB leaves items unprocessed', async () => {
    const dynamoSend = jest
      .fn()
      .mockResolvedValueOnce({ UnprocessedItems: { TrafficObservations: [{}] } })
      .mockResolvedValueOnce({});
    const sleep = jest.fn().mockResolvedValue(undefined);

    const result = await analyzeFlowLogs(
      {},
      {
        athenaClient: { send: athena([row('eni-1')]) } as any,
        dynamoClient: { send: dynamoSend } as any,
        sleep,
      },
      environment
    );

    expect(result.observations).toBe(1);
    expect(dynamoSend).toHaveBeenCalledTimes(2);
    expect(sleep).toHaveBeenCalled();
  });

  it('caps the observations and reports the truncation', async () => {
    const rows = Array.from({ length: 5001 }, (_, index) => row(`eni-${index}`));
    const athenaSend = athena(rows);
    const dynamoSend = jest.fn().mockResolvedValue({});
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);

    const result = await analyzeFlowLogs(
      {},
      {
        athenaClient: { send: athenaSend } as any,
        dynamoClient: { send: dynamoSend } as any,
        sleep: jest.fn().mockResolvedValue(undefined),
      },
      environment
    );

    warn.mockRestore();
    expect(result.observations).toBe(5000);
    expect(result.truncated).toBe(true);
  });

  it('fails fast on a missing results location', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    await expect(
      analyzeFlowLogs({}, { sleep: jest.fn().mockResolvedValue(undefined) }, {})
    ).rejects.toThrow('ATHENA_RESULTS_S3_LOCATION is required');
    warn.mockRestore();
  });
});
