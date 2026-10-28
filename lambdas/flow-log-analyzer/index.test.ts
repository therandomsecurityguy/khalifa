import {
  analyzeFlowLogs,
  normalizeAthenaResultsLocation,
  observationItems,
  OBSERVATION_TTL_DAYS,
} from './index';
import type { TrafficEndpoint } from './src/queries';

const environment = {
  ATHENA_DATABASE: 'khalifa_cloudtrail_db',
  ATHENA_WORKGROUP: 'khalifa-cloudtrail-analysis',
  ATHENA_RESULTS_S3_LOCATION: 's3://khalifa-athena-results/results/',
  TRAFFIC_OBSERVATIONS_TABLE: 'TrafficObservations',
};

function athena(
  rows: string[][],
  endpointRows: string[][] = [],
  options: { endpointFails?: boolean } = {}
) {
  const send = jest.fn();
  let started = 0;
  send.mockImplementation(
    async (command: { constructor: { name: string }; input: Record<string, unknown> }) => {
      const name = command.constructor.name;
      if (name === 'StartQueryExecutionCommand') {
        started += 1;
        return { QueryExecutionId: `exec-${started}` };
      }
      if (name === 'GetQueryExecutionCommand') {
        if (options.endpointFails && command.input.QueryExecutionId === 'exec-2') {
          return {
            QueryExecution: { Status: { State: 'FAILED', StateChangeReason: 'endpoint scan' } },
          };
        }
        return { QueryExecution: { Status: { State: 'SUCCEEDED' } } };
      }
      if (command.input.QueryExecutionId === 'exec-2') {
        const headers = [
          'interface_id',
          'account_id',
          'region',
          'srcaddr',
          'packets',
          'bytes',
          'flows',
          'last_seen',
        ];
        return {
          ResultSet: {
            Rows: [
              { Data: headers.map((VarCharValue) => ({ VarCharValue })) },
              ...endpointRows.map((row) => ({
                Data: row.map((VarCharValue) => ({ VarCharValue })),
              })),
            ],
          },
        };
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
    }
  );
  return send;
}

function endpointRow(interfaceId: string, address: string, bytes = '2048') {
  return [
    interfaceId,
    '111122223333',
    'us-west-2',
    address,
    '12',
    bytes,
    '2',
    '2026-10-19T03:00:00Z',
  ];
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

    expect(result).toEqual({
      observations: 2,
      endpoints: 0,
      truncated: false,
      endpointsTruncated: false,
      queryExecutionId: 'exec-1',
      endpointsQueryExecutionId: 'exec-2',
    });
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

describe('endpoint citations', () => {
  it('merges top remote senders into the observation items', async () => {
    const dynamoSend = jest.fn().mockResolvedValue({});
    const result = await analyzeFlowLogs(
      {},
      {
        athenaClient: {
          send: athena(
            [row('eni-1'), row('eni-2')],
            [endpointRow('eni-1', '203.0.113.7'), endpointRow('eni-1', '198.51.100.9', '1024')]
          ),
        } as any,
        dynamoClient: { send: dynamoSend } as any,
        sleep: jest.fn().mockResolvedValue(undefined),
      },
      environment
    );

    expect(result.endpoints).toBe(2);
    expect(result.endpointsTruncated).toBe(false);
    const items = dynamoSend.mock.calls[0][0].input.RequestItems.TrafficObservations;
    expect(items[0].PutRequest.Item.interface_id).toEqual({ S: 'eni-1' });
    expect(items[0].PutRequest.Item.endpoints.L).toEqual([
      {
        M: {
          address: { S: '203.0.113.7' },
          bytes: { N: '2048' },
          flows: { N: '2' },
          last_seen: { S: '2026-10-19T03:00:00Z' },
        },
      },
      {
        M: {
          address: { S: '198.51.100.9' },
          bytes: { N: '1024' },
          flows: { N: '2' },
          last_seen: { S: '2026-10-19T03:00:00Z' },
        },
      },
    ]);
    expect(items[1].PutRequest.Item.endpoints).toBeUndefined();
  });

  it('degrades to observations without citations when the endpoint query fails', async () => {
    const dynamoSend = jest.fn().mockResolvedValue({});
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);

    const result = await analyzeFlowLogs(
      {},
      {
        athenaClient: {
          send: athena([row('eni-1')], [], { endpointFails: true }),
        } as any,
        dynamoClient: { send: dynamoSend } as any,
        sleep: jest.fn().mockResolvedValue(undefined),
      },
      environment
    );

    warn.mockRestore();
    expect(result.observations).toBe(1);
    expect(result.endpoints).toBe(0);
    expect(result.endpointsQueryExecutionId).toBeUndefined();
    const items = dynamoSend.mock.calls[0][0].input.RequestItems.TrafficObservations;
    expect(items[0].PutRequest.Item.endpoints).toBeUndefined();
  });

  it('caps citations per interface even when more rows arrive', () => {
    const endpoints = new Map<string, TrafficEndpoint[]>([
      [
        'eni-1',
        Array.from({ length: 5 }, (_, index) => ({
          accountId: '111122223333',
          region: 'us-west-2',
          interfaceId: 'eni-1',
          remoteAddress: `203.0.113.${index}`,
          packets: 1,
          bytes: 1,
          flows: 1,
          lastSeen: '2026-10-19T03:00:00Z',
        })),
      ],
    ]);
    const items = observationItems(
      [
        {
          accountId: '111122223333',
          region: 'us-west-2',
          interfaceId: 'eni-1',
          packets: 1,
          bytes: 1,
          flows: 1,
          firstSeen: '2026-10-19T01:00:00Z',
          lastSeen: '2026-10-19T02:00:00Z',
        },
      ],
      7,
      new Date('2026-10-19T06:00:00Z'),
      endpoints
    );
    expect((items[0].endpoints as { L: unknown[] }).L).toHaveLength(5);
  });
});
