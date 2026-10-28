import type { AthenaClient } from '@aws-sdk/client-athena';
import {
  GetQueryExecutionCommand,
  GetQueryResultsCommand,
  StartQueryExecutionCommand,
} from '@aws-sdk/client-athena';
import { BatchWriteItemCommand, type DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { unmarshall } from '@aws-sdk/util-dynamodb';
import {
  analyzeCloudTrail,
  normalizeAthenaResultsLocation,
  validateAnalysisDays,
  validateAthenaDatabase,
} from './index';

const environment = {
  ATHENA_DATABASE: 'cloudtrail_database',
  ATHENA_WORKGROUP: 'cloudtrail_workgroup',
  ATHENA_RESULTS_S3_LOCATION: 's3://results-bucket/cloudtrail',
  ACCESS_ANALYZER_TABLE: 'AccessAnalyzerCache',
  ANALYSIS_DAYS: '90',
};

function row(index: number, count = String(index + 1), used = '2026-09-09T10:00:00Z') {
  const values = [
    `arn:aws:iam::111122223333:role/Role${index}`,
    's3.amazonaws.com',
    `Action${index}`,
    count,
    used,
  ];
  return { Data: values.map((VarCharValue) => ({ VarCharValue })) };
}

const header = {
  Data: ['principal_arn', 'eventsource', 'eventname', 'event_count', 'last_used'].map(
    (VarCharValue) => ({ VarCharValue })
  ),
};

function athena(pages: unknown[], state = 'SUCCEEDED') {
  let page = 0;
  return jest.fn(async (command: unknown) => {
    if (command instanceof StartQueryExecutionCommand) return { QueryExecutionId: 'query-123' };
    if (command instanceof GetQueryExecutionCommand) {
      return { QueryExecution: { Status: { State: state, StateChangeReason: 'query failed' } } };
    }
    if (command instanceof GetQueryResultsCommand) return pages[page++];
    throw new Error('Unexpected Athena command');
  });
}

function dependencies(athenaSend: jest.Mock, dynamoSend: jest.Mock, sleep = jest.fn()) {
  return {
    athenaClient: { send: athenaSend } as unknown as AthenaClient,
    dynamoClient: { send: dynamoSend } as unknown as DynamoDBClient,
    sleep: sleep.mockResolvedValue(undefined),
    now: () => new Date('2026-09-10T12:00:00.000Z'),
  };
}

describe('CloudTrail analyzer', () => {
  it('validates query inputs before calling AWS', async () => {
    expect(normalizeAthenaResultsLocation(' s3://results/prefix ')).toBe('s3://results/prefix/');
    expect(() => normalizeAthenaResultsLocation('https://results/prefix')).toThrow('s3://');
    expect(validateAnalysisDays('30')).toBe(30);
    expect(() => validateAnalysisDays(366)).toThrow('between 1 and 365');
    expect(validateAthenaDatabase('cloudtrail_database')).toBe('cloudtrail_database');

    const athenaSend = jest.fn();
    await expect(
      analyzeCloudTrail({}, dependencies(athenaSend, jest.fn()), {
        ...environment,
        ATHENA_DATABASE: 'db; DROP TABLE logs',
      })
    ).rejects.toThrow('unquoted Athena identifier');
    expect(athenaSend).not.toHaveBeenCalled();
  });

  it('paginates results, skips one header, batches writes, and retries unprocessed items', async () => {
    const rows = Array.from({ length: 26 }, (_, index) => row(index));
    const athenaSend = athena([
      { ResultSet: { Rows: [header, ...rows.slice(0, 25)] }, NextToken: 'next' },
      { ResultSet: { Rows: rows.slice(25) } },
    ]);
    const dynamoSend = jest
      .fn()
      .mockImplementationOnce((command: BatchWriteItemCommand) => ({
        UnprocessedItems: {
          AccessAnalyzerCache: [command.input.RequestItems!.AccessAnalyzerCache![24]],
        },
      }))
      .mockResolvedValue({});
    const sleep = jest.fn();

    await expect(
      analyzeCloudTrail({ days: 30 }, dependencies(athenaSend, dynamoSend, sleep), environment)
    ).resolves.toEqual({ recordsProcessed: 26, queryExecutionId: 'query-123', anomalies: 0 });

    const start = athenaSend.mock.calls[0][0] as StartQueryExecutionCommand;
    expect(start.input.ResultConfiguration?.OutputLocation).toBe('s3://results-bucket/cloudtrail/');
    expect(start.input.QueryString).toContain("interval '30' day");
    expect(start.input.QueryString).toContain(
      "log_date >= date_format(current_date - interval '30' day, '%Y/%m/%d')"
    );
    expect(dynamoSend).toHaveBeenCalledTimes(3);
    expect(
      (dynamoSend.mock.calls[0][0] as BatchWriteItemCommand).input.RequestItems!.AccessAnalyzerCache
    ).toHaveLength(25);
    expect(
      (dynamoSend.mock.calls[1][0] as BatchWriteItemCommand).input.RequestItems!.AccessAnalyzerCache
    ).toHaveLength(1);
    expect(
      unmarshall(
        (dynamoSend.mock.calls[2][0] as BatchWriteItemCommand).input.RequestItems!
          .AccessAnalyzerCache![0].PutRequest!.Item!
      )
    ).toMatchObject({ eventName: 'Action25', eventCount: 26 });
    expect(sleep).toHaveBeenCalledWith(100);
  });

  it('rejects malformed result rows before persistence', async () => {
    const dynamoSend = jest.fn();
    await expect(
      analyzeCloudTrail(
        {},
        dependencies(
          athena([{ ResultSet: { Rows: [header, row(0, 'not-a-number')] } }]),
          dynamoSend
        ),
        environment
      )
    ).rejects.toThrow('event_count must be an integer');
    expect(dynamoSend).not.toHaveBeenCalled();
  });

  it('fails after bounded retries leave unprocessed items', async () => {
    const dynamoSend = jest.fn((command: BatchWriteItemCommand) => ({
      UnprocessedItems: { AccessAnalyzerCache: command.input.RequestItems!.AccessAnalyzerCache },
    }));

    await expect(
      analyzeCloudTrail(
        {},
        dependencies(athena([{ ResultSet: { Rows: [header, row(0)] } }]), dynamoSend),
        environment
      )
    ).rejects.toThrow('exhausted 5 attempts');
    expect(dynamoSend).toHaveBeenCalledTimes(5);
  });

  it('propagates failed Athena queries without persisting', async () => {
    const dynamoSend = jest.fn();
    await expect(
      analyzeCloudTrail({}, dependencies(athena([], 'FAILED'), dynamoSend), environment)
    ).rejects.toThrow('Athena query FAILED: query failed');
    expect(dynamoSend).not.toHaveBeenCalled();
  });

  it('skips anomaly persistence when the graph writer is not configured', async () => {
    const athenaSend = athena([{ ResultSet: { Rows: [header, row(0)] } }]);
    const writeAnomalies = jest.fn();

    const result = await analyzeCloudTrail(
      {},
      { ...dependencies(athenaSend, jest.fn().mockResolvedValue({})), writeAnomalies },
      environment
    );

    expect(result).toEqual({ recordsProcessed: 1, queryExecutionId: 'query-123', anomalies: 0 });
    expect(writeAnomalies).not.toHaveBeenCalled();
  });

  it('writes anomaly nodes to the graph writer with a reconcile tombstone', async () => {
    const usagePage = { ResultSet: { Rows: [header, row(0)] } };
    const anomalyHeader = [
      'principal_arn',
      'source_ip',
      'event_count',
      'first_seen',
      'last_seen',
    ].map((VarCharValue) => ({ VarCharValue }));
    const rootRows = {
      ResultSet: {
        Rows: [
          anomalyHeader,
          {
            Data: [
              'arn:aws:iam::111122223333:root',
              '203.0.113.50',
              '5',
              '2026-09-09T10:00:00Z',
              '2026-09-10T10:00:00Z',
            ].map((VarCharValue) => ({ VarCharValue })),
          },
        ],
      },
    };
    const secretRows = {
      ResultSet: {
        Rows: [
          anomalyHeader,
          {
            Data: [
              'arn:aws:sts::111122223333:assumed-role/AdminRole/session-1',
              '198.51.100.7',
              '12',
              '2026-09-10T00:00:00Z',
              '2026-09-10T11:00:00Z',
            ].map((VarCharValue) => ({ VarCharValue })),
          },
        ],
      },
    };
    const deniedRows = { ResultSet: { Rows: [anomalyHeader] } };
    const detailHeader = [
      'principal_arn',
      'source_ip',
      'event_count',
      'first_seen',
      'last_seen',
      'detail',
    ].map((VarCharValue) => ({ VarCharValue }));
    const newApiRows = {
      ResultSet: {
        Rows: [
          detailHeader,
          {
            Data: [
              'arn:aws:iam::111122223333:user/deploy',
              '203.0.113.9',
              '4',
              '2026-09-10T02:00:00Z',
              '2026-09-10T02:30:00Z',
              'CreateUser, AttachUserPolicy',
            ].map((VarCharValue) => ({ VarCharValue })),
          },
        ],
      },
    };
    const unusualHourRows = {
      ResultSet: {
        Rows: [
          detailHeader,
          {
            Data: [
              'arn:aws:iam::111122223333:user/deploy',
              '203.0.113.9',
              '3',
              '2026-09-10T03:00:00Z',
              '2026-09-10T03:20:00Z',
              '3',
            ].map((VarCharValue) => ({ VarCharValue })),
          },
        ],
      },
    };
    const athenaSend = athena([
      usagePage,
      rootRows,
      secretRows,
      newApiRows,
      unusualHourRows,
      deniedRows,
    ]);
    type AnomalyNode = { id: string; properties: Record<string, unknown> };
    type AnomalyWriteBatch = {
      nodes: AnomalyNode[];
      reconcile?: { scope: string; runId: string; observedAt: string };
      observedAt: string;
    };
    const writeAnomalies = jest.fn(async (batch: AnomalyWriteBatch) => ({
      written: batch.nodes.length,
    }));

    const result = await analyzeCloudTrail(
      {},
      { ...dependencies(athenaSend, jest.fn().mockResolvedValue({})), writeAnomalies },
      { ...environment, GRAPH_WRITER_FUNCTION_NAME: 'graph-writer-fn' }
    );

    expect(result.anomalies).toBe(4);

    const nodeBatches = writeAnomalies.mock.calls
      .map((call) => call[0])
      .filter((batch) => batch.nodes.length > 0);
    expect(nodeBatches).toHaveLength(4);

    const rootNode = nodeBatches[0].nodes[0];
    expect(rootNode.properties.anomaly_type).toBe('ROOT_USAGE');
    expect(rootNode.id).toMatch(
      /^arn:aws:khalifa:anomaly:111122223333:cloudtrail-anomaly\/ROOT_USAGE\/[0-9a-f]{24}$/
    );
    expect(rootNode.properties).toMatchObject({
      principal_arn: 'arn:aws:iam::111122223333:root',
      source_ip: '203.0.113.50',
      event_count: 5,
      collection_scope: 'cloudtrail-anomalies',
    });

    const secretNode = nodeBatches[1].nodes[0];
    expect(secretNode.properties.anomaly_type).toBe('SECRET_READ_NEW_SOURCE_IP');
    expect(secretNode.properties.account_id).toBe('111122223333');

    const newApiNode = nodeBatches[2].nodes[0];
    expect(newApiNode.properties.anomaly_type).toBe('NEW_API_FOR_PRINCIPAL');
    expect(newApiNode.properties.detail).toBe('CreateUser, AttachUserPolicy');

    const unusualHourNode = nodeBatches[3].nodes[0];
    expect(unusualHourNode.properties.anomaly_type).toBe('UNUSUAL_HOUR_ACTIVITY');
    expect(unusualHourNode.properties.detail).toBe('3');

    const reconcileBatch = writeAnomalies.mock.calls
      .map((call) => call[0])
      .find((batch) => batch.reconcile);
    expect(reconcileBatch?.reconcile).toEqual({
      scope: 'cloudtrail-anomalies',
      runId: expect.any(String),
      observedAt: '2026-09-10T12:00:00.000Z',
    });

    const startedQueries = athenaSend.mock.calls.filter(
      ([command]) => command instanceof StartQueryExecutionCommand
    );
    expect(startedQueries).toHaveLength(6);
  });

  it('detects canary credential usage when canary principals are configured', async () => {
    const usagePage = { ResultSet: { Rows: [header, row(0)] } };
    const anomalyHeader = [
      'principal_arn',
      'source_ip',
      'event_count',
      'first_seen',
      'last_seen',
    ].map((VarCharValue) => ({ VarCharValue }));
    const canaryRows = {
      ResultSet: {
        Rows: [
          anomalyHeader,
          {
            Data: [
              'arn:aws:iam::111122223333:user/khalifa-canary-1',
              '198.51.100.99',
              '2',
              '2026-09-10T00:00:00Z',
              '2026-09-10T09:30:00Z',
            ].map((VarCharValue) => ({ VarCharValue })),
          },
        ],
      },
    };
    const emptyRows = { ResultSet: { Rows: [anomalyHeader] } };
    const emptyDetailRows = {
      ResultSet: {
        Rows: [
          ['principal_arn', 'source_ip', 'event_count', 'first_seen', 'last_seen', 'detail'].map(
            (VarCharValue) => ({ VarCharValue })
          ),
        ],
      },
    };
    const athenaSend = athena([
      usagePage,
      emptyRows,
      emptyRows,
      emptyDetailRows,
      emptyDetailRows,
      emptyRows,
      canaryRows,
    ]);
    const writeAnomalies = jest.fn(async (batch: { nodes: unknown[] }) => ({
      written: batch.nodes.length,
    }));

    const result = await analyzeCloudTrail(
      {},
      { ...dependencies(athenaSend, jest.fn().mockResolvedValue({})), writeAnomalies },
      {
        ...environment,
        GRAPH_WRITER_FUNCTION_NAME: 'graph-writer-fn',
        CANARY_PRINCIPAL_ARNS: 'arn:aws:iam::111122223333:user/khalifa-canary-1',
      }
    );

    expect(result.anomalies).toBe(1);

    const nodeBatches = writeAnomalies.mock.calls
      .map((call) => call[0])
      .filter((batch) => batch.nodes.length > 0);
    expect(nodeBatches).toHaveLength(1);

    const canaryNode = nodeBatches[0].nodes[0] as {
      id: string;
      properties: Record<string, unknown>;
    };
    expect(canaryNode.id).toMatch(
      /^arn:aws:khalifa:anomaly:111122223333:cloudtrail-anomaly\/CANARY_USED\/[0-9a-f]{24}$/
    );
    expect(canaryNode.properties).toMatchObject({
      anomaly_type: 'CANARY_USED',
      principal_arn: 'arn:aws:iam::111122223333:user/khalifa-canary-1',
      source_ip: '198.51.100.99',
      event_count: 2,
    });

    const canaryQuery = athenaSend.mock.calls
      .map(([command]) => (command as StartQueryExecutionCommand).input.QueryString || '')
      .find((sql) =>
        sql.includes("useridentity.arn IN ('arn:aws:iam::111122223333:user/khalifa-canary-1')")
      );
    expect(canaryQuery).toBeDefined();
    expect(
      athenaSend.mock.calls.filter(([c]) => c instanceof StartQueryExecutionCommand)
    ).toHaveLength(7);
  });

  it('rejects invalid canary ARNs before starting any queries', async () => {
    const athenaSend = jest.fn();
    await expect(
      analyzeCloudTrail({}, dependencies(athenaSend, jest.fn()), {
        ...environment,
        CANARY_PRINCIPAL_ARNS: "arn:aws:iam::111:user/x'; DROP TABLE logs",
      })
    ).rejects.toThrow('CANARY_PRINCIPAL_ARNS contains an invalid IAM user ARN');
    expect(athenaSend).not.toHaveBeenCalled();
  });
});
