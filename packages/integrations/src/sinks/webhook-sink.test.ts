import { createHmac } from 'crypto';
import { WebhookSink } from './webhook-sink';
import type { IssueLike, RuleLike } from '../types';

const sendMock = jest.fn();

jest.mock('@aws-sdk/client-secrets-manager', () => {
  return {
    SecretsManagerClient: jest.fn().mockImplementation(() => ({ send: sendMock })),
    GetSecretValueCommand: jest.fn().mockImplementation((input: { SecretId: string }) => input),
  };
});

const sampleIssue: IssueLike = {
  id: 'RULE-001-test',
  ruleId: 'RULE-001',
  resourcesInvolved: [{ resourceId: 'arn:aws:s3:::bucket', resourceType: 'S3Bucket' }],
  pathSummary: [{ from: 'a', to: 'b', edgeType: 'CONTAINS' }],
  riskScore: 85,
  severity: 'critical',
  status: 'open',
  createdAt: '2024-01-01T00:00:00Z',
  updatedAt: '2024-01-01T00:00:00Z',
  owningTeam: 'cloud-security',
  remediationHint: 'Fix it',
  metadata: {},
};

const sampleRule: RuleLike = {
  id: 'RULE-001',
  name: 'Test Rule',
  description: 'test',
  severityHint: 'critical',
  ownerTeam: 'cloud-security',
  enabled: true,
  autoTicketConfig: { enabled: true, projectKey: 'SEC', priority: 'P1' },
};

const SIGNING_SECRET = 'super-secret-signing-key';

describe('WebhookSink', () => {
  const fetchMock = jest.fn();

  beforeEach(() => {
    sendMock.mockReset();
    fetchMock.mockReset();
    jest.spyOn(global, 'fetch').mockImplementation(fetchMock);
    for (const name of [
      'WEBHOOK_URL',
      'WEBHOOK_URL_SECRET_ARN',
      'WEBHOOK_SIGNING_SECRET',
      'WEBHOOK_SIGNING_SECRET_ARN',
      'WEBHOOK_MAX_ATTEMPTS',
      'WEBHOOK_TIMEOUT_MS',
      'UI_BASE_URL',
    ]) {
      delete process.env[name];
    }
  });

  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  test('does nothing without a URL', async () => {
    const sink = new WebhookSink();

    expect(await sink.emit(sampleIssue, sampleRule)).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('refuses to deliver unsigned when the signing secret is missing', async () => {
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    const error = jest.spyOn(console, 'error').mockImplementation(() => undefined);

    const sink = new WebhookSink();

    expect(await sink.emit(sampleIssue, sampleRule)).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledWith(expect.stringContaining('refusing to deliver'));
  });

  test('signs the first delivery as issue.created with verifyable headers', async () => {
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    process.env.UI_BASE_URL = 'https://ui.example.com';
    fetchMock.mockResolvedValue({ ok: true, status: 200 });

    const sink = new WebhookSink();
    const ref = await sink.emit(sampleIssue, sampleRule);

    expect(ref).toMatchObject({ system: 'webhook', id: sampleIssue.id });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://hooks.example.com/khalifa');
    expect(init.method).toBe('POST');
    expect(init.headers).toMatchObject({
      'content-type': 'application/json',
      'x-khalifa-event': 'issue.created',
    });
    expect(init.headers['x-khalifa-delivery']).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
    );
    expect(init.headers['x-khalifa-timestamp']).toMatch(/^\d+$/);

    const expected = createHmac('sha256', SIGNING_SECRET)
      .update(`${init.headers['x-khalifa-timestamp']}.${init.body}`)
      .digest('hex');
    expect(init.headers['x-khalifa-signature']).toBe(`sha256=${expected}`);

    const payload = JSON.parse(init.body);
    expect(payload.event).toBe('issue.created');
    expect(payload.issue).toMatchObject({
      id: 'RULE-001-test',
      severity: 'critical',
      status: 'open',
      riskScore: 85,
    });
    expect(payload.rule).toEqual({ id: 'RULE-001', name: 'Test Rule' });
    expect(payload.url).toBe('https://ui.example.com/issues/RULE-001-test');
  });

  test('marks later deliveries for the same issue as issue.updated', async () => {
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    fetchMock.mockResolvedValue({ ok: true, status: 200 });

    const sink = new WebhookSink();
    await sink.emit(
      {
        ...sampleIssue,
        externalRefs: [
          { system: 'webhook', id: sampleIssue.id, emittedAt: '2024-01-01T00:00:00Z' },
        ],
      },
      sampleRule
    );

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers['x-khalifa-event']).toBe('issue.updated');
    expect(JSON.parse(init.body).event).toBe('issue.updated');
  });

  test('carries an explicit lifecycle event through the header and body', async () => {
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    fetchMock.mockResolvedValue({ ok: true, status: 200 });

    const sink = new WebhookSink();
    await sink.emit({ ...sampleIssue, status: 'suppressed' }, sampleRule, 'issue.suppressed');

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers['x-khalifa-event']).toBe('issue.suppressed');
    const payload = JSON.parse(init.body);
    expect(payload.event).toBe('issue.suppressed');
    expect(payload.issue.status).toBe('suppressed');
  });

  test('derives a lifecycle event from the status when none is given', async () => {
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    fetchMock.mockResolvedValue({ ok: true, status: 200 });

    const sink = new WebhookSink();
    await sink.emit({ ...sampleIssue, status: 'resolved' }, sampleRule);

    const [, init] = fetchMock.mock.calls[0];
    expect(init.headers['x-khalifa-event']).toBe('issue.resolved');
    expect(JSON.parse(init.body).issue.status).toBe('resolved');
  });

  test('retries a 5xx with backoff and succeeds', async () => {
    jest.useFakeTimers();
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 500, text: async () => 'boom' })
      .mockResolvedValueOnce({ ok: true, status: 200 });

    const sink = new WebhookSink();
    const delivery = sink.emit(sampleIssue, sampleRule);
    await jest.advanceTimersByTimeAsync(600);
    const ref = await delivery;

    expect(ref).toMatchObject({ system: 'webhook' });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('does not retry a permanent 4xx and reports the response', async () => {
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    fetchMock.mockResolvedValue({ ok: false, status: 400, text: async () => 'bad payload' });

    const sink = new WebhookSink();

    await expect(sink.emit(sampleIssue, sampleRule)).rejects.toThrow(
      'Webhook returned 400: bad payload'
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  test('gives up after the configured attempts on persistent failures', async () => {
    jest.useFakeTimers();
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    process.env.WEBHOOK_MAX_ATTEMPTS = '2';
    fetchMock.mockResolvedValue({ ok: false, status: 503, text: async () => 'down' });

    const sink = new WebhookSink();
    const delivery = sink.emit(sampleIssue, sampleRule);
    const failure = expect(delivery).rejects.toThrow('Webhook returned 503: down');
    await jest.advanceTimersByTimeAsync(600);
    await failure;

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  test('resolves URL and signing secret from Secrets Manager, memoized', async () => {
    process.env.WEBHOOK_URL_SECRET_ARN =
      'arn:aws:secretsmanager:us-east-1:111122223333:secret:khalifa/webhook-url';
    process.env.WEBHOOK_SIGNING_SECRET_ARN =
      'arn:aws:secretsmanager:us-east-1:111122223333:secret:khalifa/webhook-signing';
    sendMock.mockImplementation(async (input: { SecretId: string }) =>
      input.SecretId.endsWith('webhook-url')
        ? { SecretString: 'https://hooks.example.com/secret-url' }
        : { SecretString: JSON.stringify({ WEBHOOK_SIGNING_SECRET: SIGNING_SECRET }) }
    );
    fetchMock.mockResolvedValue({ ok: true, status: 200 });

    const sink = new WebhookSink();
    await sink.emit(sampleIssue, sampleRule);
    await sink.emit(sampleIssue, sampleRule);

    expect(sendMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][0]).toBe('https://hooks.example.com/secret-url');
    const [, init] = fetchMock.mock.calls[0];
    const expected = createHmac('sha256', SIGNING_SECRET)
      .update(`${init.headers['x-khalifa-timestamp']}.${init.body}`)
      .digest('hex');
    expect(init.headers['x-khalifa-signature']).toBe(`sha256=${expected}`);
  });

  test('validates configuration bounds', () => {
    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    process.env.WEBHOOK_MAX_ATTEMPTS = '0';
    expect(() => new WebhookSink()).toThrow('between 1 and 5');

    process.env.WEBHOOK_MAX_ATTEMPTS = '3';
    process.env.WEBHOOK_TIMEOUT_MS = '999999';
    expect(() => new WebhookSink()).toThrow('between 1000 and 60000');
  });

  test('healthCheck requires a URL and a signing secret', async () => {
    expect(await new WebhookSink().healthCheck()).toBe(false);

    process.env.WEBHOOK_URL = 'https://hooks.example.com/khalifa';
    expect(await new WebhookSink().healthCheck()).toBe(false);

    process.env.WEBHOOK_SIGNING_SECRET = SIGNING_SECRET;
    expect(await new WebhookSink().healthCheck()).toBe(true);

    delete process.env.WEBHOOK_SIGNING_SECRET;
    process.env.WEBHOOK_SIGNING_SECRET_ARN =
      'arn:aws:secretsmanager:us-east-1:111122223333:secret:khalifa/webhook-signing';
    expect(await new WebhookSink().healthCheck()).toBe(true);
  });
});
