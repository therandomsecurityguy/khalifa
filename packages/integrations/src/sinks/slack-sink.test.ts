import { SlackSink } from './slack-sink';
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

describe('SlackSink', () => {
  const fetchMock = jest.fn();

  beforeEach(() => {
    sendMock.mockReset();
    fetchMock.mockReset();
    jest.spyOn(global, 'fetch').mockImplementation(fetchMock);
    delete process.env.SLACK_WEBHOOK_URL;
    delete process.env.SLACK_WEBHOOK_SECRET_ARN;
    delete process.env.SLACK_MIN_SEVERITY;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('resolves the webhook URL from Secrets Manager and memoizes it', async () => {
    process.env.SLACK_WEBHOOK_SECRET_ARN =
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:khalifa/slack-webhook';
    sendMock.mockResolvedValue({
      SecretString: 'https://hooks.slack.com/services/T000/B000/XXX',
    });
    fetchMock.mockResolvedValue({ ok: true });

    const sink = new SlackSink();
    expect(await sink.healthCheck()).toBe(true);

    await sink.emit(sampleIssue, sampleRule);
    await sink.emit(sampleIssue, sampleRule);

    expect(sendMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe('https://hooks.slack.com/services/T000/B000/XXX');
  });

  test('reads a SLACK_WEBHOOK_URL field from a JSON secret value', async () => {
    process.env.SLACK_WEBHOOK_SECRET_ARN =
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:khalifa/slack-webhook';
    sendMock.mockResolvedValue({
      SecretString: JSON.stringify({ SLACK_WEBHOOK_URL: 'https://hooks.slack.com/services/A/B/C' }),
    });
    fetchMock.mockResolvedValue({ ok: true });

    const sink = new SlackSink();
    await sink.emit(sampleIssue, sampleRule);

    expect(fetchMock.mock.calls[0][0]).toBe('https://hooks.slack.com/services/A/B/C');
  });

  test('emits nothing when the secret has no webhook URL', async () => {
    process.env.SLACK_WEBHOOK_SECRET_ARN =
      'arn:aws:secretsmanager:us-east-1:123456789012:secret:khalifa/slack-webhook';
    sendMock.mockResolvedValue({ SecretString: JSON.stringify({}) });

    const sink = new SlackSink();
    expect(await sink.emit(sampleIssue, sampleRule)).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('falls back to the plaintext env var when no secret ARN is set', async () => {
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/T000/B000/XXX';
    fetchMock.mockResolvedValue({ ok: true });

    const sink = new SlackSink();
    expect(await sink.healthCheck()).toBe(true);
    await sink.emit(sampleIssue, sampleRule);

    expect(sendMock).not.toHaveBeenCalled();
    expect(fetchMock.mock.calls[0][0]).toBe('https://hooks.slack.com/services/T000/B000/XXX');
  });

  test('does not emit below the minimum severity', async () => {
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/T000/B000/XXX';
    process.env.SLACK_MIN_SEVERITY = 'high';
    fetchMock.mockResolvedValue({ ok: true });

    const sink = new SlackSink();
    const ref = await sink.emit({ ...sampleIssue, severity: 'medium' }, sampleRule);

    expect(ref).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
