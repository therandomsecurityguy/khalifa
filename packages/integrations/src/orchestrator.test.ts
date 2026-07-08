import { IssueIntegrationsOrchestrator } from './orchestrator';
import type { IssueLike, RuleLike } from './types';

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

describe('IssueIntegrationsOrchestrator', () => {
  afterEach(() => {
    delete process.env.ISSUE_SINKS;
    delete process.env.ISSUES_TOPIC_ARN;
    delete process.env.SLACK_WEBHOOK_URL;
    delete process.env.SLACK_MIN_SEVERITY;
  });

  test('returns empty refs when no sinks configured', async () => {
    delete process.env.ISSUE_SINKS;
    const orchestrator = new IssueIntegrationsOrchestrator();
    const refs = await orchestrator.emit(sampleIssue, sampleRule);
    expect(refs).toEqual([]);
    expect(orchestrator.configuredSinks).toEqual([]);
  });

  test('loads SNS sink when configured', async () => {
    process.env.ISSUE_SINKS = 'sns';
    process.env.ISSUES_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:khalifa-issues';

    const orchestrator = new IssueIntegrationsOrchestrator();
    expect(orchestrator.configuredSinks).toEqual(['sns']);

    const health = await orchestrator.healthCheck();
    expect(health.sns).toBe(true);
  });

  test('loads Slack sink when configured', async () => {
    process.env.ISSUE_SINKS = 'slack';
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/T000/B000/XXX';

    const orchestrator = new IssueIntegrationsOrchestrator();
    expect(orchestrator.configuredSinks).toEqual(['slack']);

    const health = await orchestrator.healthCheck();
    expect(health.slack).toBe(true);
  });

  test('loads multiple sinks when configured', async () => {
    process.env.ISSUE_SINKS = 'sns,slack';
    process.env.ISSUES_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:khalifa-issues';
    process.env.SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/T000/B000/XXX';

    const orchestrator = new IssueIntegrationsOrchestrator();
    expect(orchestrator.configuredSinks).toHaveLength(2);
    expect(orchestrator.configuredSinks).toContain('sns');
    expect(orchestrator.configuredSinks).toContain('slack');
  });

  test('deduplicates sink names', async () => {
    process.env.ISSUE_SINKS = 'sns,sns,SNS';
    process.env.ISSUES_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:khalifa-issues';

    const orchestrator = new IssueIntegrationsOrchestrator();
    expect(orchestrator.configuredSinks).toHaveLength(1);
  });

  test('ignores unknown sink names', async () => {
    process.env.ISSUE_SINKS = 'sns,unknown-sink';
    process.env.ISSUES_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:khalifa-issues';

    const orchestrator = new IssueIntegrationsOrchestrator();
    expect(orchestrator.configuredSinks).toEqual(['sns']);
  });
});
