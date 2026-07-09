import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';
import type { IssueActionSink, IssueLike, RuleLike, ExternalRef, SinkFactory } from '../types';
import { registerSink } from '../types';

export class SnsSink implements IssueActionSink {
  readonly system = 'sns';
  private client: SNSClient;
  private topicArn: string;

  constructor() {
    this.client = new SNSClient({ region: process.env.AWS_REGION || 'us-east-1' });
    this.topicArn = process.env.ISSUES_TOPIC_ARN || '';
  }

  async emit(issue: IssueLike, rule: RuleLike): Promise<ExternalRef | null> {
    if (!this.topicArn) return null;

    const message = JSON.stringify(
      {
        issueId: issue.id,
        ruleId: issue.ruleId,
        ruleName: rule.name,
        severity: issue.severity,
        owningTeam: issue.owningTeam,
        status: issue.status,
        riskScore: issue.riskScore,
        resources: issue.resourcesInvolved.map((r) => ({
          type: r.resourceType,
          id: r.resourceId,
          name: r.resourceName,
        })),
        pathLength: issue.pathSummary.length,
        remediationHint: issue.remediationHint,
        uiUrl: process.env.UI_BASE_URL
          ? `${process.env.UI_BASE_URL}/issues/${issue.id}`
          : undefined,
        emittedAt: new Date().toISOString(),
      },
      null,
      2
    );

    const subject = `[khalifa] ${issue.severity.toUpperCase()} ${rule.name}`;

    await this.client.send(
      new PublishCommand({
        TopicArn: this.topicArn,
        Subject: subject.slice(0, 100),
        Message: message,
        MessageAttributes: {
          severity: { DataType: 'String', StringValue: issue.severity },
          ruleId: { DataType: 'String', StringValue: issue.ruleId },
          issueId: { DataType: 'String', StringValue: issue.id },
        },
      })
    );

    return {
      system: this.system,
      id: issue.id,
      url: this.topicArn,
      emittedAt: new Date().toISOString(),
    };
  }

  async healthCheck(): Promise<boolean> {
    if (!this.topicArn) return false;
    return this.topicArn.startsWith('arn:aws:sns:');
  }
}

export class SnsSinkFactory implements SinkFactory {
  create(): IssueActionSink {
    return new SnsSink();
  }
}

registerSink('sns', new SnsSinkFactory());
