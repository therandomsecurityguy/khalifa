import type { IssueActionSink, IssueLike, RuleLike, ExternalRef, SinkFactory } from '../types';
import { registerSink } from '../types';

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const SEVERITY_EMOJI: Record<string, string> = {
  critical: ':rotating_light:',
  high: ':warning:',
  medium: ':large_orange_diamond:',
  low: ':white_circle:',
};

export class SlackSink implements IssueActionSink {
  readonly system = 'slack';
  private webhookUrl: string;
  private minSeverity: string;

  constructor() {
    this.webhookUrl = process.env.SLACK_WEBHOOK_URL || '';
    this.minSeverity = (process.env.SLACK_MIN_SEVERITY || 'high').toLowerCase();
  }

  async emit(issue: IssueLike, rule: RuleLike): Promise<ExternalRef | null> {
    if (!this.webhookUrl) return null;
    if (SEVERITY_RANK[issue.severity] < SEVERITY_RANK[this.minSeverity]) return null;

    const emoji = SEVERITY_EMOJI[issue.severity] || ':grey_question:';
    const uiUrl = process.env.UI_BASE_URL
      ? `${process.env.UI_BASE_URL}/issues/${issue.id}`
      : undefined;

    const resourceLines = issue.resourcesInvolved
      .slice(0, 5)
      .map((r) => `  • ${r.resourceType}: \`${r.resourceId}\``)
      .join('\n');
    const moreResources =
      issue.resourcesInvolved.length > 5
        ? `\n  • _and ${issue.resourcesInvolved.length - 5} more_`
        : '';

    const linkText = uiUrl ? `<${uiUrl}|View in Khalifa>` : 'Khalifa UI not configured';

    const payload = {
      text: `${emoji} ${issue.severity.toUpperCase()} security issue: ${rule.name}`,
      blocks: [
        {
          type: 'header',
          text: { type: 'plain_text', text: `${emoji} ${rule.name}` },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Severity:* ${issue.severity}` },
            { type: 'mrkdwn', text: `*Risk score:* ${issue.riskScore}` },
            { type: 'mrkdwn', text: `*Rule:* ${issue.ruleId}` },
            { type: 'mrkdwn', text: `*Team:* ${issue.owningTeam}` },
          ],
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Resources:*\n${resourceLines}${moreResources}`,
          },
        },
        {
          type: 'section',
          text: { type: 'mrkdwn', text: `*Remediation:* ${issue.remediationHint}` },
        },
        {
          type: 'context',
          elements: [
            { type: 'mrkdwn', text: linkText },
            { type: 'mrkdwn', text: `Issue ID: \`${issue.id}\`` },
          ],
        },
      ],
    };

    const response = await fetch(this.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`Slack webhook returned ${response.status}: ${await response.text()}`);
    }

    return {
      system: this.system,
      id: issue.id,
      url: uiUrl,
      emittedAt: new Date().toISOString(),
    };
  }

  async healthCheck(): Promise<boolean> {
    return this.webhookUrl.startsWith('https://hooks.slack.com/');
  }
}

export class SlackSinkFactory implements SinkFactory {
  create(): IssueActionSink {
    return new SlackSink();
  }
}

registerSink('slack', new SlackSinkFactory());
