import { createHmac, randomUUID } from 'crypto';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import type {
  IssueActionSink,
  IssueLike,
  RuleLike,
  ExternalRef,
  IssueEvent,
  SinkFactory,
} from '../types';
import { registerSink } from '../types';

// Delivery hardening: a bounded number of attempts with growing backoff, and a
// per-attempt timeout. 4xx responses other than 429 are permanent and are not
// retried.
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_TIMEOUT_MS = 10_000;
export const WEBHOOK_BACKOFF_MS = [500, 1_500] as const;
// The payload stays small on purpose: core issue fields, the rule identity,
// and a link back to the UI. The full path, metadata, and evidence live behind
// the link; a receiver that needs them should query the API.
const MAX_RESOURCES = 20;
const MAX_HINT_LENGTH = 500;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function readBoundedInteger(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  if (value === undefined || !value.trim()) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`Webhook configuration must be an integer between ${minimum} and ${maximum}`);
  }
  return parsed;
}

/**
 * POSTs issue events to an operator-configured endpoint, HMAC-signed.
 *
 * Headers: `X-Khalifa-Event` (`issue.created` on the first delivery for an
 * issue, `issue.updated` on later refreshes, `issue.resolved` and
 * `issue.suppressed` on lifecycle transitions), `X-Khalifa-Delivery` (unique
 * per attempt sequence, for receiver-side idempotency),
 * `X-Khalifa-Timestamp` (epoch seconds), and `X-Khalifa-Signature`
 * (`sha256=<hex>`). The signature covers `${timestamp}.${rawBody}`, so
 * receivers should recompute it over the received raw bytes, compare in
 * constant time, and reject timestamps outside their replay window.
 *
 * Configuration (URL: plaintext `WEBHOOK_URL` or the secret behind
 * `WEBHOOK_URL_SECRET_ARN`; key: plaintext `WEBHOOK_SIGNING_SECRET` for local
 * development or the secret behind `WEBHOOK_SIGNING_SECRET_ARN`). Secrets hold
 * the bare value or a JSON record with a `WEBHOOK_URL` /
 * `WEBHOOK_SIGNING_SECRET` field. A configured URL without a signing secret
 * refuses to deliver: unsigned payloads would invite receivers to trust
 * unauthenticated content.
 */
export class WebhookSink implements IssueActionSink {
  readonly system = 'webhook';
  private url: string;
  private urlSecretArn: string;
  private signingSecret: string;
  private signingSecretArn: string;
  private maxAttempts: number;
  private timeoutMs: number;
  private resolvedUrl?: string;
  private resolvedSigningSecret?: string;

  constructor() {
    this.url = process.env.WEBHOOK_URL || '';
    this.urlSecretArn = process.env.WEBHOOK_URL_SECRET_ARN || '';
    this.signingSecret = process.env.WEBHOOK_SIGNING_SECRET || '';
    this.signingSecretArn = process.env.WEBHOOK_SIGNING_SECRET_ARN || '';
    this.maxAttempts = readBoundedInteger(
      process.env.WEBHOOK_MAX_ATTEMPTS,
      DEFAULT_MAX_ATTEMPTS,
      1,
      5
    );
    this.timeoutMs = readBoundedInteger(
      process.env.WEBHOOK_TIMEOUT_MS,
      DEFAULT_TIMEOUT_MS,
      1_000,
      60_000
    );
  }

  private async resolveUrl(): Promise<string> {
    if (!this.urlSecretArn) return this.url;
    if (this.resolvedUrl === undefined) {
      this.resolvedUrl = await this.readSecret(this.urlSecretArn, 'WEBHOOK_URL');
    }
    return this.resolvedUrl;
  }

  private async resolveSigningSecret(): Promise<string> {
    if (!this.signingSecretArn) return this.signingSecret;
    if (this.resolvedSigningSecret === undefined) {
      this.resolvedSigningSecret = await this.readSecret(
        this.signingSecretArn,
        'WEBHOOK_SIGNING_SECRET'
      );
    }
    return this.resolvedSigningSecret;
  }

  /** The secret value is the bare string or a JSON record with the given field. */
  private async readSecret(secretArn: string, field: string): Promise<string> {
    const client = new SecretsManagerClient({
      region: process.env.AWS_REGION || 'us-east-1',
    });
    const response = await client.send(new GetSecretValueCommand({ SecretId: secretArn }));
    const raw = response.SecretString || '';
    try {
      const parsed: unknown = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        const value = (parsed as Record<string, unknown>)[field];
        return typeof value === 'string' ? value : '';
      }
    } catch {
      // Not JSON: treat the secret value as the bare string.
    }
    return raw;
  }

  async emit(issue: IssueLike, rule: RuleLike, event?: IssueEvent): Promise<ExternalRef | null> {
    const url = await this.resolveUrl();
    if (!url) return null;
    const signingSecret = await this.resolveSigningSecret();
    if (!signingSecret) {
      console.error(
        'Webhook sink is configured with a URL but no signing secret; refusing to deliver unsigned payloads'
      );
      return null;
    }

    const priorDelivery = (issue.externalRefs || []).some(
      (ref) => ref.system === this.system && ref.id === issue.id
    );
    // An explicit event always wins; otherwise the status decides (lifecycle
    // transitions) and the stored delivery refs separate created from updated.
    const effectiveEvent =
      event ??
      (issue.status === 'suppressed'
        ? 'issue.suppressed'
        : issue.status === 'resolved'
          ? 'issue.resolved'
          : priorDelivery
            ? 'issue.updated'
            : 'issue.created');
    const uiUrl = process.env.UI_BASE_URL ? `${process.env.UI_BASE_URL}/issues/${issue.id}` : null;

    const body = JSON.stringify({
      event: effectiveEvent,
      deliveredAt: new Date().toISOString(),
      issue: {
        id: issue.id,
        ruleId: issue.ruleId,
        severity: issue.severity,
        status: issue.status,
        riskScore: issue.riskScore,
        owningTeam: issue.owningTeam,
        createdAt: issue.createdAt,
        updatedAt: issue.updatedAt,
        resourcesInvolved: issue.resourcesInvolved.slice(0, MAX_RESOURCES),
        remediationHint: issue.remediationHint.slice(0, MAX_HINT_LENGTH),
      },
      rule: { id: rule.id, name: rule.name },
      url: uiUrl,
    });

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const signature = createHmac('sha256', signingSecret)
      .update(`${timestamp}.${body}`)
      .digest('hex');

    await this.deliver(url, body, {
      'content-type': 'application/json',
      'user-agent': 'khalifa-webhook/1.0',
      'x-khalifa-event': effectiveEvent,
      'x-khalifa-delivery': randomUUID(),
      'x-khalifa-timestamp': timestamp,
      'x-khalifa-signature': `sha256=${signature}`,
    });

    return {
      system: this.system,
      id: issue.id,
      url: uiUrl ?? undefined,
      emittedAt: new Date().toISOString(),
    };
  }

  private async deliver(url: string, body: string, headers: Record<string, string>): Promise<void> {
    let lastError: Error = new Error('Webhook delivery failed');
    for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
      if (attempt > 1) {
        await sleep(WEBHOOK_BACKOFF_MS[Math.min(attempt - 2, WEBHOOK_BACKOFF_MS.length - 1)]);
      }

      let response: Response;
      try {
        response = await fetch(url, {
          method: 'POST',
          headers,
          body,
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (error) {
        // Network failure or timeout: worth another attempt.
        lastError = error instanceof Error ? error : new Error(String(error));
        continue;
      }

      if (response.ok) return;
      const detail = (await response.text().catch(() => '')).slice(0, 200);
      lastError = new Error(`Webhook returned ${response.status}${detail ? `: ${detail}` : ''}`);
      // 4xx (except rate limiting) will not succeed on retry.
      if (response.status !== 429 && response.status < 500) throw lastError;
    }
    throw lastError;
  }

  async healthCheck(): Promise<boolean> {
    const urlConfigured = this.urlSecretArn
      ? /^arn:(aws|aws-cn|aws-us-gov):secretsmanager:/.test(this.urlSecretArn)
      : /^https?:\/\//.test(this.url);
    if (!urlConfigured) return false;
    if (this.signingSecretArn) {
      return /^arn:(aws|aws-cn|aws-us-gov):secretsmanager:/.test(this.signingSecretArn);
    }
    return this.signingSecret.length >= 16;
  }
}

export class WebhookSinkFactory implements SinkFactory {
  create(): IssueActionSink {
    return new WebhookSink();
  }
}

registerSink('webhook', new WebhookSinkFactory());
