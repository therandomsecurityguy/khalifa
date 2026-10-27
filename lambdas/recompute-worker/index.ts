import { DeleteMessageCommand, ReceiveMessageCommand, SQSClient } from '@aws-sdk/client-sqs';
import { runPolicyEvaluation } from '../policy-evaluator';
import { Logger } from '../shared/types';

// Event-triggered recompute: the incremental collector signals when an IAM
// change could have moved an escalation, and this worker drains that queue by
// re-running the policy evaluator — so a new admin grant or trust produces its
// escalation paths within one incremental cycle instead of at the evaluator's
// scheduled hour. Two bounds keep the heavy job from running constantly: the
// producer's FIFO deduplication id collapses bursts to one message per
// five-minute window, and the worker itself refuses to run more often than
// RECOMPUTE_MIN_INTERVAL_SECONDS (default 900). Messages received inside the
// interval are deleted as covered by the run that just happened; messages
// whose evaluation failed are left for SQS redelivery (and the queue's DLQ).
const logger = new Logger('recompute-worker');
export const DEFAULT_RECOMPUTE_MIN_INTERVAL_SECONDS = 900;
const MAX_MESSAGES = 10;

export interface RecomputeWorkerResult {
  messages: number;
  evaluations: number;
  skipped: number;
}

export function recomputeMinIntervalSeconds(
  environment: NodeJS.ProcessEnv,
  name = 'RECOMPUTE_MIN_INTERVAL_SECONDS'
): number {
  const raw = environment[name] ?? String(DEFAULT_RECOMPUTE_MIN_INTERVAL_SECONDS);
  const parsed =
    typeof raw === 'number' ? raw : /^\d+$/.test(String(raw).trim()) ? Number(raw) : NaN;
  if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > 86_400) {
    throw new Error(`${name} must be an integer between 0 and 86400`);
  }
  return parsed;
}

export interface RecomputeWorkerDependencies {
  sqsClient?: SQSClient;
  evaluate?: typeof runPolicyEvaluation;
  now?: () => Date;
  signal?: AbortSignal;
}

export async function runRecomputeWorker(
  environment: NodeJS.ProcessEnv = process.env,
  dependencies: RecomputeWorkerDependencies = {}
): Promise<RecomputeWorkerResult> {
  const queueUrl = environment.RECOMPUTE_QUEUE_URL?.trim();
  if (!queueUrl) throw new Error('RECOMPUTE_QUEUE_URL is required');
  const minIntervalMs = recomputeMinIntervalSeconds(environment) * 1000;
  const sqsClient =
    dependencies.sqsClient || new SQSClient({ region: environment.AWS_REGION || 'us-east-1' });
  const evaluate = dependencies.evaluate || runPolicyEvaluation;
  const now = dependencies.now || (() => new Date());
  const signal = dependencies.signal;

  const result: RecomputeWorkerResult = { messages: 0, evaluations: 0, skipped: 0 };
  let lastRunAt: number | undefined;

  while (!signal?.aborted) {
    const response = await sqsClient.send(
      new ReceiveMessageCommand({
        QueueUrl: queueUrl,
        MaxNumberOfMessages: MAX_MESSAGES,
        WaitTimeSeconds: 20,
      }),
      signal ? { abortSignal: signal } : undefined
    );
    const messages = response.Messages || [];
    if (messages.length === 0) continue;
    result.messages += messages.length;

    const nowMs = now().getTime();
    let evaluated = true;
    if (lastRunAt !== undefined && nowMs - lastRunAt < minIntervalMs) {
      result.skipped += messages.length;
      logger.info('Recompute skipped inside the minimum interval', {
        nextAllowedInSeconds: Math.ceil((minIntervalMs - (nowMs - lastRunAt)) / 1000),
      });
    } else {
      try {
        await evaluate({}, environment);
        lastRunAt = nowMs;
        result.evaluations += 1;
        logger.info('Event-triggered policy evaluation complete');
      } catch (error) {
        evaluated = false;
        logger.error(
          `Event-triggered policy evaluation failed; leaving messages for redelivery: ${error}`
        );
      }
    }

    if (!evaluated) continue;
    for (const message of messages) {
      if (!message.ReceiptHandle) continue;
      await sqsClient.send(
        new DeleteMessageCommand({ QueueUrl: queueUrl, ReceiptHandle: message.ReceiptHandle })
      );
    }
  }
  return result;
}
