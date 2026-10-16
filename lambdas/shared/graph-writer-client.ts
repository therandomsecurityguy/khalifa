import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import type { GraphNode, GraphEdge, GraphReconcile } from './types';
import type { GraphMutationBatch, GraphWriter } from './graph-batch-writer';

// One client per process: constructing a client per invocation drops connection
// reuse across the batches of a single collection run.
let cachedLambdaClient: LambdaClient | null = null;

function getLambdaClient(region: string): LambdaClient {
  cachedLambdaClient ||= new LambdaClient({ region });
  return cachedLambdaClient;
}

interface LambdaInvoker {
  send(command: InvokeCommand): Promise<{
    FunctionError?: string;
    Payload?: Uint8Array;
  }>;
}

const GRAPH_WRITER_MAX_RETRY_DELAY_MS = 30_000;

export interface GraphWriterRetry {
  attempts: number;
  delayMs: number;
  sleep?: (ms: number) => Promise<void>;
}

function isCount(value: number | undefined): boolean {
  return value === undefined || (Number.isSafeInteger(value) && value >= 0);
}

function parseWriteResponse(body: string): Awaited<ReturnType<GraphWriter>> {
  const result = JSON.parse(body) as {
    success?: boolean;
    written?: number;
    skipped?: number;
    tombstoned?: number;
  };
  if (
    result.success !== true ||
    !Number.isSafeInteger(result.written) ||
    result.written! < 0 ||
    !isCount(result.skipped) ||
    !isCount(result.tombstoned)
  ) {
    throw new Error('Graph writer returned an invalid response');
  }
  return {
    success: true,
    written: result.written!,
    skipped: result.skipped || 0,
    tombstoned: result.tombstoned || 0,
  };
}

export function createHttpGraphWriter(
  baseUrl: string,
  timeoutMs: number,
  request: typeof fetch = fetch,
  token = '',
  retry: GraphWriterRetry = { attempts: 1, delayMs: 1_000 }
): GraphWriter {
  const endpoint = new URL('/mutations', `${baseUrl}/`).toString();
  const sleep =
    retry.sleep || ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const post = async (body: string) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await request(endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${token}`,
        },
        body,
        signal: controller.signal,
      });
      return { status: response.status, ok: response.ok, body: await response.text() };
    } finally {
      clearTimeout(timeout);
    }
  };
  return async (mutation) => {
    const body = JSON.stringify(mutation);
    for (let attempt = 1; ; attempt++) {
      const canRetry = attempt < retry.attempts;
      const backoff = () =>
        sleep(Math.min(retry.delayMs * 2 ** (attempt - 1), GRAPH_WRITER_MAX_RETRY_DELAY_MS));
      let response: { status: number; ok: boolean; body: string };
      try {
        response = await post(body);
      } catch (error) {
        // Connection failures and client-side timeouts; the upserts are idempotent.
        if (!canRetry) throw error;
        await backoff();
        continue;
      }
      if (response.ok) return parseWriteResponse(response.body);
      // 503 is the graph-writer's signal for a busy writer or a transient Neptune failure.
      if (response.status !== 503 || !canRetry) {
        throw new Error(`Graph writer returned ${response.status}: ${response.body}`);
      }
      await backoff();
    }
  };
}

export async function invokeGraphWriter(
  mutations: {
    nodes: GraphNode[];
    edges: GraphEdge[];
    observedAt?: string;
    reconcile?: GraphReconcile;
  },
  options: {
    functionName?: string;
    client?: LambdaInvoker;
  } = {}
): Promise<{ success: true; written: number; skipped: number; tombstoned: number }> {
  const functionName = options.functionName || process.env.GRAPH_WRITER_FUNCTION_NAME || '';
  if (!functionName.trim()) {
    throw new Error('GRAPH_WRITER_FUNCTION_NAME is required');
  }

  const client = options.client || getLambdaClient(process.env.AWS_REGION || 'us-east-1');
  const response = await client.send(
    new InvokeCommand({
      FunctionName: functionName,
      InvocationType: 'RequestResponse',
      Payload: Buffer.from(JSON.stringify(mutations)),
    })
  );

  const payload = response.Payload ? Buffer.from(response.Payload).toString('utf8') : '';
  if (response.FunctionError) {
    throw new Error(
      `Graph writer invocation failed: ${response.FunctionError}${payload ? `: ${payload}` : ''}`
    );
  }

  let result: {
    success?: boolean;
    written?: number;
    skipped?: number;
    tombstoned?: number;
  };
  try {
    result = JSON.parse(payload);
  } catch {
    throw new Error('Graph writer returned an invalid response');
  }

  if (result.success !== true || !Number.isSafeInteger(result.written) || result.written! < 0) {
    throw new Error('Graph writer did not confirm persistence');
  }
  if (
    (result.skipped !== undefined && !Number.isSafeInteger(result.skipped)) ||
    (result.tombstoned !== undefined && !Number.isSafeInteger(result.tombstoned))
  ) {
    throw new Error('Graph writer returned an invalid response');
  }

  return {
    success: true,
    written: result.written!,
    skipped: result.skipped || 0,
    tombstoned: result.tombstoned || 0,
  };
}
