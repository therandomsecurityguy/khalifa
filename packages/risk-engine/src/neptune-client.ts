import { defaultProvider } from '@aws-sdk/credential-provider-node';
import { Sha256 } from '@smithy/core/checksum';
import { HttpRequest } from '@smithy/core/protocols';
import { SignatureV4 } from '@smithy/signature-v4';
import Gremlin from 'gremlin';

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_MAX_RESULTS = 10_000;

// Neptune Serverless raises MemoryLimitExceededException /
// ConcurrentModificationException sporadically while it scales, and the
// identical query succeeds once the transition settles. Ride that out with
// more attempts and a longer, capped backoff than the connection-level retries
// use — a short 100/200ms budget was not enough and failed whole assessments.
const SERVERLESS_TRANSIENT_ATTEMPTS = 5;
const SERVERLESS_TRANSIENT_BASE_MS = 500;
const SERVERLESS_TRANSIENT_MAX_MS = 5_000;

interface GremlinClient {
  readonly isOpen: boolean;
  open(): Promise<void>;
  close(): Promise<void>;
  submit(
    query: string | Gremlin.process.Bytecode,
    bindings?: Record<string, unknown>,
    options?: Partial<Gremlin.driver.RequestOptions>
  ): Promise<unknown>;
}

export interface NeptuneEndpoint {
  hostname: string;
  port: number;
  url: string;
}

export interface NeptuneQueryClient {
  connect(): Promise<void>;
  close(): Promise<void>;
  executeQuery(query: string): Promise<any[]>;
}

export interface NeptuneRuntimeConfig {
  endpoint: string;
  region?: string;
  timeoutMs?: number;
  maxAttempts?: number;
  maxResults?: number;
}

export interface NeptuneQueryOptions {
  timeoutMs?: number;
  maxAttempts?: number;
  /** Per-call override of the result guard (see `submit`). */
  maxResults?: number;
}

export interface NeptuneRuntimeDependencies {
  createClient?: (url: string, headers: Record<string, string>) => GremlinClient;
  createHeaders?: (endpoint: NeptuneEndpoint, region: string) => Promise<Record<string, string>>;
  sleep?: (ms: number) => Promise<void>;
}

export class NeptuneRuntimeClient implements NeptuneQueryClient {
  private client: GremlinClient | null = null;
  private connecting: Promise<GremlinClient> | null = null;
  private generation = 0;
  private readonly timeoutMs: number;
  private readonly maxAttempts: number;
  private readonly maxResults: number;
  private readonly endpoint: string;
  private readonly region: string;
  private readonly createClient: (url: string, headers: Record<string, string>) => GremlinClient;
  private readonly createHeaders: (
    endpoint: NeptuneEndpoint,
    region: string
  ) => Promise<Record<string, string>>;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(config: NeptuneRuntimeConfig, dependencies: NeptuneRuntimeDependencies = {}) {
    this.timeoutMs = positiveInteger(config.timeoutMs, DEFAULT_TIMEOUT_MS, 'timeoutMs');
    this.maxAttempts = positiveInteger(config.maxAttempts, DEFAULT_MAX_ATTEMPTS, 'maxAttempts');
    this.maxResults = positiveInteger(config.maxResults, DEFAULT_MAX_RESULTS, 'maxResults');
    this.endpoint = config.endpoint;
    this.region = config.region || process.env.AWS_REGION || 'us-east-1';
    this.createHeaders = dependencies.createHeaders || createSigV4Headers;
    this.createClient =
      dependencies.createClient ||
      ((url, headers) =>
        new Gremlin.driver.Client(url, {
          traversalSource: 'g',
          headers,
          messageMaxChunkSize: 65_536,
        }) as GremlinClient);
    this.sleep = dependencies.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  async connect(): Promise<void> {
    try {
      await withTimeout(this.getClient(), this.timeoutMs, 'Neptune connection');
    } catch (error) {
      await this.resetClient(error);
      throw error;
    }
  }

  async close(): Promise<void> {
    this.generation++;
    const client = this.client;
    this.client = null;
    this.connecting = null;
    if (client) await withTimeout(client.close(), this.timeoutMs, 'Neptune connection close');
  }

  async executeQuery(query: string): Promise<any[]> {
    if (!query.trim()) throw new Error('Gremlin query is required');
    const normalized = query.trim().replace(/;$/, '');
    const bounded = /\.count\(\s*\)$/.test(normalized)
      ? normalized
      : `${normalized}.limit(${this.maxResults + 1})`;
    return this.execute(bounded, { maxResults: this.maxResults });
  }

  /**
   * Submits a query without the default result guard.
   *
   * The guard exists to stop an unbounded read from allocating without limit,
   * but the CIEM lambdas deliberately page with range() and cap the total
   * themselves (enumerateGraph), so a legitimate page can exceed maxResults
   * and would be rejected or truncated by executeQuery. Callers of this method
   * are responsible for bounding their own result set.
   *
   * `NeptuneQueryClient` has no bindings: Amazon Neptune rejects Gremlin script
   * bindings ("Bindings in Gremlin are not supported"), so callers submit
   * either a fully-formed script or a Bytecode traversal, never parameters.
   */
  async submit(query: string | Gremlin.process.Bytecode): Promise<any[]> {
    return this.execute(query, { maxResults: Number.MAX_SAFE_INTEGER });
  }

  async execute(
    query: string | Gremlin.process.Bytecode,
    options: NeptuneQueryOptions = {}
  ): Promise<any[]> {
    const timeoutMs = options.timeoutMs ?? this.timeoutMs;
    const maxAttempts = options.maxAttempts ?? this.maxAttempts;
    const maxResults = options.maxResults ?? this.maxResults;
    for (let attempt = 1; ; attempt += 1) {
      try {
        const client = await withTimeout(this.getClient(), timeoutMs, 'Neptune connection');
        const result = unwrapTraversers(
          toArray(
            await withTimeout(
              client.submit(query, undefined, { evaluationTimeout: timeoutMs }),
              timeoutMs,
              'Neptune query'
            )
          ),
          maxResults
        );
        if (result.length > maxResults) {
          throw new Error(`Neptune query exceeded the configured result limit of ${maxResults}`);
        }
        return result;
      } catch (error) {
        const transient = isNeptuneServerlessTransient(error);
        const retryable = transient || isNeptuneRetryable(error);
        if (!retryable) throw error;
        // Always drop the connection first: a stalled query (timeout) leaves a
        // hung socket that must be closed even when this is the last attempt.
        await this.resetClient(error);
        const limit = transient
          ? Math.max(maxAttempts, SERVERLESS_TRANSIENT_ATTEMPTS)
          : maxAttempts;
        if (attempt >= limit) throw error;
        await this.sleep(
          transient
            ? Math.min(
                SERVERLESS_TRANSIENT_BASE_MS * 2 ** (attempt - 1),
                SERVERLESS_TRANSIENT_MAX_MS
              )
            : 100 * 2 ** (attempt - 1)
        );
      }
    }
    throw new Error('Neptune query failed without an error');
  }

  private async getClient(): Promise<GremlinClient> {
    if (this.client?.isOpen) return this.client;
    if (this.connecting) return this.connecting;

    const generation = this.generation;
    const connecting = (async () => {
      const endpoint = normalizeNeptuneEndpoint(this.endpoint);
      const headers = await this.createHeaders(endpoint, this.region);
      if (generation !== this.generation) throw new Error('Neptune connection closed');
      const client = this.createClient(endpoint.url, headers);
      this.client = client;
      try {
        await client.open();
        if (generation !== this.generation) {
          throw new Error('Neptune connection closed');
        }
      } catch (error) {
        if (this.client === client) this.client = null;
        await client
          .close()
          .catch((closeError) =>
            console.error('Failed to close rejected Neptune connection', { closeError, error })
          );
        throw error;
      }
      return client;
    })();
    this.connecting = connecting;
    try {
      return await connecting;
    } finally {
      if (this.connecting === connecting) this.connecting = null;
    }
  }

  private async resetClient(originalError: unknown): Promise<void> {
    this.generation++;
    const client = this.client;
    this.client = null;
    this.connecting = null;
    if (!client) return;
    try {
      await withTimeout(client.close(), this.timeoutMs, 'Neptune connection close');
    } catch (error) {
      console.error('Failed to reset Neptune connection', { error, originalError });
    }
  }
}

export function createNeptuneRuntimeClient(endpoint: string): NeptuneRuntimeClient {
  return new NeptuneRuntimeClient({
    endpoint,
    region: process.env.AWS_REGION,
    timeoutMs: envInteger('NEPTUNE_QUERY_TIMEOUT_MS', DEFAULT_TIMEOUT_MS),
    maxAttempts: envInteger('NEPTUNE_MAX_ATTEMPTS', DEFAULT_MAX_ATTEMPTS),
    maxResults: envInteger('NEPTUNE_MAX_RESULTS', DEFAULT_MAX_RESULTS),
  });
}

export function normalizeNeptuneEndpoint(value: string): NeptuneEndpoint {
  const input = value.trim();
  if (!input) throw new Error('NEPTUNE_ENDPOINT is required');
  const parsed = new URL(input.includes('://') ? input : `wss://${input}`);
  if (!['wss:', 'https:'].includes(parsed.protocol)) {
    throw new Error('NEPTUNE_ENDPOINT must use wss or https');
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(
      'NEPTUNE_ENDPOINT must not contain credentials, query parameters, or fragments'
    );
  }
  if (parsed.pathname !== '/' && parsed.pathname !== '/gremlin') {
    throw new Error('NEPTUNE_ENDPOINT path must be /gremlin');
  }
  const port = parsed.port ? Number(parsed.port) : 8182;
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error('Invalid Neptune port');
  return {
    hostname: parsed.hostname,
    port,
    url: `wss://${parsed.hostname}:${port}/gremlin`,
  };
}

export async function createSigV4Headers(
  endpoint: NeptuneEndpoint,
  region: string,
  credentials: ReturnType<typeof defaultProvider> = defaultProvider()
): Promise<Record<string, string>> {
  const signer = new SignatureV4({
    credentials,
    region,
    service: 'neptune-db',
    sha256: Sha256,
    applyChecksum: false,
  });
  const signed = await signer.sign(
    new HttpRequest({
      protocol: 'https:',
      hostname: endpoint.hostname,
      port: endpoint.port,
      method: 'GET',
      path: '/gremlin',
      headers: { host: `${endpoint.hostname}:${endpoint.port}` },
    })
  );
  return Object.fromEntries(
    Object.entries(signed.headers).filter(
      (entry): entry is [string, string] => typeof entry[1] === 'string'
    )
  );
}

// Bytecode submissions come back as Traverser wrappers ({ object, bulk }); the
// driver only expands them for DriverRemoteConnection users. Script submissions
// come back as plain values. Expand bulk so callers see one item per result,
// but never past limit + 1 items: the caller rejects anything over the limit,
// so a bulk value from the server cannot drive an unbounded allocation.
function unwrapTraversers(items: unknown[], limit: number): unknown[] {
  const expanded: unknown[] = [];
  for (const item of items) {
    if (expanded.length > limit) break;
    if (!(item instanceof Gremlin.process.Traverser)) {
      expanded.push(item);
      continue;
    }
    // The driver's Traverser carries `object` and `bulk`; the typings omit both.
    const { object, bulk } = item as unknown as { object: unknown; bulk?: number };
    const count = Math.min(Math.max(1, Number(bulk) || 1), limit + 1 - expanded.length);
    for (let index = 0; index < count; index += 1) expanded.push(object);
  }
  return expanded;
}

function toArray(value: unknown): any[] {
  if (Array.isArray(value)) return value;
  if (value && typeof value === 'object' && 'toArray' in value) {
    const result = (value as { toArray: () => unknown }).toArray();
    if (Array.isArray(result)) return result;
  }
  throw new Error('Neptune returned an invalid result set');
}

function neptuneErrorText(error: unknown): string {
  const value = error as { code?: string; message?: string };
  return `${value?.code || ''} ${value?.message || String(error)}`.toLowerCase();
}

/** Neptune Serverless capacity-transition errors, which retry more patiently. */
export function isNeptuneServerlessTransient(error: unknown): boolean {
  const text = neptuneErrorText(error);
  return (
    text.includes('memorylimitexceededexception') ||
    text.includes('concurrentmodificationexception')
  );
}

export function isNeptuneRetryable(error: unknown): boolean {
  const value = error as {
    code?: string;
    message?: string;
    statusCode?: number;
    $metadata?: { httpStatusCode?: number };
  };
  const text = neptuneErrorText(error);
  // Neptune reports permanent query failures (InternalFailureException) with
  // status 500, so only the gateway/throttling statuses are retryable on their own.
  return (
    [408, 429, 502, 503, 504].includes(
      Number(value?.$metadata?.httpStatusCode ?? value?.statusCode)
    ) ||
    [
      'timeout',
      'websocket is not open',
      'connection has been closed',
      'econnrefused',
      'econnreset',
      'etimedout',
      'throttlingexception',
      'serviceunavailableexception',
      'concurrentmodificationexception',
      // Neptune Serverless raises this sporadically while other writes are in
      // flight; the identical query succeeds on retry.
      'memorylimitexceededexception',
    ].some((token) => text.includes(token))
  );
}

function positiveInteger(value: number | undefined, fallback: number, name: string): number {
  const candidate = value ?? fallback;
  if (!Number.isSafeInteger(candidate) || candidate < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return candidate;
}

function envInteger(name: string, fallback: number): number {
  const value = process.env[name];
  return value ? positiveInteger(Number(value), fallback, name) : fallback;
}

export async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  operation: string
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`${operation} timeout after ${timeoutMs}ms`));
        }, timeoutMs);
        timer.unref?.();
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
