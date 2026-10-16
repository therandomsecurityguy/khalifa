import {
  createSigV4Headers,
  isNeptuneRetryable,
  normalizeNeptuneEndpoint,
  withTimeout,
  type NeptuneEndpoint,
} from '@khalifa/risk-engine';
import Gremlin from 'gremlin';
import { GraphRepository, type GraphWriteResult } from '../shared/graph-repository';
import type { GraphEdge, GraphNode, GraphReconcile } from '../shared/types';
import { Logger } from '../shared/types';

const logger = new Logger('graph-writer');

export interface WriterEvent {
  nodes: GraphNode[];
  edges: GraphEdge[];
  observedAt?: string;
  reconcile?: GraphReconcile;
}

export { createSigV4Headers, normalizeNeptuneEndpoint } from '@khalifa/risk-engine';

interface RuntimeConnection {
  readonly isOpen: boolean;
  open(): Promise<void>;
  close(): Promise<void>;
}

interface WriterRepository {
  write(event: WriterEvent, observedAt?: string): Promise<GraphWriteResult>;
}

export interface WriterDependencies {
  createHeaders: (endpoint: NeptuneEndpoint, region: string) => Promise<Record<string, string>>;
  createConnection: (url: string, headers: Record<string, string>) => RuntimeConnection;
  createRepository: (connection: RuntimeConnection) => WriterRepository;
  sleep: (ms: number) => Promise<void>;
}

export interface WriterConfig {
  endpoint: NeptuneEndpoint;
  region: string;
  timeoutMs: number;
  maxAttempts: number;
}

export class NeptuneGraphWriter {
  private connection: RuntimeConnection | null = null;
  private repository: WriterRepository | null = null;
  private connecting: Promise<WriterRepository> | null = null;
  private generation = 0;

  constructor(
    private readonly config: WriterConfig,
    private readonly dependencies: WriterDependencies
  ) {}

  async write(event: WriterEvent): Promise<GraphWriteResult> {
    for (let attempt = 1; attempt <= this.config.maxAttempts; attempt += 1) {
      try {
        const repository = await withTimeout(
          this.getRepository(),
          this.config.timeoutMs,
          'Neptune connection'
        );
        return await withTimeout(
          repository.write(event, event.observedAt),
          this.config.timeoutMs,
          'Neptune graph write'
        );
      } catch (error) {
        const retryable = isNeptuneRetryable(error);
        if (retryable) await this.reset(error);
        if (!retryable || attempt === this.config.maxAttempts) throw error;
        await this.dependencies.sleep(100 * 2 ** (attempt - 1));
      }
    }
    throw new Error('Neptune graph write failed without an error');
  }

  async close(): Promise<void> {
    this.generation++;
    const connection = this.connection;
    this.connection = null;
    this.repository = null;
    this.connecting = null;
    if (connection) {
      await withTimeout(connection.close(), this.config.timeoutMs, 'Neptune connection close');
    }
  }

  private async getRepository(): Promise<WriterRepository> {
    if (this.connection?.isOpen && this.repository) return this.repository;
    if (this.connecting) return this.connecting;

    const generation = this.generation;
    const connecting = (async () => {
      const headers = await this.dependencies.createHeaders(
        this.config.endpoint,
        this.config.region
      );
      if (generation !== this.generation) throw new Error('Neptune connection closed');
      const connection = this.dependencies.createConnection(this.config.endpoint.url, headers);
      this.connection = connection;
      try {
        await connection.open();
        if (generation !== this.generation) throw new Error('Neptune connection closed');
      } catch (error) {
        if (this.connection === connection) this.connection = null;
        await connection
          .close()
          .catch((closeError) =>
            logger.error('Failed to close rejected Neptune connection', { closeError, error })
          );
        throw error;
      }
      this.repository = this.dependencies.createRepository(connection);
      return this.repository;
    })();
    this.connecting = connecting;
    try {
      return await connecting;
    } finally {
      if (this.connecting === connecting) this.connecting = null;
    }
  }

  private async reset(originalError: unknown): Promise<void> {
    try {
      await this.close();
    } catch (error) {
      logger.error('Failed to reset Neptune connection', { error, originalError });
    }
  }
}

export function createGraphWriterHandler(writer?: Pick<NeptuneGraphWriter, 'write'>): (
  event: WriterEvent
) => Promise<{
  success: true;
  written: number;
  skipped: number;
  tombstoned: number;
}> {
  let runtimeWriter: NeptuneGraphWriter | undefined;
  return async (event) => {
    if (!event || !Array.isArray(event.nodes) || !Array.isArray(event.edges)) {
      throw new Error('Graph writer event must contain nodes and edges arrays');
    }

    try {
      runtimeWriter ||= writer ? undefined : createRuntimeWriter();
      const result = await (writer || runtimeWriter!).write(event);
      return {
        success: true,
        written: result.nodes + result.edges,
        skipped: result.skippedEdges,
        tombstoned: result.tombstoned,
      };
    } catch (error) {
      logger.error('Neptune write failed', {
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  };
}

export const handler = createGraphWriterHandler();

export function createRuntimeWriter(): NeptuneGraphWriter {
  const timeoutMs = envInteger('NEPTUNE_WRITE_TIMEOUT_MS', 30_000);
  const maxConcurrency = envInteger('NEPTUNE_WRITE_CONCURRENCY', 2);
  const chunkSize = envInteger('NEPTUNE_MUTATION_CHUNK', 25);
  return new NeptuneGraphWriter(
    {
      endpoint: normalizeNeptuneEndpoint(process.env.NEPTUNE_ENDPOINT || ''),
      region: process.env.AWS_REGION || 'us-east-1',
      timeoutMs,
      maxAttempts: envInteger('NEPTUNE_MAX_ATTEMPTS', 3),
    },
    {
      createHeaders: createSigV4Headers,
      createConnection: (url, headers) =>
        new Gremlin.driver.DriverRemoteConnection(url, {
          traversalSource: 'g',
          headers,
          messageMaxChunkSize: 65_536,
        }),
      createRepository: (connection) =>
        new GraphRepository(
          createRemoteTraversal(connection, timeoutMs),
          maxConcurrency,
          chunkSize
        ),
      sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    }
  );
}

export function createRemoteTraversal(
  connection: RuntimeConnection,
  timeoutMs: number
): Gremlin.process.GraphTraversalSource {
  return Gremlin.process
    .traversal()
    .withRemote(connection as unknown as Gremlin.driver.RemoteConnection)
    .with_('evaluationTimeout', timeoutMs);
}

function envInteger(name: string, fallback: number): number {
  const value = process.env[name];
  const parsed = value ? Number(value) : fallback;
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}
