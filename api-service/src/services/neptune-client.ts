import Gremlin from 'gremlin';
import type { GraphVertex, GraphEdge } from '../types';

const DEFAULT_TIMEOUT = 30000;
const DEFAULT_RETRY_ATTEMPTS = 3;
const DEFAULT_RETRY_DELAY = 1000;

export interface NeptuneRawVertex {
  id: { value: string } | string;
  label: string;
  [key: string]: unknown;
}

export interface NeptunePathResult {
  objects: NeptuneRawVertex[];
}

export interface NeptuneNeighborResult {
  node: NeptuneRawVertex;
  neighbor: NeptuneRawVertex;
  edge: NeptuneRawVertex;
}

export interface NeptuneConfig {
  endpoint: string;
  port?: number;
  timeout?: number;
  maxConcurrentQueries?: number;
}

export class NeptuneClient {
  private client: Gremlin.driver.Client | null = null;
  private config: NeptuneConfig;
  private connected: boolean = false;

  constructor(config: NeptuneConfig) {
    this.config = {
      port: 8182,
      timeout: DEFAULT_TIMEOUT,
      maxConcurrentQueries: 10,
      ...config,
    };
  }

  async connect(): Promise<void> {
    if (this.connected && this.client) {
      return;
    }

    const { endpoint, port, timeout } = this.config;

    this.client = new Gremlin.driver.Client(`wss://${endpoint}:${port}/gremlin`, {
      traversalSource: 'g',
      connectTimeout: timeout,
      messageMaxChunkSize: 65536,
      poolSize: this.config.maxConcurrentQueries,
      rejectionDecade: 100,
    });

    await this.client.open();
    this.connected = true;
  }

  async close(): Promise<void> {
    if (this.client) {
      await this.client.close();
      this.client = null;
      this.connected = false;
    }
  }

  async executeQuery(
    query: string,
    bindings: Record<string, unknown> = {},
    options: { timeout?: number; retries?: number } = {}
  ): Promise<unknown[]> {
    const { retries = DEFAULT_RETRY_ATTEMPTS } = options;
    const timeout = options.timeout || this.config.timeout;

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        if (!this.connected || !this.client) {
          await this.connect();
        }

        const result = await this.executeWithTimeout(query, bindings, timeout ?? DEFAULT_TIMEOUT);
        return this.processResult(result);
      } catch (error) {
        lastError = error as Error;

        if (this.isRetriableError(error)) {
          const delay = DEFAULT_RETRY_DELAY * Math.pow(2, attempt);
          await this.sleep(delay);
          this.connected = false;
          continue;
        }

        throw error;
      }
    }

    throw lastError;
  }

  private async executeWithTimeout(
    query: string,
    bindings: Record<string, unknown>,
    timeout: number
  ): Promise<unknown> {
    if (!this.client) {
      throw new Error('Neptune client not initialized');
    }

    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`Query timeout after ${timeout}ms`)), timeout);
    });

    return Promise.race([this.client.submit(query, bindings), timeoutPromise]);
  }

  private processResult(result: unknown): unknown[] {
    if (!result) return [];

    if (Array.isArray(result)) {
      return result;
    }

    if (typeof result === 'object' && result !== null && '_items' in result) {
      return (result as { _items: unknown[] })._items;
    }

    return [result];
  }

  private isRetriableError(error: unknown): boolean {
    if (!error) return false;

    const message =
      error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();

    const retriablePatterns = [
      'timeout',
      'connection',
      'network',
      'socket',
      'econnrefused',
      'enetunreach',
      'service unavailable',
      '503',
    ];

    return retriablePatterns.some((pattern) => message.includes(pattern));
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async findAttackPath(
    fromSelector: string,
    toSelector: string,
    maxPathLength: number = 4
  ): Promise<{ nodes: GraphVertex[]; edges: GraphEdge[] }> {
    const query = `
      g.V()
        .hasLabel(${fromSelector})
        .as('start')
        .repeat(
          out().simplePath()
        ).times(${maxPathLength})
        .until(
          hasLabel(${toSelector})
        )
        .hasLabel(${toSelector})
        .as('target')
        .path()
          .by(valueMap(true))
    `;

    const results = await this.executeQuery(query);

    if (results.length === 0) {
      return { nodes: [], edges: [] };
    }

    const path = this.extractPathFromResult(results[0] as NeptunePathResult);
    return path;
  }

  async getNeighbors(arn: string): Promise<{ nodes: GraphVertex[]; edges: GraphEdge[] }> {
    const query = `
      g.V().has('arn', '${arn}')
        .as('node')
        .both()
        .fold()
        .coalesce(
          unfold().as('neighbor').project('node', 'neighbor', 'edge').by(valueMap(true)).by(valueMap(true)).by(valueMap(true)),
          unfold().as('neighbor').project('node', 'neighbor', 'edge').by(valueMap(true)).by(valueMap(true)).by(valueMap(true))
        )
    `;

    try {
      const results = await this.executeQuery(query);
      return this.extractNeighborsFromResult(results as NeptuneNeighborResult[]);
    } catch (error) {
      return { nodes: [], edges: [] };
    }
  }

  async getResource(arn: string): Promise<GraphVertex | null> {
    const query = `g.V().has('arn', '${arn}').valueMap(true)`;

    const results = await this.executeQuery(query);

    if (results.length === 0) {
      return null;
    }

    return this.extractVertexFromResult(results[0] as NeptuneRawVertex);
  }

  private extractPathFromResult(result: NeptunePathResult): {
    nodes: GraphVertex[];
    edges: GraphEdge[];
  } {
    const nodes: GraphVertex[] = [];
    const edges: GraphEdge[] = [];

    if (!result || !result.objects) {
      return { nodes, edges };
    }

    for (const obj of result.objects) {
      if (obj) {
        nodes.push(this.extractVertexFromResult(obj));
      }
    }

    for (let i = 0; i < nodes.length - 1; i++) {
      edges.push({
        id: `${nodes[i].id}-${nodes[i + 1].id}`,
        label: 'CONNECTED',
        from: nodes[i].id,
        to: nodes[i + 1].id,
      });
    }

    return { nodes, edges };
  }

  private extractVertexFromResult(obj: NeptuneRawVertex): GraphVertex {
    const properties: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      if (key === 'id' || key === 'label') continue;

      properties[key] = this.unwrapGremlinValue(value);
    }

    return {
      id: typeof obj.id === 'object' ? obj.id.value : obj.id,
      label: obj.label || 'unknown',
      properties,
    };
  }

  private unwrapGremlinValue(val: unknown): unknown {
    if (val && typeof val === 'object' && 'value' in val) {
      return (val as { value: unknown }).value ?? val;
    }
    return val;
  }

  private extractNeighborsFromResult(results: NeptuneNeighborResult[]): {
    nodes: GraphVertex[];
    edges: GraphEdge[];
  } {
    const nodes: GraphVertex[] = [];
    const edges: GraphEdge[] = [];

    for (const result of results) {
      if (result.node && result.neighbor && result.edge) {
        const node = this.extractVertexFromResult(result.node);
        const neighbor = this.extractVertexFromResult(result.neighbor);
        const edge = this.extractEdgeFromResult(result.edge, node.id, neighbor.id);

        nodes.push(node, neighbor);
        edges.push(edge);
      }
    }

    return { nodes, edges };
  }

  private extractEdgeFromResult(obj: NeptuneRawVertex, from: string, to: string): GraphEdge {
    const properties: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(obj)) {
      if (key === 'id' || key === 'label') continue;

      properties[key] = this.unwrapGremlinValue(value);
    }

    return {
      id: typeof obj.id === 'object' ? obj.id.value : obj.id,
      label: obj.label || 'CONNECTED',
      from,
      to,
      properties,
    };
  }
}
