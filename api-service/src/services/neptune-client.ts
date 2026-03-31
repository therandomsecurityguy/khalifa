import Gremlin from 'gremlin';
import { GraphVertex, GraphEdge } from '../types';

const DEFAULT_TIMEOUT = 30000;
const DEFAULT_RETRY_ATTEMPTS = 3;
const DEFAULT_RETRY_DELAY = 1000;

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

    this.client = new Gremlin.driver.Client(
      `wss://${endpoint}:${port}/gremlin`,
      {
        traversalSource: 'g',
        connectTimeout: timeout,
        messageMaxChunkSize: 65536,
        poolSize: this.config.maxConcurrentQueries,
        rejectionDecade: 100,
      }
    );

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
    bindings: Record<string, any> = {},
    options: { timeout?: number; retries?: number } = {}
  ): Promise<any[]> {
    const { retries = DEFAULT_RETRY_ATTEMPTS } = options;
    const timeout = options.timeout || this.config.timeout;

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        if (!this.connected || !this.client) {
          await this.connect();
        }

        const result = await this.executeWithTimeout(query, bindings, timeout!);
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
    bindings: Record<string, any>,
    timeout: number
  ): Promise<any> {
    return new Promise(async (resolve, reject) => {
      let timedOut = false;

      const timeoutId = setTimeout(() => {
        timedOut = true;
        reject(new Error(`Query timeout after ${timeout}ms`));
      }, timeout);

      try {
        if (!this.client) {
          throw new Error('Neptune client not initialized');
        }

        const result = await this.client.submit(query, bindings);
        clearTimeout(timeoutId);

        if (!timedOut) {
          resolve(result);
        }
      } catch (error) {
        clearTimeout(timeoutId);
        if (!timedOut) {
          reject(error);
        }
      }
    });
  }

  private processResult(result: any): any[] {
    if (!result) return [];

    if (Array.isArray(result)) {
      return result;
    }

    if (result._items) {
      return result._items;
    }

    return [result];
  }

  private isRetriableError(error: any): boolean {
    if (!error) return false;

    const message = error.message?.toLowerCase() || '';

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

    return retriablePatterns.some(pattern => message.includes(pattern));
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
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

    const path = this.extractPathFromResult(results[0]);
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
      return this.extractNeighborsFromResult(results);
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

    return this.extractVertexFromResult(results[0]);
  }

  private extractPathFromResult(result: any): { nodes: GraphVertex[]; edges: GraphEdge[] } {
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

  private extractVertexFromResult(obj: any): GraphVertex {
    const properties: Record<string, any> = {};

    for (const [key, value] of Object.entries(obj)) {
      if (key === 'id' || key === 'label') continue;

      const val = value as any;
      properties[key] = val?.value ?? val;
    }

    return {
      id: obj.id?.value || obj.id,
      label: obj.label || 'unknown',
      properties,
    };
  }

  private extractNeighborsFromResult(results: any[]): { nodes: GraphVertex[]; edges: GraphEdge[] } {
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

  private extractEdgeFromResult(obj: any, from: string, to: string): GraphEdge {
    const properties: Record<string, any> = {};

    for (const [key, value] of Object.entries(obj)) {
      if (key === 'id' || key === 'label') continue;

      const val = value as any;
      properties[key] = val?.value ?? val;
    }

    return {
      id: obj.id?.value || obj.id,
      label: obj.label || 'CONNECTED',
      from,
      to,
      properties,
    };
  }
}
