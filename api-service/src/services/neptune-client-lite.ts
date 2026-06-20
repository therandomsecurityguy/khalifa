import Gremlin from 'gremlin';

export interface NeptuneConfig {
  endpoint: string;
  port?: number;
  timeout?: number;
}

export class NeptuneClient {
  private client: Gremlin.driver.Client | null = null;
  private config: NeptuneConfig;
  private connected: boolean = false;

  constructor(config: NeptuneConfig) {
    this.config = {
      port: 8182,
      timeout: 30000,
      ...config,
    };
  }

  async connect(): Promise<void> {
    if (this.connected && this.client) return;
    const { endpoint, port, timeout } = this.config;
    this.client = new Gremlin.driver.Client(`wss://${endpoint}:${port}/gremlin`, {
      traversalSource: 'g',
      connectTimeout: timeout,
      messageMaxChunkSize: 65536,
      poolSize: 10,
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

  async executeQuery(query: string, bindings: Record<string, unknown> = {}): Promise<unknown[]> {
    if (!this.client) await this.connect();
    const client = this.client!;
    const result = await client.submit(query, bindings);
    return this.processResult(result);
  }

  private processResult(result: unknown): unknown[] {
    if (!result) return [];
    if (Array.isArray(result)) return result;
    if (typeof result === 'object' && result !== null && '_items' in result) {
      return (result as { _items: unknown[] })._items;
    }
    return [result];
  }
}
