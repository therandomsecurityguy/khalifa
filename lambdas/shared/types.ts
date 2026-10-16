export interface GraphNode {
  id: string;
  label: string;
  properties: Record<string, any>;
  observedAt?: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  label: string;
  properties?: Record<string, any>;
  observedAt?: string;
}

export interface GraphReconcile {
  scope: string;
  runId: string;
  observedAt: string;
  accountId?: string;
  region?: string;
}

export class Logger {
  constructor(private context: string) {}

  info(message: string, meta?: Record<string, any>) {
    console.log(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'INFO',
        context: this.context,
        message,
        ...meta,
      })
    );
  }

  error(message: string, meta?: Record<string, any>) {
    console.error(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'ERROR',
        context: this.context,
        message,
        ...meta,
      })
    );
  }

  warn(message: string, meta?: Record<string, any>) {
    console.warn(
      JSON.stringify({
        timestamp: new Date().toISOString(),
        level: 'WARN',
        context: this.context,
        message,
        ...meta,
      })
    );
  }
}

export interface SecretsClient {
  username: string;
  password: string;
}
