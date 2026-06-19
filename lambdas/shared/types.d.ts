export interface GraphNode {
    id: string;
    label: string;
    properties: Record<string, any>;
}
export interface GraphEdge {
    from: string;
    to: string;
    label: string;
    properties?: Record<string, any>;
}
export declare class Logger {
    private context;
    constructor(context: string);
    info(message: string, meta?: Record<string, any>): void;
    error(message: string, meta?: Record<string, any>): void;
    warn(message: string, meta?: Record<string, any>): void;
}
export interface SecretsClient {
    username: string;
    password: string;
}
export declare function getSecret(secretArn: string): Promise<SecretsClient>;
//# sourceMappingURL=types.d.ts.map