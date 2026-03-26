import Gremlin from 'gremlin';
import { GraphNode, GraphEdge, Logger } from '../../shared/types';
import { getSecret } from '../../shared/secrets-client';

const logger = new Logger('graph-writer');

let client: Gremlin.driver.Client | null = null;

async function getClient(): Promise<Gremlin.driver.Client> {
  if (!client) {
    const endpoint = process.env.NEPTUNE_ENDPOINT || '';
    const secretArn = process.env.NEPTUNE_AUTH_SECRET_ARN || '';
    
    let credentials = {};
    if (secretArn) {
      const secret = await getSecret(secretArn);
      credentials = { username: secret.username, password: secret.password };
    }

    client = new Gremlin.driver.Client(
      `wss://${endpoint}:8182/gremlin`,
      { traversalSource: 'g', connectTimeout: 10000, messageMaxChunkSize: 65536, ...credentials }
    );
  }
  return client;
}

interface WriterEvent {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const handler = async (event: WriterEvent): Promise<{ success: boolean; written: number }> => {
  const { nodes, edges } = event;
  logger.info(`Starting Neptune write: ${nodes.length} nodes, ${edges.length} edges`);

  const BATCH_SIZE = 50;
  let written = 0;

  try {
    const gremlinClient = await getClient();

    for (let i = 0; i < nodes.length; i += BATCH_SIZE) {
      await writeNodesBatch(gremlinClient, nodes.slice(i, i + BATCH_SIZE));
      written += Math.min(BATCH_SIZE, nodes.length - i);
    }

    for (let i = 0; i < edges.length; i += BATCH_SIZE) {
      await writeEdgesBatch(gremlinClient, edges.slice(i, i + BATCH_SIZE));
      written += Math.min(BATCH_SIZE, edges.length - i);
    }

    logger.info(`Neptune write complete: ${written} items`);
    return { success: true, written };
  } catch (error) {
    logger.error(`Neptune write failed: ${error}`);
    throw error;
  }
};

async function writeNodesBatch(client: Gremlin.driver.Client, nodes: GraphNode[]): Promise<void> {
  const statements: string[] = [];

  for (const node of nodes) {
    const props = Object.entries(node.properties)
      .filter(([_, v]) => v !== undefined && v !== null)
      .map(([k, v]) => {
        const val = typeof v === 'string' ? `'${v.replace(/'/g, "\\'")}'` : JSON.stringify(v);
        return `${k}: ${val}`;
      })
      .join(', ');

    statements.push(
      `g.V().has('${node.label}', 'arn', '${node.id}').fold().coalesce(` +
      `unfold(), addV('${node.label}').property('arn', '${node.id}').property(${props})).next()`
    );
  }

  const script = statements.join('\n');
  await client.submit(script);
}

async function writeEdgesBatch(client: Gremlin.driver.Client, edges: GraphEdge[]): Promise<void> {
  const statements: string[] = [];

  for (const edge of edges) {
    statements.push(
      `g.V().has('arn', '${edge.from}').as('from').V().has('arn', '${edge.to}').as('to').coalesce(` +
      `__.has('from').out('${edge.label}').has('to'), __.addE('${edge.label}').from('from').to('to')).next()`
    );
  }

  const script = statements.join('\n');
  await client.submit(script);
}
