import Gremlin from 'gremlin';
import type { GraphNode, GraphEdge } from '../shared/types';
import { Logger } from '../shared/types';
import { getSecret } from '../shared/secrets-client';

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

    client = new Gremlin.driver.Client(`wss://${endpoint}:8182/gremlin`, {
      traversalSource: 'g',
      connectTimeout: 10000,
      messageMaxChunkSize: 65536,
      ...credentials,
    });
  }
  return client;
}

interface WriterEvent {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export const handler = async (
  event: WriterEvent
): Promise<{ success: boolean; written: number }> => {
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
  const bindings: Record<string, any> = {};
  let idx = 0;

  for (const node of nodes) {
    const lblKey = `lbl_${idx}`;
    const arnKey = `arn_${idx}`;
    bindings[lblKey] = node.label;
    bindings[arnKey] = node.id;

    const propParts: string[] = [];
    let propIdx = 0;
    for (const [k, v] of Object.entries(node.properties)) {
      if (v === undefined || v === null) continue;
      const pk = `pk_${idx}_${propIdx}`;
      const pv = `pv_${idx}_${propIdx}`;
      bindings[pk] = k;
      bindings[pv] = v;
      propParts.push(`property(${pk}, ${pv})`);
      propIdx++;
    }

    const propsClause = propParts.length > 0 ? '.' + propParts.join('.') : '';
    statements.push(
      `g.V().has(${lblKey}, 'arn', ${arnKey}).fold().coalesce(unfold(), addV(${lblKey}).property('arn', ${arnKey})${propsClause}).next()`
    );
    idx++;
  }

  const script = statements.join('\n');
  await client.submit(script, bindings);
}

async function writeEdgesBatch(client: Gremlin.driver.Client, edges: GraphEdge[]): Promise<void> {
  const statements: string[] = [];
  const bindings: Record<string, any> = {};
  let idx = 0;

  for (const edge of edges) {
    const fromKey = `ef_${idx}`;
    const toKey = `et_${idx}`;
    const lblKey = `el_${idx}`;
    bindings[fromKey] = edge.from;
    bindings[toKey] = edge.to;
    bindings[lblKey] = edge.label;

    statements.push(
      `g.V().has('arn', ${fromKey}).as('from').V().has('arn', ${toKey}).as('to').coalesce(` +
        `__.select('from').out(${lblKey}).where(__.as('to')), __.addE(${lblKey}).from('from').to('to')).next()`
    );
    idx++;
  }

  const script = statements.join('\n');
  await client.submit(script, bindings);
}
