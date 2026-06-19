import type { Request, Response } from 'express';
import { NeptuneClient } from '../services/neptune-client';
import type { NeptunePathResult, NeptuneRawVertex } from '../services/neptune-client';
import type { GraphVertex, GraphEdge } from '../types';

const neptuneEndpoint = process.env.NEPTUNE_ENDPOINT || '';
const neptuneClient = new NeptuneClient({ endpoint: neptuneEndpoint });

export async function findAttackPath(req: Request, res: Response): Promise<void> {
  try {
    const { fromSelector, toSelector, maxPathLength } = req.query;

    if (!fromSelector || !toSelector) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'fromSelector and toSelector are required',
      });
      return;
    }

    await neptuneClient.connect();

    const path = await neptuneClient.findAttackPath(
      fromSelector as string,
      toSelector as string,
      maxPathLength ? parseInt(maxPathLength as string, 10) : 4
    );

    res.json({
      from: fromSelector,
      to: toSelector,
      maxPathLength: maxPathLength || 4,
      nodes: path.nodes,
      edges: path.edges,
    });
  } catch (error) {
    console.error('Error finding attack path:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to find attack path',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function findAllAttackPaths(req: Request, res: Response): Promise<void> {
  try {
    const { maxPathLength } = req.query;
    const maxLen = maxPathLength ? parseInt(maxPathLength as string, 10) : 4;

    await neptuneClient.connect();

    const query = `
      g.V().has('isInternetExposed', true)
        .as('start')
        .repeat(
          out().simplePath()
        ).times(${maxLen})
        .until(
          has('crown_jewel', true)
        )
        .has('crown_jewel', true)
        .as('target')
        .path()
          .by(valueMap(true))
    `;

    const results = await neptuneClient.executeQuery(query);

    const paths = (results as NeptunePathResult[]).map((result) => {
      const nodes: GraphVertex[] = [];
      const edges: GraphEdge[] = [];

      if (result && result.objects) {
        for (const obj of result.objects) {
          if (obj) {
            const vertex: GraphVertex = {
              id: typeof obj.id === 'object' ? obj.id.value : obj.id,
              label: obj.label,
              properties: extractProperties(obj),
            };
            nodes.push(vertex);
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
      }

      return { nodes, edges };
    });

    res.json({
      total: paths.length,
      maxPathLength: maxLen,
      paths: paths.slice(0, 100),
    });
  } catch (error) {
    console.error('Error finding all attack paths:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to find attack paths',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

function extractProperties(obj: NeptuneRawVertex): Record<string, unknown> {
  const properties: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (key !== 'id' && key !== 'label') {
      properties[key] = unwrapGremlinValue(value);
    }
  }

  return properties;
}

function unwrapGremlinValue(val: unknown): unknown {
  if (val && typeof val === 'object' && 'value' in val) {
    return (val as { value: unknown }).value ?? val;
  }
  return val;
}
