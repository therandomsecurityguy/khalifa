import type { Request, Response } from 'express';
import { DynamoDBIssueRepository } from '@khalifa/risk-engine';
import { parseBoundedInteger } from '../middleware/gremlin-validator';
import { getApiNeptuneClient } from '../services/api-dependencies';
import { ALL_LABELS } from '../services/neptune-client';
import type { GraphVertex, GraphEdge, Issue } from '../types';

const neptuneClient = getApiNeptuneClient();
const issueStore = new DynamoDBIssueRepository();
const MAX_GRAPH_NODES = 500;
const MAX_GRAPH_EDGES = 1_000;

// Counting labels reads every vertex and can take tens of seconds, while the
// counts only move when the collector runs. The last good count is served at
// once and refreshed in the background when stale; only the first request
// waits. A failed refresh keeps the previous count. Concurrent callers share
// one in-flight read.
const LABELS_TTL_MS = 10 * 60 * 1000;
type LabelCounts = Awaited<ReturnType<typeof neptuneClient.listResourceLabels>>;
let labelCounts: { at: number; labels: LabelCounts } | null = null;
let labelRead: Promise<LabelCounts> | null = null;

function refreshLabelCounts(): Promise<LabelCounts> {
  if (!labelRead) {
    labelRead = Promise.resolve()
      .then(() => neptuneClient.listResourceLabels())
      .then((labels) => {
        labelCounts = { at: Date.now(), labels };
        return labels;
      })
      .finally(() => {
        labelRead = null;
      });
  }
  return labelRead;
}

export async function listResourceLabels(_req: Request, res: Response): Promise<void> {
  try {
    if (labelCounts) {
      if (Date.now() - labelCounts.at > LABELS_TTL_MS) {
        refreshLabelCounts().catch((error) =>
          console.error('Error refreshing resource labels:', error)
        );
      }
      res.json({ labels: labelCounts.labels });
      return;
    }
    res.json({ labels: await refreshLabelCounts() });
  } catch (error) {
    console.error('Error listing resource labels:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list resource labels' });
  }
}

// Graph labels and property keys are identifiers, never free text.
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const identifier = (value: unknown): string | null =>
  typeof value === 'string' && IDENTIFIER.test(value) ? value : null;
const labelOrAll = (value: unknown): string | null =>
  value === ALL_LABELS ? ALL_LABELS : identifier(value);

export async function listResourceProperties(req: Request, res: Response): Promise<void> {
  const label = labelOrAll(req.query.label);
  if (!label) {
    res.status(400).json({ code: 'BAD_REQUEST', message: 'A valid label is required' });
    return;
  }
  try {
    res.json({ properties: await neptuneClient.listResourceProperties(label) });
  } catch (error) {
    console.error('Error listing resource properties:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list properties' });
  }
}

export async function listPropertyValues(req: Request, res: Response): Promise<void> {
  const label = labelOrAll(req.query.label);
  const property = identifier(req.query.property);
  if (!label || !property) {
    res
      .status(400)
      .json({ code: 'BAD_REQUEST', message: 'A valid label and property are required' });
    return;
  }
  try {
    res.json(await neptuneClient.listPropertyValues(label, property));
  } catch (error) {
    console.error('Error listing property values:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list property values' });
  }
}

export async function getResource(req: Request<{ arn: string }>, res: Response): Promise<void> {
  try {
    const { arn } = req.params;
    const { includeNeighbors, includeIssues } = req.query;

    const includeNeigh = includeNeighbors !== 'false';
    const includeIss = includeIssues !== 'false';

    const resource = await neptuneClient.getResource(arn);

    if (!resource) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `Resource not found: ${arn}`,
      });
      return;
    }

    let neighbors: GraphVertex[] = [];
    let neighborEdges: GraphEdge[] = [];
    let issues: Issue[] = [];

    if (includeNeigh) {
      const neighborResult = await neptuneClient.getNeighbors(arn);
      neighbors = neighborResult.nodes.filter((n) => n.id !== arn);
      neighborEdges = neighborResult.edges;
    }

    if (includeIss) {
      issues = await issueStore.getOpenIssuesByResourceArn(arn);
    }

    res.json({
      resource,
      neighbors,
      edges: neighborEdges,
      issues,
    });
  } catch (error) {
    console.error('Error getting resource:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get resource',
    });
  }
}

export async function searchResources(req: Request, res: Response): Promise<void> {
  try {
    const { label, property, value, limit, nextToken } = req.query;

    if (typeof label !== 'string' || !label) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'label query parameter is required',
      });
      return;
    }
    if ((property === undefined) !== (value === undefined)) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'property and value must be provided together',
      });
      return;
    }
    if (
      (property !== undefined && typeof property !== 'string') ||
      (value !== undefined && typeof value !== 'string') ||
      (nextToken !== undefined && typeof nextToken !== 'string')
    ) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'Invalid resource search query' });
      return;
    }

    const limitNum = parseBoundedInteger(limit, 100, 1, 200, 'limit');
    const result =
      label === ALL_LABELS && property === undefined
        ? await neptuneClient.browseAllLabels({
            labels: (labelCounts?.labels ?? (await refreshLabelCounts())).map(
              (entry) => entry.label
            ),
            limit: limitNum,
            nextToken,
          })
        : await neptuneClient.searchResources({
            label,
            property,
            value,
            limit: limitNum,
            nextToken,
          });

    res.json({
      label,
      resources: result.resources,
      nextToken: result.nextToken,
    });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Invalid pagination token')) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    if (error instanceof Error && error.message.startsWith('limit must be')) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    console.error('Error searching resources:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to search resources',
    });
  }
}

export async function getResourceGraph(req: Request, res: Response): Promise<void> {
  try {
    const { arn, depth } = req.query;

    if (typeof arn !== 'string' || !arn) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'arn query parameter is required',
      });
      return;
    }
    const maxDepth = parseBoundedInteger(depth, 2, 0, 3, 'depth');

    const result = await getResourceWithNeighbors(arn as string, maxDepth);

    res.json(result);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('depth must be')) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    console.error('Error getting resource graph:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get resource graph',
    });
  }
}

async function getResourceWithNeighbors(
  arn: string,
  depth: number
): Promise<{ nodes: GraphVertex[]; edges: GraphEdge[] }> {
  const root = await neptuneClient.getResource(arn);
  if (!root) return { nodes: [], edges: [] };

  const nodes = new Map<string, GraphVertex>([[root.id, root]]);
  const edges = new Map<string, GraphEdge>();
  let frontier = [arn];

  for (let currentDepth = 0; currentDepth < depth && frontier.length > 0; currentDepth += 1) {
    const nextFrontier: string[] = [];
    for (const currentArn of frontier) {
      if (nodes.size >= MAX_GRAPH_NODES || edges.size >= MAX_GRAPH_EDGES) break;
      const remainingEdges = Math.min(200, MAX_GRAPH_EDGES - edges.size);
      const result = await neptuneClient.getNeighbors(currentArn, remainingEdges);
      result.edges.forEach((edge) => edges.set(edge.id, edge));
      for (const neighbor of result.nodes) {
        if (nodes.size >= MAX_GRAPH_NODES) break;
        if (!nodes.has(neighbor.id)) {
          nodes.set(neighbor.id, neighbor);
          const neighborArn =
            typeof neighbor.properties.arn === 'string' ? neighbor.properties.arn : neighbor.id;
          nextFrontier.push(neighborArn);
        }
      }
    }
    frontier = nextFrontier;
  }

  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()].filter((edge) => nodes.has(edge.from) && nodes.has(edge.to)),
  };
}
