import type { Request, Response } from 'express';
import { NeptuneClient } from '../services/neptune-client';
import { IssueStore } from '../services/issue-store';
import type { GraphVertex, GraphEdge, Issue } from '../types';

const neptuneEndpoint = process.env.NEPTUNE_ENDPOINT || '';
const neptuneClient = new NeptuneClient({ endpoint: neptuneEndpoint });
const issueStore = new IssueStore();

export async function getResource(req: Request, res: Response): Promise<void> {
  try {
    const { arn } = req.params;
    const { includeNeighbors, includeIssues } = req.query;

    const includeNeigh = includeNeighbors !== 'false';
    const includeIss = includeIssues !== 'false';

    await neptuneClient.connect();

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
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function searchResources(req: Request, res: Response): Promise<void> {
  try {
    const { label, property, value, limit } = req.query;

    if (!label) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'label query parameter is required',
      });
      return;
    }

    await neptuneClient.connect();

    let query = `g.V().has('label', '${label}')`;

    if (property && value) {
      query += `.has('${property}', '${value}')`;
    }

    query += `.limit(${limit ? parseInt(limit as string, 10) : 100})`;

    const results = await neptuneClient.executeQuery(query);

    const resources: GraphVertex[] = results.map((result: any) => ({
      id: result.id?.value || result.id,
      label: result.label,
      properties: extractProperties(result),
    }));

    res.json({
      label: label,
      total: resources.length,
      resources,
    });
  } catch (error) {
    console.error('Error searching resources:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to search resources',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getResourceGraph(req: Request, res: Response): Promise<void> {
  try {
    const { arn, depth } = req.query;
    const maxDepth = depth ? parseInt(depth as string, 10) : 2;

    if (!arn) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: 'arn query parameter is required',
      });
      return;
    }

    await neptuneClient.connect();

    const result = await getResourceWithNeighbors(arn as string, maxDepth);

    res.json(result);
  } catch (error) {
    console.error('Error getting resource graph:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get resource graph',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

async function getResourceWithNeighbors(
  arn: string,
  depth: number
): Promise<{ nodes: GraphVertex[]; edges: GraphEdge[] }> {
  const visited = new Set<string>();
  const nodes: GraphVertex[] = [];
  const edges: GraphEdge[] = [];

  async function traverse(currentArn: string, currentDepth: number): Promise<void> {
    if (currentDepth > depth || visited.has(currentArn)) {
      return;
    }

    visited.add(currentArn);

    const resource = await neptuneClient.getResource(currentArn);
    if (resource) {
      nodes.push(resource);
    }

    const { nodes: neighbors, edges: neighborEdges } = await neptuneClient.getNeighbors(currentArn);

    for (const neighbor of neighbors) {
      if (!visited.has(neighbor.id)) {
        edges.push(...neighborEdges.filter((e) => e.from === currentArn && e.to === neighbor.id));
        await traverse(neighbor.id, currentDepth + 1);
      }
    }
  }

  await traverse(arn, 0);

  return { nodes, edges };
}

function extractProperties(obj: any): Record<string, any> {
  const properties: Record<string, any> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (key !== 'id' && key !== 'label') {
      const val = value as any;
      properties[key] = val?.value ?? val;
    }
  }

  return properties;
}
