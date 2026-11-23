import type { Request, Response } from 'express';
import { DynamoDBIssueRepository } from '@khalifa/risk-engine';
import { parseBoundedInteger, pathParam } from '../middleware/gremlin-validator';
import { getApiNeptuneClient } from '../services/api-dependencies';
import { AI_INVENTORY_LABELS, type AiInventoryType } from '../services/neptune-client';
import type { GraphVertex, Issue } from '../types';

const neptuneClient = getApiNeptuneClient();
const issueStore = new DynamoDBIssueRepository();
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

// The only edge labels the agent detail groups by; any other neighbor of the
// agent vertex is ignored rather than passed through unclassified.
const AGENT_EDGE_GROUPS: Record<
  string,
  'role' | 'knowledgeBases' | 'guardrail' | 'tools' | 'model'
> = {
  RUNS_AS: 'role',
  HAS_KB: 'knowledgeBases',
  PROTECTED_BY: 'guardrail',
  HAS_ACTION_GROUP: 'tools',
  USES_MODEL: 'model',
};

export async function getAiInventory(req: Request, res: Response): Promise<void> {
  try {
    const limit = parseBoundedInteger(req.query.limit, DEFAULT_LIMIT, 1, MAX_LIMIT, 'limit');
    const requested = req.query.type;
    if (
      requested !== undefined &&
      (typeof requested !== 'string' || !(requested in AI_INVENTORY_LABELS))
    ) {
      res.status(400).json({
        code: 'BAD_REQUEST',
        message: `type must be one of: ${Object.keys(AI_INVENTORY_LABELS).join(', ')}`,
      });
      return;
    }

    const sections = await neptuneClient.listAiInventory(
      limit,
      requested === undefined ? undefined : [requested as AiInventoryType]
    );
    res.json({ types: sections });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('limit must be')) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    console.error('Error listing AI inventory:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list AI inventory' });
  }
}

export async function getAiAgent(
  req: Request<{ arn: string | string[] }>,
  res: Response
): Promise<void> {
  try {
    const arn = pathParam(req.params.arn);
    const agent = await neptuneClient.getResource(arn);
    if (!agent || agent.label !== 'AiAgent') {
      res.status(404).json({ code: 'NOT_FOUND', message: `AI agent not found: ${arn}` });
      return;
    }

    const { nodes, edges } = await neptuneClient.getNeighbors(arn);
    const byId = new Map(nodes.map((node) => [node.id, node]));
    const groups: Record<string, GraphVertex[]> = {
      role: [],
      knowledgeBases: [],
      guardrail: [],
      tools: [],
      model: [],
    };
    for (const edge of edges) {
      const group = AGENT_EDGE_GROUPS[edge.label];
      if (!group) continue;
      const neighborId = edge.from === arn ? edge.to : edge.from;
      const node = byId.get(neighborId);
      if (!node || groups[group].some((existing) => existing.id === node.id)) continue;
      groups[group].push(node);
    }

    const issues: Issue[] = await issueStore.getOpenIssuesByResourceArn(arn);

    res.json({
      agent,
      role: groups.role[0] ?? null,
      knowledgeBases: groups.knowledgeBases,
      guardrail: groups.guardrail[0] ?? null,
      tools: groups.tools,
      model: groups.model[0] ?? null,
      issues,
    });
  } catch (error) {
    console.error('Error getting AI agent:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get AI agent' });
  }
}
