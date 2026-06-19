import type { Request, Response } from 'express';
import { IssueStore } from '../services/issue-store';
import { NeptuneClient } from '../services/neptune-client';
import type {
  IssueListQuery,
  IssueDetailResponse,
  Severity,
  IssueStatus,
  Environment,
  GraphVertex,
  GraphEdge,
} from '../types';

const issueStore = new IssueStore();

const neptuneEndpoint = process.env.NEPTUNE_ENDPOINT || '';
const neptuneClient = new NeptuneClient({ endpoint: neptuneEndpoint });

export async function listIssues(req: Request, res: Response): Promise<void> {
  try {
    const { severity, team, env, status, ruleId, limit, nextToken } = req.query;

    const query: IssueListQuery = {
      severity: severity
        ? Array.isArray(severity)
          ? (severity as Severity[])
          : [severity as Severity]
        : undefined,
      team: team ? (Array.isArray(team) ? (team as string[]) : [team as string]) : undefined,
      env: env ? (Array.isArray(env) ? (env as Environment[]) : [env as Environment]) : undefined,
      status: status
        ? Array.isArray(status)
          ? (status as IssueStatus[])
          : [status as IssueStatus]
        : undefined,
      ruleId: ruleId as string | undefined,
      limit: limit ? Math.min(parseInt(limit as string, 10), 1000) : 50,
      nextToken: nextToken as string | undefined,
    };

    const response = await issueStore.listIssues(query);

    res.json(response);
  } catch (error) {
    console.error('Error listing issues:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to list issues',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getIssue(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;

    const issue = await issueStore.getIssue(id);

    if (!issue) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `Issue not found: ${id}`,
      });
      return;
    }

    let attackPathNodes: GraphVertex[] = [];
    let attackPathEdges: GraphEdge[] = [];

    if (issue.pathSummary && issue.pathSummary.length > 0) {
      try {
        await neptuneClient.connect();
        const pathNodes: GraphVertex[] = [];

        for (const segment of issue.pathSummary) {
          const fromNode = await neptuneClient.getResource(segment.from);
          const toNode = await neptuneClient.getResource(segment.to);

          if (fromNode) pathNodes.push(fromNode);
          if (toNode) pathNodes.push(toNode);
        }

        attackPathNodes = pathNodes;
        attackPathEdges = issue.pathSummary.map((segment) => ({
          id: `${segment.from}-${segment.to}`,
          label: segment.edgeType,
          from: segment.from,
          to: segment.to,
        }));
      } catch (neptuneError) {
        console.warn('Failed to fetch attack path from Neptune:', neptuneError);
      }
    }

    const response: IssueDetailResponse = {
      ...issue,
      attackPath: {
        nodes: attackPathNodes,
        edges: attackPathEdges,
      },
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting issue:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get issue',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getIssueCounts(req: Request, res: Response): Promise<void> {
  try {
    const counts = await issueStore.getTotalCounts();
    res.json(counts);
  } catch (error) {
    console.error('Error getting issue counts:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get issue counts',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getIssueStats(req: Request, res: Response): Promise<void> {
  try {
    const openIssues = await issueStore.listIssues({
      status: ['open'],
      limit: 1000,
    });

    const stats = {
      total: openIssues.totalCount,
      critical: openIssues.items.filter((i) => i.severity === 'critical').length,
      high: openIssues.items.filter((i) => i.severity === 'high').length,
      medium: openIssues.items.filter((i) => i.severity === 'medium').length,
      low: openIssues.items.filter((i) => i.severity === 'low').length,
      byTeam: {} as Record<string, number>,
      byRule: {} as Record<string, number>,
    };

    for (const issue of openIssues.items) {
      stats.byTeam[issue.owningTeam] = (stats.byTeam[issue.owningTeam] || 0) + 1;
      stats.byRule[issue.ruleId] = (stats.byRule[issue.ruleId] || 0) + 1;
    }

    res.json(stats);
  } catch (error) {
    console.error('Error getting issue stats:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get issue stats',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}
