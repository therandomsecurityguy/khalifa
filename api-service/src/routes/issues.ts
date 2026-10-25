import type { Request, Response } from 'express';
import {
  DynamoDBIssueRepository,
  PostureTrendStore,
  type IssueListQuery,
} from '@khalifa/risk-engine';
import { parseBoundedInteger } from '../middleware/gremlin-validator';
import { getApiNeptuneClient } from '../services/api-dependencies';
import { nextRuns } from '../services/cron';
import { outsidePrincipals } from './attack-paths';
import type {
  AttackPathEntry,
  IssueDetailResponse,
  Severity,
  IssueStatus,
  Environment,
  GraphVertex,
  GraphEdge,
} from '../types';

const issueStore = new DynamoDBIssueRepository();
const trendStore = new PostureTrendStore();
// Bounds the DynamoDB filter expression; the catalogue has far fewer rules.
const MAX_RULE_FILTERS = 50;
// The runner caps an issue's resources at 200; never read more than that.
const MAX_INVOLVED_LOOKUPS = 200;
const neptuneClient = getApiNeptuneClient();

export async function listIssues(req: Request, res: Response): Promise<void> {
  try {
    const { severity, team, env, status, ruleId, limit, nextToken, order = 'desc' } = req.query;

    const ruleIds = ruleId === undefined ? [] : Array.isArray(ruleId) ? ruleId : [ruleId];
    if (
      ruleIds.length > MAX_RULE_FILTERS ||
      ruleIds.some((value) => typeof value !== 'string' || !value || value.length > 64) ||
      (nextToken !== undefined && (typeof nextToken !== 'string' || nextToken.length > 2048)) ||
      (order !== 'asc' && order !== 'desc')
    ) {
      res.status(400).json({ code: 'BAD_REQUEST', message: 'Invalid issue query' });
      return;
    }

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
      ruleId: ruleIds.length === 1 ? (ruleIds[0] as string) : undefined,
      ruleIds: ruleIds.length > 1 ? (ruleIds as string[]) : undefined,
      order,
      limit: parseBoundedInteger(limit, 50, 1, 1000, 'limit'),
      nextToken,
    };

    const response = await issueStore.listIssues(query);

    res.json(response);
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message.startsWith('limit must be') || error.message.includes('pagination token'))
    ) {
      res.status(400).json({ code: 'BAD_REQUEST', message: error.message });
      return;
    }
    console.error('Error listing issues:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to list issues',
    });
  }
}

export async function getIssue(req: Request<{ id: string }>, res: Response): Promise<void> {
  try {
    const { id } = req.params;

    const issue = await issueStore.getIssueById(id);

    if (!issue) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `Issue not found: ${id}`,
      });
      return;
    }

    let attackPathNodes: GraphVertex[] = [];
    let attackPathEdges: GraphEdge[] = [];
    let entry: AttackPathEntry | undefined;
    let involvedResources: GraphVertex[] = [];

    // Consecutive segments share a vertex; look each one up once, in path order.
    // A single-resource match has no segments, so its resources stand alone.
    const orderedIds = issue.pathSummary?.length
      ? [...new Set(issue.pathSummary.flatMap((segment) => [segment.from, segment.to]))]
      : [...new Set((issue.resourcesInvolved || []).map((resource) => resource.resourceId))];

    if (orderedIds.length > 0) {
      try {
        const pathNodes = await Promise.all(orderedIds.map((id) => neptuneClient.getResource(id)));
        const involved = new Map(
          (issue.resourcesInvolved || []).map((resource) => [resource.resourceId, resource])
        );
        // A vertex gone from the graph stays as a placeholder, so the drawing
        // never bridges the gap with an edge that does not exist. The issue
        // still knows its type and name from when it matched.
        attackPathNodes = pathNodes.map((node, index) => {
          if (node) return node;
          const id = orderedIds[index];
          const resource = involved.get(id);
          return {
            id,
            label: 'Missing',
            properties: {
              name: resource?.resourceName || id.split(/[:/]/).pop(),
              missing: true,
              ...(resource?.resourceType ? { deleted_label: resource.resourceType } : {}),
            },
          };
        });
        attackPathEdges = (issue.pathSummary || []).map((segment) => ({
          id: `${segment.from}-${segment.to}`,
          label: segment.edgeType,
          from: segment.from,
          to: segment.to,
        }));
        entry = await pathEntry(attackPathNodes[0]);
      } catch (neptuneError) {
        console.warn('Failed to fetch attack path from Neptune:', neptuneError);
      }
    }

    // Resources the issue lists but its drawn path does not cross, such as
    // other findings on the same instance, so each can show its own evidence.
    const onPath = new Set(orderedIds);
    const offPathIds = [
      ...new Set((issue.resourcesInvolved || []).map((resource) => resource.resourceId)),
    ]
      .filter((id) => !onPath.has(id))
      .slice(0, MAX_INVOLVED_LOOKUPS);
    if (offPathIds.length > 0) {
      try {
        involvedResources = await neptuneClient.getResources(offPathIds);
      } catch (neptuneError) {
        console.warn('Failed to fetch involved resources from Neptune:', neptuneError);
      }
    }

    const response: IssueDetailResponse = {
      ...issue,
      attackPath: {
        nodes: attackPathNodes,
        edges: attackPathEdges,
        entry,
      },
      involvedResources,
    };

    res.json(response);
  } catch (error) {
    console.error('Error getting issue:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get issue',
    });
  }
}

// The internet only when the first resource is actually reachable from it;
// the trusted outside principals when the path starts at a cross-account role.
async function pathEntry(first: GraphVertex | undefined): Promise<AttackPathEntry | undefined> {
  if (!first || first.label === 'Internet') return undefined;
  const props = first.properties;
  if (
    props.is_internet_exposed === true ||
    props.is_publicly_accessible === true ||
    props.endpoint_world_open === true
  ) {
    return { kind: 'internet' };
  }
  if (first.label === 'IamRole' && props.has_cross_account_trust === true) {
    // An empty list still marks the entry as outside, just not resolved.
    return {
      kind: 'trust',
      principals: outsidePrincipals(first, await neptuneClient.getTrustedPrincipals(first.id)),
    };
  }
  return undefined;
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
    });
  }
}

export async function getIssueSummary(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ counts: await issueStore.getSeverityStatusCounts() });
  } catch (error) {
    console.error('Error getting issue summary:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get issue summary',
    });
  }
}

export async function getIssueStats(req: Request, res: Response): Promise<void> {
  try {
    const openIssues = await issueStore.getOpenIssues();

    const stats = {
      total: openIssues.length,
      critical: openIssues.filter((i) => i.severity === 'critical').length,
      high: openIssues.filter((i) => i.severity === 'high').length,
      medium: openIssues.filter((i) => i.severity === 'medium').length,
      low: openIssues.filter((i) => i.severity === 'low').length,
      byTeam: {} as Record<string, number>,
      byRule: {} as Record<string, number>,
    };

    for (const issue of openIssues) {
      stats.byTeam[issue.owningTeam] = (stats.byTeam[issue.owningTeam] || 0) + 1;
      stats.byRule[issue.ruleId] = (stats.byRule[issue.ruleId] || 0) + 1;
    }

    res.json(stats);
  } catch (error) {
    console.error('Error getting issue stats:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get issue stats',
    });
  }
}

// When the rule runner last wrote issues and when it runs next. The last run
// is the trends row every run writes at the end; the next comes from the
// CronJob schedule and time zone the chart passes in.
export async function getIssueSchedule(_req: Request, res: Response): Promise<void> {
  try {
    const latest = await trendStore.getLatest('openIssuesBySeverity');
    const schedule = process.env.RULE_RUNNER_SCHEDULE;
    let nextRunAt: string | null = null;
    let intervalMinutes: number | null = null;
    if (schedule) {
      const [next, after] = nextRuns(
        schedule,
        process.env.RULE_RUNNER_TIMEZONE || 'UTC',
        new Date(),
        2
      );
      nextRunAt = next?.toISOString() ?? null;
      intervalMinutes =
        next && after ? Math.round((after.getTime() - next.getTime()) / 60_000) : null;
    }
    res.json({ lastRunAt: latest?.recordedAt ?? null, nextRunAt, intervalMinutes });
  } catch (error) {
    console.error('Error reading the issue schedule:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to read the issue schedule' });
  }
}
