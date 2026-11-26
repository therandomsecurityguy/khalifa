import type { Request, Response, NextFunction } from 'express';
import express from 'express';
import openapiDocument from './openapi.json';
import {
  listIssues,
  getIssue,
  getIssueCounts,
  getIssueStats,
  getIssueSummary,
  getIssueSchedule,
} from './routes/issues';
import { listAccounts, searchAttackPaths, simulateAttackPaths } from './routes/attack-paths';
import { listAttackScenarios, runAttackScenario } from './routes/attack-scenarios';
import { getDataSources } from './routes/data-sources';
import { createServiceToken, listServiceTokens, revokeServiceToken } from './routes/service-tokens';
import { getAiAgent, getAiBom, getAiInventory, getShadowAiAnomalies } from './routes/ai';
import {
  createAiUseCase,
  deleteAiUseCase,
  getAiUseCase,
  getAiUseCaseCoverage,
  listAiUseCases,
  updateAiUseCase,
} from './routes/ai-use-cases';
import {
  getResource,
  searchResources,
  getResourceGraph,
  listResourceLabels,
  listResourceProperties,
  listPropertyValues,
} from './routes/resources';
import {
  listFrameworks,
  getFrameworkSummary,
  getFrameworkControls,
  getControlDetails,
  getComplianceReport,
  getDriftReport,
} from './routes/compliance';
import { validateGremlinSelectors, validateArnPathParam } from './middleware/gremlin-validator';
import { authenticate } from './middleware/auth';
import {
  requireViewer,
  requireAnalyst,
  requireAdmin,
  requireTrustCenterSync,
} from './middleware/rbac';
import { apiRateLimiter, expensiveRateLimiter, probeRateLimiter } from './middleware/rate-limit';
import { corsMiddleware, originGuard } from './middleware/origin-guard';
import { metricsMiddleware, renderMetrics, buildInfo } from './observability/metrics';
import compression from 'compression';
import helmet from 'helmet';
import { getReadinessService } from './services/readiness';
import {
  getEffectivePermissions,
  getEscalationPaths,
  getUnusedPermissions,
  getRightsizingRecommendation,
  getTrustGraph,
  getLeastPrivilegeFindings,
  getLeastPrivilegeFinding,
  getLeastPrivilegeSummary,
} from './routes/identity';
import { getTrend, listTrendMetrics } from './routes/trends';
import { getIntegrationsStatus, suppressIssue, reopenIssue } from './routes/integrations';
import { getSession } from './routes/session';
import { getRule, getRuleQuality, listRules } from './routes/rules';
import { getPublishableRequirements } from './routes/trust-center';
import { getSecret, listSecretReaderCounts, listSecrets } from './routes/secrets';

const app = express();
app.disable('x-powered-by');

app.use(metricsMiddleware);
app.use(
  helmet({
    // The API serves JSON only; CSP is enforced at the edge and in the UI.
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);
app.use(compression());

app.use(corsMiddleware);

const liveness = (_req: Request, res: Response): void => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
};
app.get('/health', liveness);
app.get('/livez', liveness);

// Readiness performs a Neptune query and a DynamoDB read, so the result is
// cached for a few seconds: a scrape loop must not become backend load, and a
// transient failure still surfaces on the next window.
const READINESS_CACHE_MS = 5_000;
let readinessCache: {
  at: number;
  result: Awaited<ReturnType<ReturnType<typeof getReadinessService>['check']>>;
} | null = null;

app.get('/readyz', probeRateLimiter, async (_req: Request, res: Response) => {
  try {
    const now = Date.now();
    if (!readinessCache || now - readinessCache.at >= READINESS_CACHE_MS) {
      readinessCache = { at: now, result: await getReadinessService().check() };
    }
    res.status(readinessCache.result.status === 'ready' ? 200 : 503).json({
      ...readinessCache.result,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Readiness check failed:', error);
    res.status(503).json({ status: 'not_ready', timestamp: new Date().toISOString() });
  }
});

app.get('/metrics', probeRateLimiter, (_req: Request, res: Response) => {
  res.type('text/plain; version=0.0.4; charset=utf-8').send(renderMetrics());
});

// The API description itself: unauthenticated like the probes, and pinned to
// the registered routes by openapi.test.ts.
app.get('/openapi.json', (_req: Request, res: Response) => {
  res.json(openapiDocument);
});

app.get('/version', (_req: Request, res: Response) => {
  res.json(buildInfo());
});

app.use(authenticate);
app.use(express.json({ limit: '32kb' }));
app.use(apiRateLimiter);
app.use(originGuard);
app.use(validateGremlinSelectors);

app.get('/session', requireViewer, getSession);
app.get('/rules', requireViewer, listRules);
app.get('/rules/quality', requireViewer, getRuleQuality);
app.get('/rules/:id', requireViewer, getRule);
app.get('/issues', requireViewer, listIssues);
app.get('/issues/counts', requireViewer, getIssueCounts);
app.get('/issues/stats', requireViewer, expensiveRateLimiter, getIssueStats);
app.get('/issues/summary', requireViewer, getIssueSummary);
app.get('/issues/schedule', requireViewer, getIssueSchedule);
app.get('/issues/:id', requireViewer, getIssue);

app.get('/attack-paths/search', requireViewer, expensiveRateLimiter, searchAttackPaths);
app.get('/attack-paths/simulate', requireViewer, expensiveRateLimiter, simulateAttackPaths);
app.get('/attack-scenarios', requireViewer, listAttackScenarios);
app.get('/attack-scenarios/:id', requireViewer, expensiveRateLimiter, runAttackScenario);
app.get('/accounts', requireViewer, listAccounts);
app.get('/data-sources', requireViewer, expensiveRateLimiter, getDataSources);
app.get('/secrets', requireViewer, expensiveRateLimiter, listSecrets);
app.get('/secrets/reader-counts', requireViewer, expensiveRateLimiter, listSecretReaderCounts);
app.get(
  '/secrets/*arn',
  validateArnPathParam('arn'),
  requireViewer,
  expensiveRateLimiter,
  getSecret
);

app.get('/resources/search', requireViewer, searchResources);
app.get('/resources/labels', requireViewer, expensiveRateLimiter, listResourceLabels);
app.get('/resources/properties', requireViewer, expensiveRateLimiter, listResourceProperties);
app.get('/resources/values', requireViewer, expensiveRateLimiter, listPropertyValues);
app.get('/resources/graph', requireViewer, expensiveRateLimiter, getResourceGraph);
app.get(
  '/resources/*arn',
  validateArnPathParam('arn'),
  requireViewer,
  expensiveRateLimiter,
  getResource
);

app.get('/ai/inventory', requireViewer, expensiveRateLimiter, getAiInventory);
app.get('/ai/bom', requireViewer, expensiveRateLimiter, getAiBom);
app.get('/ai/shadow', requireViewer, expensiveRateLimiter, getShadowAiAnomalies);
app.get(
  '/ai/agents/*arn',
  validateArnPathParam('arn'),
  requireViewer,
  expensiveRateLimiter,
  getAiAgent
);

app.get('/ai/use-cases', requireViewer, listAiUseCases);
app.get('/ai/use-cases/coverage', requireViewer, expensiveRateLimiter, getAiUseCaseCoverage);
app.post('/ai/use-cases', requireAnalyst, createAiUseCase);
app.get('/ai/use-cases/:id', requireViewer, getAiUseCase);
app.put('/ai/use-cases/:id', requireAnalyst, updateAiUseCase);
app.delete('/ai/use-cases/:id', requireAnalyst, deleteAiUseCase);

app.get('/compliance/frameworks', requireViewer, listFrameworks);
app.get('/compliance/frameworks/:framework/controls', requireViewer, getFrameworkControls);
app.get('/compliance/frameworks/:framework/controls/:controlId', requireViewer, getControlDetails);
app.get(
  '/compliance/frameworks/:framework/report',
  requireViewer,
  expensiveRateLimiter,
  getComplianceReport
);
app.get(
  '/compliance/frameworks/:framework/drift',
  requireViewer,
  expensiveRateLimiter,
  getDriftReport
);
app.get('/compliance/frameworks/:framework', requireViewer, getFrameworkSummary);
app.get(
  '/compliance/reconciliation/publishable',
  requireTrustCenterSync,
  getPublishableRequirements
);

app.get('/identity/escalation-paths', requireViewer, getEscalationPaths);
app.get('/identity/unused-permissions', requireViewer, getUnusedPermissions);
app.get('/identity/trust-graph', requireViewer, getTrustGraph);
app.get('/identity/least-privilege', requireViewer, getLeastPrivilegeFindings);
app.get(
  '/identity/least-privilege/summary',
  requireViewer,
  expensiveRateLimiter,
  getLeastPrivilegeSummary
);
app.get(
  '/identity/least-privilege/:accountId/*principalArn',
  validateArnPathParam('principalArn'),
  requireViewer,
  getLeastPrivilegeFinding
);
app.get(
  '/identity/effective-permissions/*principal',
  validateArnPathParam('principal'),
  requireViewer,
  expensiveRateLimiter,
  getEffectivePermissions
);
app.get(
  '/identity/rightsizing/*principal',
  validateArnPathParam('principal'),
  requireViewer,
  expensiveRateLimiter,
  getRightsizingRecommendation
);

app.get('/trends', requireViewer, listTrendMetrics);
app.get('/trends/:metric', requireViewer, getTrend);

app.get('/integrations/status', requireViewer, getIntegrationsStatus);
app.get('/service-tokens', requireAdmin, listServiceTokens);
app.post('/service-tokens', requireAdmin, createServiceToken);
app.delete('/service-tokens/:id', requireAdmin, revokeServiceToken);
app.post('/issues/:id/suppress', requireAnalyst, suppressIssue);
app.post('/issues/:id/reopen', requireAnalyst, reopenIssue);

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    code: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
  });
});

export default app;
