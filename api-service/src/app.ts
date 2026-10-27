import type { Request, Response, NextFunction } from 'express';
import express from 'express';
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
import { requireViewer, requireAnalyst, requireTrustCenterSync } from './middleware/rbac';
import { apiRateLimiter, expensiveRateLimiter } from './middleware/rate-limit';
import { metricsMiddleware, renderMetrics } from './observability/metrics';
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

app.use((_req: Request, res: Response, next: NextFunction) => {
  const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const origin = _req.headers.origin;
  if (origin && (allowedOrigins.length === 0 || allowedOrigins.includes(origin))) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  if (_req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
});

const liveness = (_req: Request, res: Response): void => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
};
app.get('/health', liveness);
app.get('/livez', liveness);

app.get('/readyz', async (_req: Request, res: Response) => {
  try {
    const result = await getReadinessService().check();
    res.status(result.status === 'ready' ? 200 : 503).json({
      ...result,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Readiness check failed:', error);
    res.status(503).json({ status: 'not_ready', timestamp: new Date().toISOString() });
  }
});

app.get('/metrics', (_req: Request, res: Response) => {
  res.type('text/plain; version=0.0.4; charset=utf-8').send(renderMetrics());
});

app.use(authenticate);
app.use(express.json({ limit: '32kb' }));
app.use(apiRateLimiter);
app.use(validateGremlinSelectors);

app.get('/session', requireViewer, getSession);
app.get('/rules', requireViewer, listRules);
app.get('/rules/quality', requireViewer, getRuleQuality);
app.get('/rules/:id', requireViewer, getRule);
app.get('/issues', requireViewer, listIssues);
app.get('/issues/counts', requireViewer, getIssueCounts);
app.get('/issues/stats', requireViewer, getIssueStats);
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
  '/secrets/:arn(*)',
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
app.get('/resources/:arn(*)', validateArnPathParam('arn'), requireViewer, getResource);

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
app.get('/identity/least-privilege/summary', requireViewer, getLeastPrivilegeSummary);
app.get(
  '/identity/least-privilege/:accountId/:principalArn(*)',
  validateArnPathParam('principalArn'),
  requireViewer,
  getLeastPrivilegeFinding
);
app.get(
  '/identity/effective-permissions/:principal(*)',
  validateArnPathParam('principal'),
  requireViewer,
  expensiveRateLimiter,
  getEffectivePermissions
);
app.get(
  '/identity/rightsizing/:principal(*)',
  validateArnPathParam('principal'),
  requireViewer,
  expensiveRateLimiter,
  getRightsizingRecommendation
);

app.get('/trends', requireViewer, listTrendMetrics);
app.get('/trends/:metric', requireViewer, getTrend);

app.get('/integrations/status', requireViewer, getIntegrationsStatus);
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
