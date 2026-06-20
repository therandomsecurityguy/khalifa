import type { Request, Response, NextFunction } from 'express';
import express from 'express';
import { listIssues, getIssue, getIssueCounts, getIssueStats } from './routes/issues';
import { findAttackPath, findAllAttackPaths } from './routes/attack-paths';
import { getResource, searchResources, getResourceGraph } from './routes/resources';
import {
  listFrameworks,
  getFrameworkSummary,
  getFrameworkControls,
  getControlDetails,
  getComplianceReport,
  getDriftReport,
} from './routes/compliance';
import { validateGremlinSelectors, validateArnParam } from './middleware/gremlin-validator';
import { authenticate } from './middleware/auth';
import { requireViewer, requireAdmin } from './middleware/rbac';
import {
  getEffectivePermissions,
  getEscalationPaths,
  getUnusedPermissions,
  getRightsizingRecommendation,
  getTrustGraph,
} from './routes/identity';

const app = express();

app.use(express.json());

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.use(validateGremlinSelectors);
app.use('/resources/:arn', validateArnParam);

app.use(authenticate);

app.get('/issues', requireViewer, listIssues);
app.get('/issues/counts', requireViewer, getIssueCounts);
app.get('/issues/stats', requireViewer, getIssueStats);
app.get('/issues/:id', requireViewer, getIssue);

app.get('/attack-paths', requireViewer, findAttackPath);
app.get('/attack-paths/all', requireViewer, findAllAttackPaths);

app.get('/resources/:arn', requireViewer, getResource);
app.get('/resources/search', requireViewer, searchResources);
app.get('/resources/graph', requireViewer, getResourceGraph);

app.get('/compliance/frameworks', requireViewer, listFrameworks);
app.get('/compliance/frameworks/:framework', requireViewer, getFrameworkSummary);
app.get('/compliance/frameworks/:framework/controls', requireViewer, getFrameworkControls);
app.get('/compliance/frameworks/:framework/controls/:controlId', requireViewer, getControlDetails);
app.get('/compliance/frameworks/:framework/report', requireViewer, getComplianceReport);
app.get('/compliance/frameworks/:framework/drift', requireViewer, getDriftReport);

app.get('/identity/effective-permissions/:principal', requireViewer, getEffectivePermissions);
app.get('/identity/escalation-paths', requireViewer, getEscalationPaths);
app.get('/identity/unused-permissions', requireViewer, getUnusedPermissions);
app.get('/identity/rightsizing/:principal', requireViewer, getRightsizingRecommendation);
app.get('/identity/trust-graph', requireViewer, getTrustGraph);

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    code: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
  });
});

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(`API service listening on port ${PORT}`);
});

export default app;
