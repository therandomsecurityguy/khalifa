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

const app = express();

app.use(express.json());

app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

app.get('/issues', listIssues);
app.get('/issues/counts', getIssueCounts);
app.get('/issues/stats', getIssueStats);
app.get('/issues/:id', getIssue);

app.get('/attack-paths', findAttackPath);
app.get('/attack-paths/all', findAllAttackPaths);

app.get('/resources/:arn', getResource);
app.get('/resources/search', searchResources);
app.get('/resources/graph', getResourceGraph);

app.get('/compliance/frameworks', listFrameworks);
app.get('/compliance/frameworks/:framework', getFrameworkSummary);
app.get('/compliance/frameworks/:framework/controls', getFrameworkControls);
app.get('/compliance/frameworks/:framework/controls/:controlId', getControlDetails);
app.get('/compliance/frameworks/:framework/report', getComplianceReport);
app.get('/compliance/frameworks/:framework/drift', getDriftReport);

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
