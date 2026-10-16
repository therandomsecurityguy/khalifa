import type { Request, Response } from 'express';
import { ComplianceService } from '../services/compliance-service';
import {
  DynamoDBIssueRepository,
  getRuleById,
  type ComplianceFramework,
  type ComplianceControlResult,
  type ComplianceReport,
  type ComplianceEvidence,
} from '@khalifa/risk-engine';
import type { Severity } from '../types';

const complianceService = new ComplianceService({
  evidenceTableName: process.env.EVIDENCE_TABLE,
  reportsTableName: process.env.REPORTS_TABLE,
});

const issueStore = new DynamoDBIssueRepository();

// Issues listed per rule on a control page; the count is always the full total.
const RELATED_ISSUES_SHOWN = 5;
const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

interface RelatedRuleIssues {
  ruleId: string;
  ruleName: string;
  // null when the issue store could not be read: unknown, not zero.
  openCount: number | null;
  highestSeverity: Severity | null;
  issues: { id: string; severity: Severity; resourceId: string; resourceName?: string }[];
}

// A control's related rules and their actual open issues. The route previously
// returned every related rule as `status: 'open'` with the control's severity,
// whether or not the rule had a single finding.
async function relatedRuleIssues(ruleIds: string[]): Promise<RelatedRuleIssues[]> {
  const settled = await Promise.allSettled(ruleIds.map((id) => issueStore.getOpenIssuesByRule(id)));
  return ruleIds.map((ruleId, index) => {
    const ruleName = getRuleById(ruleId)?.name ?? ruleId;
    const outcome = settled[index];
    if (outcome.status === 'rejected') {
      console.error(`Error reading open issues for ${ruleId}:`, outcome.reason);
      return { ruleId, ruleName, openCount: null, highestSeverity: null, issues: [] };
    }
    const open = [...outcome.value].sort(
      (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || b.riskScore - a.riskScore
    );
    return {
      ruleId,
      ruleName,
      openCount: open.length,
      highestSeverity: open[0]?.severity ?? null,
      issues: open.slice(0, RELATED_ISSUES_SHOWN).map((issue) => ({
        id: issue.id,
        severity: issue.severity,
        resourceId: issue.resourcesInvolved[0]?.resourceId ?? '',
        resourceName: issue.resourcesInvolved[0]?.resourceName,
      })),
    };
  });
}

const VALID_FRAMEWORKS: ComplianceFramework[] = ['CIS_AWS_FOUNDATIONS', 'KHALIFA_BASELINE'];

function isValidFramework(f: string): f is ComplianceFramework {
  return VALID_FRAMEWORKS.includes(f as ComplianceFramework);
}

export async function listFrameworks(_req: Request, res: Response): Promise<void> {
  try {
    const summaries = await complianceService.listFrameworks();
    res.json({
      frameworks: summaries,
      totalFrameworks: summaries.length,
    });
  } catch (error) {
    console.error('Error listing frameworks:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to list frameworks',
    });
  }
}

export async function getFrameworkSummary(
  req: Request<{ framework: string }>,
  res: Response
): Promise<void> {
  try {
    const { framework } = req.params;
    if (!isValidFramework(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: `Invalid framework. Must be one of: ${VALID_FRAMEWORKS.join(', ')}`,
      });
      return;
    }
    const summary = await complianceService.getFrameworkSummary(framework);
    res.json({
      ...summary,
      sections: [],
    });
  } catch (error) {
    console.error('Error getting framework summary:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get framework summary',
    });
  }
}

export async function getFrameworkControls(
  req: Request<{ framework: string }>,
  res: Response
): Promise<void> {
  try {
    const { framework } = req.params;
    if (!isValidFramework(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: `Invalid framework. Must be one of: ${VALID_FRAMEWORKS.join(', ')}`,
      });
      return;
    }
    const report = await complianceService.getLatestReport(framework);
    if (!report) {
      res.json({
        framework,
        totalControls: 0,
        controls: [],
      });
      return;
    }
    const controls = report.controls.map((r) => ({
      id: r.control.id,
      title: r.control.title,
      section: r.control.section,
      severity: r.control.severity,
      automated: r.control.automated,
      status: r.status,
      relatedRules: r.control.relatedRules,
      lastEvaluated: r.lastEvaluated,
      regionsEvaluated: r.regionsEvaluated,
    }));
    res.json({
      framework,
      totalControls: controls.length,
      controls,
    });
  } catch (error) {
    console.error('Error getting framework controls:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get framework controls',
    });
  }
}

export async function getControlDetails(
  req: Request<{ framework: string; controlId: string }>,
  res: Response
): Promise<void> {
  try {
    const { framework, controlId } = req.params;
    if (!isValidFramework(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: 'Invalid framework',
      });
      return;
    }
    const result = await complianceService.getControlResult(controlId, framework);
    const evidence: ComplianceEvidence[] = result ? result.evidence : [];

    if (!result) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `Control ${controlId} not found or not evaluated in ${framework}`,
      });
      return;
    }

    res.json({
      id: result.control.id,
      title: result.control.title,
      section: result.control.section,
      severity: result.control.severity,
      automated: result.control.automated,
      framework,
      description: result.control.description,
      status: result.status,
      lastEvaluated: result.lastEvaluated,
      remediationHint: result.control.remediationGuidance,
      evidenceRequirements: result.control.evidenceRequirements,
      evidence,
      regionsEvaluated: result.regionsEvaluated,
      relatedIssues: await relatedRuleIssues(result.control.relatedRules),
    });
  } catch (error) {
    console.error('Error getting control details:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get control details',
    });
  }
}

export async function getComplianceReport(
  req: Request<{ framework: string }>,
  res: Response
): Promise<void> {
  try {
    const { framework } = req.params;
    const { format } = req.query;

    if (!isValidFramework(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: 'Invalid framework',
      });
      return;
    }

    const report = await complianceService.getLatestReport(framework);
    if (!report) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `No assessment found for ${framework}`,
      });
      return;
    }

    if (format === 'csv') {
      const csv = generateCSVReport(report);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${framework}-report-${Date.now()}.csv"`
      );
      res.send(csv);
      return;
    }

    res.json(report);
  } catch (error) {
    console.error('Error generating compliance report:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to generate compliance report',
    });
  }
}

export async function getDriftReport(
  req: Request<{ framework: string }>,
  res: Response
): Promise<void> {
  try {
    const { framework } = req.params;
    if (!isValidFramework(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: 'Invalid framework',
      });
      return;
    }

    const report = await complianceService.getLatestReport(framework);
    if (!report) {
      res.json({
        framework,
        generatedAt: new Date().toISOString(),
        totalDriftItems: 0,
        criticalDrift: 0,
        highDrift: 0,
        mediumDrift: 0,
        lowDrift: 0,
        driftItems: [],
      });
      return;
    }

    const failedAutomated = report.controls.filter(
      (c: ComplianceControlResult) => c.status === 'FAIL' && c.control.automated
    );

    const driftItems = failedAutomated.map((c) => ({
      controlId: c.control.id,
      controlTitle: c.control.title,
      section: c.control.section,
      severity: c.control.severity,
      detectedAt: c.lastEvaluated,
      description: `Control ${c.control.id} (${c.control.title}) is currently failing`,
      relatedRules: c.control.relatedRules,
      remediation: c.control.remediationGuidance,
    }));

    res.json({
      framework,
      generatedAt: new Date().toISOString(),
      totalDriftItems: driftItems.length,
      criticalDrift: driftItems.filter((d) => d.severity === 'critical').length,
      highDrift: driftItems.filter((d) => d.severity === 'high').length,
      mediumDrift: driftItems.filter((d) => d.severity === 'medium').length,
      lowDrift: driftItems.filter((d) => d.severity === 'low').length,
      driftItems,
    });
  } catch (error) {
    console.error('Error getting drift report:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get drift report',
    });
  }
}

function generateCSVReport(report: ComplianceReport): string {
  const headers = [
    'Control ID',
    'Title',
    'Section',
    'Severity',
    'Automated',
    'Status',
    'Last Evaluated',
    'Regions Evaluated',
    'Issues',
  ];
  const rows = report.controls.map((c) => [
    c.control.id,
    c.control.title,
    c.control.section,
    c.control.severity,
    c.control.automated ? 'Yes' : 'No',
    c.status,
    c.lastEvaluated,
    c.regionsEvaluated?.join(' ') ?? '',
    c.issues.join('; '),
  ]);

  return [headers.join(','), ...rows.map((r: string[]) => r.map((v) => `"${v}"`).join(','))].join(
    '\n'
  );
}
