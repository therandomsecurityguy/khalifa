import type { Request, Response } from 'express';
import { ComplianceService } from '../services/compliance-service';
import {
  type ComplianceFramework,
  type ComplianceControlResult,
  type ComplianceReport,
  type ComplianceEvidence,
} from '@khalifa/risk-engine';

const neptuneEndpoint = process.env.NEPTUNE_ENDPOINT || '';
const complianceService = new ComplianceService({
  neptuneEndpoint,
  evidenceTableName: process.env.EVIDENCE_TABLE,
  reportsTableName: process.env.REPORTS_TABLE,
});

const VALID_FRAMEWORKS: ComplianceFramework[] = ['CIS_AWS_FOUNDATIONS', 'SOC2', 'ISO27001'];

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
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getFrameworkSummary(req: Request, res: Response): Promise<void> {
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
      framework: summary.framework,
      version: summary.version,
      totalControls: summary.totalControls,
      automatedControls: summary.automatedControls,
      manualControls: summary.manualControls,
      coveragePercent: summary.coveragePercent,
      lastAssessment: summary.lastAssessment,
      sections: [],
      summary: summary,
    });
  } catch (error) {
    console.error('Error getting framework summary:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get framework summary',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getFrameworkControls(req: Request, res: Response): Promise<void> {
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
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getControlDetails(req: Request, res: Response): Promise<void> {
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
      relatedIssues: result.control.relatedRules.map((ruleId: string) => ({
        ruleId,
        severity: result.control.severity,
        status: 'open',
      })),
    });
  } catch (error) {
    console.error('Error getting control details:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get control details',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getComplianceReport(req: Request, res: Response): Promise<void> {
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
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getDriftReport(req: Request, res: Response): Promise<void> {
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
      details: error instanceof Error ? error.message : undefined,
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
    c.issues.join('; '),
  ]);

  return [headers.join(','), ...rows.map((r: string[]) => r.map((v) => `"${v}"`).join(','))].join(
    '\n'
  );
}
