import { SEVERITY_RANK, type PlanSeverity } from './catalogue';
import type { PlanFinding } from './analyzers';

export interface PlanReport {
  minSeverity: PlanSeverity;
  findings: PlanFinding[];
  /** Findings at or above the minimum severity: the gate's failures. */
  failing: PlanFinding[];
}

// Plan analysis states its own coverage: it reads the plan, not the graph, so
// the counts carry none of collection's context (data classification, which
// accounts are collected, the real topology).
export const PLAN_COVERAGE = {
  level: 'plan-time' as const,
  note: 'Evaluated from the plan; the collected graph would add data classification, collected-account context and topology.',
};

export function buildReport(findings: PlanFinding[], minSeverity: PlanSeverity): PlanReport {
  return {
    minSeverity,
    findings,
    failing: findings.filter(
      (finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[minSeverity]
    ),
  };
}

export function formatReport(report: PlanReport): string {
  const lines: string[] = [];
  if (report.findings.length === 0) {
    lines.push('No findings: the plan introduces no risk the catalogue recognizes.');
  }
  for (const finding of report.findings) {
    const label = finding.ruleId ?? 'no-rule';
    lines.push(`[${finding.severity.toUpperCase()}] ${label} ${finding.ruleName}`);
    lines.push(`  ${finding.address}: ${finding.detail}`);
    lines.push(`  path: ${finding.predictedPath}`);
  }
  lines.push(
    `${report.findings.length} finding${report.findings.length === 1 ? '' : 's'}, ` +
      `${report.failing.length} at or above ${report.minSeverity}.`
  );
  lines.push(`Coverage: ${PLAN_COVERAGE.note}`);
  return lines.join('\n');
}

export function reportJson(report: PlanReport): string {
  return JSON.stringify(
    {
      minSeverity: report.minSeverity,
      coverage: PLAN_COVERAGE,
      findings: report.findings,
      summary: { total: report.findings.length, failing: report.failing.length },
    },
    null,
    2
  );
}
