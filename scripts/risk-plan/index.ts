import { readFileSync } from 'node:fs';
import { analyzePlan, finalizeFindings, sortFindings, type PlanFinding } from './analyzers';
import { isSeverity, type PlanSeverity } from './catalogue';
import { HelmValuesParseError, helmValuesFindings } from './helm-values';
import { PolicyParseError, standalonePolicyFindings } from './iam-policies';
import { PlanParseError, parsePlan } from './plan';
import { buildReport, formatReport, reportJson, type PlanReport } from './report';

export interface RiskPlanResult {
  report: PlanReport;
  output: string;
  /** 0 when no finding reaches the minimum severity, 1 when the gate fails. */
  exitCode: number;
}

export interface RiskPlanOptions {
  planText?: string;
  /** A standalone IAM policy document (the proposed `after`), for flows outside Terraform. */
  policyText?: string;
  /** The policy document as it exists today: with it, only newly granted risk is reported. */
  policyBeforeText?: string;
  /** A Helm values file for the chart: ingress that reaches the internet is flagged. */
  helmValuesText?: string;
  minSeverity?: PlanSeverity;
  json?: boolean;
}

// The CI gate's core: parse a `terraform show -json` document and/or standalone
// IAM policy / Helm values inputs, predict which catalogue rules the changes
// would feed (IAM policies are parsed with the same parser the CIEM evaluator
// runs; with a before-policy the checks are a diff), and fail when any reach
// the minimum severity. Read-only — nothing here touches AWS or the graph.
export function runRiskPlan(options: RiskPlanOptions): RiskPlanResult {
  const minSeverity = options.minSeverity ?? 'high';
  const findings: PlanFinding[] = [];
  if (options.planText !== undefined) {
    findings.push(...analyzePlan(parsePlan(options.planText)));
  }
  if (options.policyText !== undefined) {
    findings.push(
      ...finalizeFindings(standalonePolicyFindings(options.policyText, options.policyBeforeText))
    );
  }
  if (options.helmValuesText !== undefined) {
    findings.push(...finalizeFindings(helmValuesFindings(options.helmValuesText)));
  }
  const report = buildReport(sortFindings(findings), minSeverity);
  return {
    report,
    output: options.json ? reportJson(report) : formatReport(report),
    exitCode: report.failing.length > 0 ? 1 : 0,
  };
}

export interface ParsedArgs {
  planPath?: string;
  policyPath?: string;
  policyBeforePath?: string;
  helmValuesPath?: string;
  minSeverity: PlanSeverity;
  json: boolean;
  error?: string;
}

const USAGE =
  'Usage: npm run risk:plan -- <plan.json> [--policy after.json] [--policy-before before.json]\n' +
  '                             [--helm-values values.yaml] [--min-severity low|medium|high|critical] [--json]\n' +
  'At least one of <plan.json>, --policy or --helm-values is required.\n' +
  'Produce the plan file with: terraform plan -out plan.out && terraform show -json plan.out > plan.json';

export function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { minSeverity: 'high', json: false };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--json') {
      parsed.json = true;
    } else if (arg === '--policy') {
      const value = argv[++index];
      if (!value || value.startsWith('-'))
        return { ...parsed, error: '--policy needs a file path' };
      parsed.policyPath = value;
    } else if (arg === '--policy-before') {
      const value = argv[++index];
      if (!value || value.startsWith('-')) {
        return { ...parsed, error: '--policy-before needs a file path' };
      }
      parsed.policyBeforePath = value;
    } else if (arg === '--helm-values') {
      const value = argv[++index];
      if (!value || value.startsWith('-')) {
        return { ...parsed, error: '--helm-values needs a file path' };
      }
      parsed.helmValuesPath = value;
    } else if (arg === '--min-severity') {
      const value = argv[++index];
      if (!value || !isSeverity(value)) {
        return { ...parsed, error: '--min-severity must be low, medium, high or critical' };
      }
      parsed.minSeverity = value;
    } else if (arg.startsWith('--min-severity=')) {
      const value = arg.slice('--min-severity='.length);
      if (!isSeverity(value)) {
        return { ...parsed, error: '--min-severity must be low, medium, high or critical' };
      }
      parsed.minSeverity = value;
    } else if (arg.startsWith('-')) {
      return { ...parsed, error: `Unknown option: ${arg}` };
    } else if (parsed.planPath === undefined) {
      parsed.planPath = arg;
    } else {
      return { ...parsed, error: `Unexpected argument: ${arg}` };
    }
  }
  if (parsed.policyBeforePath && !parsed.policyPath) {
    return { ...parsed, error: '--policy-before only applies together with --policy' };
  }
  if (!parsed.planPath && !parsed.policyPath && !parsed.helmValuesPath) {
    return { ...parsed, error: 'A plan file, --policy or --helm-values input is required' };
  }
  return parsed;
}

export interface MainIo {
  out: (line: string) => void;
  err: (line: string) => void;
  readFile: (path: string, encoding: 'utf8') => string;
}

// 0 ok, 1 gate failure, 2 usage or plan-file error.
export function main(argv: string[], io: MainIo): number {
  const parsed = parseArgs(argv);
  if (parsed.error) {
    io.err(parsed.error);
    io.err(USAGE);
    return 2;
  }
  try {
    const result = runRiskPlan({
      ...(parsed.planPath !== undefined ? { planText: io.readFile(parsed.planPath, 'utf8') } : {}),
      ...(parsed.policyPath !== undefined
        ? { policyText: io.readFile(parsed.policyPath, 'utf8') }
        : {}),
      ...(parsed.policyBeforePath !== undefined
        ? { policyBeforeText: io.readFile(parsed.policyBeforePath, 'utf8') }
        : {}),
      ...(parsed.helmValuesPath !== undefined
        ? { helmValuesText: io.readFile(parsed.helmValuesPath, 'utf8') }
        : {}),
      minSeverity: parsed.minSeverity,
      json: parsed.json,
    });
    io.out(result.output);
    return result.exitCode;
  } catch (error) {
    if (
      error instanceof PlanParseError ||
      error instanceof PolicyParseError ||
      error instanceof HelmValuesParseError
    ) {
      io.err(error.message);
      return 2;
    }
    throw error;
  }
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2), {
    out: console.log,
    err: console.error,
    readFile: readFileSync,
  });
}
