import { readFileSync } from 'node:fs';
import { analyzePlan } from './analyzers';
import { isSeverity, type PlanSeverity } from './catalogue';
import { PlanParseError, parsePlan } from './plan';
import { buildReport, formatReport, reportJson, type PlanReport } from './report';

export interface RiskPlanResult {
  report: PlanReport;
  output: string;
  /** 0 when no finding reaches the minimum severity, 1 when the gate fails. */
  exitCode: number;
}

export interface RiskPlanOptions {
  planText: string;
  minSeverity?: PlanSeverity;
  json?: boolean;
}

// The CI gate's core: parse a `terraform show -json` document, predict which
// catalogue rules the planned changes would feed, and fail when any reach the
// minimum severity. Read-only — nothing here touches AWS or the graph.
export function runRiskPlan(options: RiskPlanOptions): RiskPlanResult {
  const minSeverity = options.minSeverity ?? 'high';
  const report = buildReport(analyzePlan(parsePlan(options.planText)), minSeverity);
  return {
    report,
    output: options.json ? reportJson(report) : formatReport(report),
    exitCode: report.failing.length > 0 ? 1 : 0,
  };
}

export interface ParsedArgs {
  planPath?: string;
  minSeverity: PlanSeverity;
  json: boolean;
  error?: string;
}

const USAGE =
  'Usage: npm run risk:plan -- <plan.json> [--min-severity low|medium|high|critical] [--json]\n' +
  'Produce the plan file with: terraform plan -out plan.out && terraform show -json plan.out > plan.json';

export function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = { minSeverity: 'high', json: false };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--json') {
      parsed.json = true;
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
  if (!parsed.planPath) return { ...parsed, error: 'A plan file path is required' };
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
      planText: io.readFile(parsed.planPath!, 'utf8'),
      minSeverity: parsed.minSeverity,
      json: parsed.json,
    });
    io.out(result.output);
    return result.exitCode;
  } catch (error) {
    if (error instanceof PlanParseError) {
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
