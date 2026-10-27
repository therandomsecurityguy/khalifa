import { runRiskPlan, parseArgs, main, type MainIo } from './index';

function change(address: string, type: string, after: Record<string, unknown>) {
  return {
    address,
    mode: 'managed',
    type,
    name: address,
    change: { actions: ['create'], before: null, after },
  };
}

const worldOpenSsh = change('aws_security_group.app', 'aws_security_group', {
  ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }],
});

const rootTrust = change('aws_iam_role.vendor', 'aws_iam_role', {
  assume_role_policy: JSON.stringify({
    Statement: [
      {
        Effect: 'Allow',
        Principal: { AWS: 'arn:aws:iam::222233334444:root' },
        Action: 'sts:AssumeRole',
      },
    ],
  }),
});

const planText = (changes: unknown[]) => JSON.stringify({ resource_changes: changes });

describe('runRiskPlan', () => {
  it('fails the gate on a world-open security group and an account-root trust, naming both', () => {
    const result = runRiskPlan({ planText: planText([worldOpenSsh, rootTrust]) });

    expect(result.exitCode).toBe(1);
    expect(result.output).toContain('RULE-002 Security Groups Open to the Internet on SSH/RDP');
    expect(result.output).toContain('Coverage: Evaluated from the plan');
    expect(result.output).toContain(
      'RULE-006 Cross-Account IAM Trust with Wildcard Resource Access'
    );
    expect(result.output).toContain('path: Internet → aws_security_group.app → attached resources');
    expect(result.output).toContain('path: ExternalAccount → TRUSTS → aws_iam_role.vendor');
    expect(result.report.failing).toHaveLength(2);
  });

  it('still lists lower findings but only fails at or above the minimum severity', () => {
    const result = runRiskPlan({
      planText: planText([worldOpenSsh]),
      minSeverity: 'critical',
    });

    expect(result.report.findings).toHaveLength(1);
    expect(result.report.failing).toEqual([]);
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('0 at or above critical.');
  });

  it('passes and says so when the plan introduces nothing the catalogue recognizes', () => {
    const result = runRiskPlan({ planText: planText([]) });
    expect(result.exitCode).toBe(0);
    expect(result.output).toContain('No findings');
  });

  it('emits machine-readable output with --json', () => {
    const result = runRiskPlan({ planText: planText([worldOpenSsh]), json: true });
    const body = JSON.parse(result.output);
    expect(body.summary).toEqual({ total: 1, failing: 1 });
    expect(body.findings[0]).toMatchObject({ ruleId: 'RULE-002' });
    expect(body.minSeverity).toBe('high');
    expect(body.coverage).toMatchObject({ level: 'plan-time' });
  });
});

describe('parseArgs', () => {
  it('defaults to high and takes the path positionally', () => {
    expect(parseArgs(['plan.json'])).toEqual({
      planPath: 'plan.json',
      minSeverity: 'high',
      json: false,
    });
  });

  it('accepts both min-severity forms and --json', () => {
    expect(parseArgs(['--min-severity', 'critical', 'plan.json', '--json'])).toMatchObject({
      minSeverity: 'critical',
      json: true,
    });
    expect(parseArgs(['plan.json', '--min-severity=low'])).toMatchObject({ minSeverity: 'low' });
  });

  it.each([
    [[], 'A plan file path is required'],
    [['--min-severity', 'potato', 'plan.json'], '--min-severity must be'],
    [['--verbose', 'plan.json'], 'Unknown option: --verbose'],
    [['a.json', 'b.json'], 'Unexpected argument: b.json'],
  ])('rejects %j', (argv, message) => {
    const parsed = parseArgs(argv as string[]);
    expect(parsed.error).toContain(message);
  });
});

describe('main', () => {
  function io(planTextValue: string) {
    const out: string[] = [];
    const err: string[] = [];
    const io: MainIo = {
      out: (line) => out.push(line),
      err: (line) => err.push(line),
      readFile: () => planTextValue,
    };
    return { io, out, err };
  }

  it('returns the gate exit code and prints the report', () => {
    const { io: streams, out } = io(planText([worldOpenSsh]));
    expect(main(['plan.json'], streams)).toBe(1);
    expect(out.join('\n')).toContain('RULE-002');
  });

  it('returns 2 with usage on bad arguments', () => {
    const { io: streams, err } = io('{}');
    expect(main([], streams)).toBe(2);
    expect(err.join('\n')).toContain('Usage:');
  });

  it('returns 2 with the parse message when the file is not a plan', () => {
    const { io: streams, err } = io('not json');
    expect(main(['plan.json'], streams)).toBe(2);
    expect(err.join('\n')).toContain('not valid JSON');
  });
});
