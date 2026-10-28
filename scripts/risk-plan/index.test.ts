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
    [[], 'A plan file, --policy or --helm-values input is required'],
    [['--min-severity', 'potato', 'plan.json'], '--min-severity must be'],
    [['--verbose', 'plan.json'], 'Unknown option: --verbose'],
    [['a.json', 'b.json'], 'Unexpected argument: b.json'],
    [['--policy'], '--policy needs a file path'],
    [['--policy-before', 'before.json'], '--policy-before only applies together with --policy'],
    [['--helm-values'], '--helm-values needs a file path'],
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

describe('shift-left inputs', () => {
  const passRolePolicy = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      { Effect: 'Allow', Action: ['iam:PassRole'], Resource: '*' },
      { Effect: 'Allow', Action: ['s3:GetObject'], Resource: 'arn:aws:s3:::data/*' },
    ],
  });
  const scopedBefore = JSON.stringify({
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['iam:PassRole'],
        Resource: 'arn:aws:iam::111122223333:role/app',
      },
    ],
  });

  it('fails the gate on an IAM policy diff that newly grants iam:PassRole on *', () => {
    const result = runRiskPlan({ policyText: passRolePolicy, policyBeforeText: scopedBefore });

    expect(result.exitCode).toBe(1);
    expect(result.output).toContain('IAM Policy Grants iam:PassRole on All Resources');
    expect(result.output).toContain('Identity → iam:PassRole(*) → compute it launches → role');
    expect(result.report.failing).toHaveLength(1);
  });

  it('reports nothing new when the grant already existed', () => {
    const alreadyWide = JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: ['iam:PassRole'], Resource: '*' }],
    });

    const result = runRiskPlan({ policyText: passRolePolicy, policyBeforeText: alreadyWide });
    expect(result.exitCode).toBe(0);
    expect(result.report.findings).toEqual([]);
  });

  it('scans policies embedded in a plan, diffing before against after', () => {
    const result = runRiskPlan({
      planText: planText([
        change('aws_iam_policy.wide', 'aws_iam_policy', { policy: passRolePolicy }),
      ]),
    });

    expect(result.exitCode).toBe(1);
    expect(result.output).toContain('aws_iam_policy.wide');

    const diffed = runRiskPlan({
      planText: JSON.stringify({
        resource_changes: [
          {
            address: 'aws_iam_policy.wide',
            mode: 'managed',
            type: 'aws_iam_policy',
            name: 'wide',
            change: {
              actions: ['update'],
              before: { policy: passRolePolicy },
              after: { policy: passRolePolicy },
            },
          },
        ],
      }),
    });
    expect(diffed.report.findings).toEqual([]);
  });

  it('flags an internet-facing Helm ingress and lets a plain one pass a high gate', () => {
    const flagged = runRiskPlan({
      helmValuesText:
        'ingress:\n  enabled: true\n  annotations:\n    alb.ingress.kubernetes.io/scheme: internet-facing\n',
    });
    expect(flagged.exitCode).toBe(1);
    expect(flagged.output).toContain('Internet-Facing Ingress Declared for the API/UI');

    const note = runRiskPlan({ helmValuesText: 'ingress:\n  enabled: true\n' });
    expect(note.exitCode).toBe(0);
    expect(note.output).toContain('Ingress Declared for the API/UI');

    const disabled = runRiskPlan({ helmValuesText: 'ingress:\n  enabled: false\n' });
    expect(disabled.report.findings).toEqual([]);
  });

  it('treats a malformed policy or values file as a usage error', () => {
    expect(() => runRiskPlan({ policyText: 'not json' })).toThrow(
      '--policy must be a valid IAM policy document (JSON)'
    );
    expect(() => runRiskPlan({ helmValuesText: ':::: not yaml ::::' })).toThrow(
      '--helm-values must be a valid YAML values file'
    );
  });
});
