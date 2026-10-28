import { analyzePlan } from './analyzers';
import type { PlannedResource } from './plan';

function res(type: string, address: string, after: Record<string, unknown>): PlannedResource {
  return { address, type, name: address, actions: ['create'], after, before: {} };
}

const policy = (document: unknown) => JSON.stringify(document);

describe('security group ingress', () => {
  it('flags a world-open SSH rule as RULE-002 with the entry path', () => {
    const findings = analyzePlan([
      res('aws_security_group', 'aws_security_group.app', {
        ingress: [
          {
            from_port: 22,
            to_port: 22,
            protocol: 'tcp',
            cidr_blocks: ['0.0.0.0/0'],
          },
        ],
      }),
    ]);

    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'RULE-002',
      severity: 'high',
      address: 'aws_security_group.app',
    });
    expect(findings[0].detail).toContain('0.0.0.0/0');
    expect(findings[0].predictedPath).toBe(
      'Internet → aws_security_group.app → attached resources'
    );
  });

  it('flags RDP, all-protocol, and unknown-port rules, and standalone rule resources', () => {
    expect(
      analyzePlan([
        res('aws_security_group', 'sg.rdp', {
          ingress: [
            { from_port: 3389, to_port: 3389, protocol: 'tcp', ipv6_cidr_blocks: ['::/0'] },
          ],
        }),
        res('aws_security_group', 'sg.all', {
          ingress: [{ protocol: '-1', cidr_blocks: ['0.0.0.0/0'] }],
        }),
        res('aws_security_group_rule', 'rule.ssh', {
          type: 'ingress',
          from_port: 22,
          to_port: 22,
          protocol: 'tcp',
          cidr_blocks: ['0.0.0.0/0'],
        }),
        res('aws_vpc_security_group_ingress_rule', 'vpc_rule.http', {
          from_port: 80,
          to_port: 80,
          ip_protocol: 'tcp',
          cidr_ipv4: '0.0.0.0/0',
        }),
      ])
    ).toHaveLength(4);
  });

  it('marks ports no rule covers yet without inventing a rule id', () => {
    const [finding] = analyzePlan([
      res('aws_security_group', 'sg.web', {
        ingress: [{ from_port: 8080, to_port: 8080, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }],
      }),
    ]);
    expect(finding.ruleId).toBeNull();
    expect(finding.ruleName).toContain('no catalogue rule');
  });

  it('ignores private CIDRs, egress, and deleted rules', () => {
    expect(
      analyzePlan([
        res('aws_security_group', 'sg.private', {
          ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['10.0.0.0/8'] }],
        }),
        res('aws_security_group_rule', 'rule.egress', {
          type: 'egress',
          from_port: 0,
          to_port: 0,
          protocol: '-1',
          cidr_blocks: ['0.0.0.0/0'],
        }),
        {
          address: 'gone',
          type: 'aws_security_group_rule',
          name: 'gone',
          actions: ['delete'],
          after: {},
          before: {},
        },
      ])
    ).toEqual([]);
  });

  it('merges several world-open rules on one group into one finding', () => {
    const findings = analyzePlan([
      res('aws_security_group', 'sg.mixed', {
        ingress: [
          { from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] },
          { from_port: 3389, to_port: 3389, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] },
        ],
      }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0].detail).toContain('; ');
  });
});

describe('buckets, databases, and clusters', () => {
  it('flags public bucket ACLs, disabled blocks, and anyone policies as RULE-007', () => {
    const findings = analyzePlan([
      res('aws_s3_bucket_acl', 'acl.public', { acl: 'public-read' }),
      res('aws_s3_bucket_public_access_block', 'pab.off', {
        block_public_acls: false,
        block_public_policy: true,
        ignore_public_acls: true,
        restrict_public_buckets: true,
      }),
      res('aws_s3_bucket_policy', 'policy.anyone', {
        policy: policy({
          Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: '*' }],
        }),
      }),
      res('aws_s3_bucket_policy', 'policy.org', {
        policy: policy({
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: 's3:GetObject',
              Resource: '*',
              Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorgid' } },
            },
          ],
        }),
      }),
      res('aws_s3_bucket_public_access_block', 'pab.on', {
        block_public_acls: true,
        block_public_policy: true,
        ignore_public_acls: true,
        restrict_public_buckets: true,
      }),
    ]);

    expect(findings.map((finding) => finding.address)).toEqual([
      'acl.public',
      'pab.off',
      'policy.anyone',
    ]);
    expect(findings.every((finding) => finding.ruleId === 'RULE-007')).toBe(true);
  });

  it('flags publicly accessible RDS as RULE-008 and ignores private databases', () => {
    const findings = analyzePlan([
      res('aws_db_instance', 'db.public', { publicly_accessible: true }),
      res('aws_db_instance', 'db.private', { publicly_accessible: false }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'RULE-008', address: 'db.public' });
  });

  it('flags a world-open EKS endpoint as RULE-019', () => {
    const findings = analyzePlan([
      res('aws_eks_cluster', 'eks.world', {
        vpc_config: { endpoint_public_access: true, public_access_cidrs: ['0.0.0.0/0'] },
      }),
      res('aws_eks_cluster', 'eks.private-cidr', {
        vpc_config: { endpoint_public_access: true, public_access_cidrs: ['203.0.113.0/24'] },
      }),
      res('aws_eks_cluster', 'eks.private-endpoint', {
        vpc_config: { endpoint_public_access: false, public_access_cidrs: ['0.0.0.0/0'] },
      }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'RULE-019', address: 'eks.world' });
  });
});

describe('trusts and resource policies', () => {
  it('flags an account-root trust as RULE-006', () => {
    const findings = analyzePlan([
      res('aws_iam_role', 'role.vendor', {
        assume_role_policy: policy({
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::222233334444:root' },
              Action: 'sts:AssumeRole',
            },
          ],
        }),
      }),
      res('aws_iam_role', 'role.service', {
        assume_role_policy: policy({
          Statement: [
            {
              Effect: 'Allow',
              Principal: { Service: 'lambda.amazonaws.com' },
              Action: 'sts:AssumeRole',
            },
          ],
        }),
      }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'RULE-006', severity: 'critical' });
    expect(findings[0].detail).toContain('222233334444');
    expect(findings[0].predictedPath).toBe('ExternalAccount → TRUSTS → role.vendor');
  });

  it('flags a Principal * trust and secret policy, and leaves org-restricted ones alone', () => {
    const findings = analyzePlan([
      res('aws_iam_role', 'role.anyone', {
        assume_role_policy: policy({
          Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sts:AssumeRole' }],
        }),
      }),
      res('aws_secretsmanager_secret_policy', 'secret.anyone', {
        policy: policy({
          Statement: [{ Effect: 'Allow', Principal: '*', Action: 'secretsmanager:GetSecretValue' }],
        }),
      }),
      res('aws_secretsmanager_secret_policy', 'secret.org', {
        policy: policy({
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: 'secretsmanager:GetSecretValue',
              Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-exampleorgid' } },
            },
          ],
        }),
      }),
    ]);
    expect(findings.map((finding) => [finding.address, finding.ruleId])).toEqual([
      ['role.anyone', 'RULE-006'],
      ['secret.anyone', 'RULE-010'],
    ]);
  });

  it('ignores malformed policy documents instead of failing the run', () => {
    expect(
      analyzePlan([
        res('aws_iam_role', 'role.broken', { assume_role_policy: 'not json' }),
        res('aws_secretsmanager_secret_policy', 'secret.broken', { policy: '{' }),
      ])
    ).toEqual([]);
  });
});

describe('workload exposure', () => {
  it('flags an unauthenticated function URL as RULE-009', () => {
    const findings = analyzePlan([
      res('aws_lambda_function_url', 'url.public', { authorization_type: 'NONE' }),
      res('aws_lambda_function_url', 'url.iam', { authorization_type: 'AWS_IAM' }),
    ]);
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: 'RULE-009', address: 'url.public' });
  });

  it('flags EC2 instances without enforced IMDSv2 as RULE-024', () => {
    const findings = analyzePlan([
      res('aws_instance', 'instance.default', {}),
      res('aws_instance', 'instance.optional', { metadata_options: { http_tokens: 'optional' } }),
      res('aws_instance', 'instance.required', { metadata_options: { http_tokens: 'required' } }),
    ]);
    expect(findings.map((finding) => finding.address)).toEqual([
      'instance.default',
      'instance.optional',
    ]);
    expect(findings.every((finding) => finding.ruleId === 'RULE-024')).toBe(true);
  });
});

describe('ordering', () => {
  it('ranks critical findings above lower ones and sorts addresses within a severity', () => {
    const findings = analyzePlan([
      res('aws_s3_bucket_acl', 'z-acl', { acl: 'public-read' }),
      res('aws_security_group', 'sg.ssh', {
        ingress: [{ from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }],
      }),
      res('aws_s3_bucket_acl', 'a-acl', { acl: 'public-read-write' }),
    ]);
    expect(findings.map((finding) => [finding.severity, finding.address])).toEqual([
      ['critical', 'a-acl'],
      ['critical', 'z-acl'],
      ['high', 'sg.ssh'],
    ]);
  });
});
