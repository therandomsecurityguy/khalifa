import { readFileSync } from 'fs';
import Gremlin from 'gremlin';
import { NeptuneRuntimeClient } from './neptune-client';
import { getRuleById, riskRules } from './rules';

// Runs each rule's real query through the runner's client against a throwaway
// local Gremlin Server (CI only). Fixtures are made up; never point this at Neptune.
const endpoint = process.env.GREMLIN_TEST_ENDPOINT ?? '';
if (!/^ws:\/\/(127\.0\.0\.1|localhost):\d+\/gremlin$/.test(endpoint)) {
  throw new Error('GREMLIN_TEST_ENDPOINT must be a local ws://127.0.0.1:<port>/gremlin');
}

const neptune = new NeptuneRuntimeClient(
  { endpoint: 'wss://localhost/gremlin', maxAttempts: 1, timeoutMs: 15_000 },
  {
    createHeaders: async () => ({}),
    createClient: () => new Gremlin.driver.Client(endpoint, { traversalSource: 'g' }),
  }
);

type Props = Record<string, string | number | boolean>;
const lit = (value: string | number | boolean) =>
  typeof value === 'string'
    ? `'${value.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`
    : String(value);

async function vertex(label: string, id: string, props: Props = {}): Promise<void> {
  const set = Object.entries({ arn: id, ...props })
    .map(([key, value]) => `.property('${key}', ${lit(value)})`)
    .join('');
  await neptune.submit(`g.addV('${label}').property(T.id, ${lit(id)})${set}.iterate()`);
}

async function edge(from: string, label: string, to: string, props: Props = {}): Promise<void> {
  const set = Object.entries(props)
    .map(([key, value]) => `.property('${key}', ${lit(value)})`)
    .join('');
  await neptune.submit(`g.V(${lit(from)}).addE('${label}').to(__.V(${lit(to)}))${set}.iterate()`);
}

// Vertex ids on each matched path, in path order (edges dropped).
async function run(ruleId: string): Promise<string[][]> {
  const rule = getRuleById(ruleId);
  if (!rule) throw new Error(`No rule ${ruleId}`);
  const rows = await neptune.executeQuery(rule.gremlinQueryTemplate);
  return rows.map((row) => {
    const objects: unknown[] = Array.isArray(row) ? row : (row?.objects ?? []);
    return objects.filter((_, index) => index % 2 === 0).map(idOf);
  });
}

function idOf(element: unknown): string {
  const entries = element instanceof Map ? [...element.entries()] : Object.entries(element ?? {});
  const id = entries.find(
    ([key]) => key === 'id' || (key as { elementName?: string })?.elementName === 'id'
  );
  return String(Array.isArray(id?.[1]) ? id?.[1][0] : id?.[1]);
}

const starts = (paths: string[][]) => [...new Set(paths.map((path) => path[0]))].sort();

// One role with an inline policy document holding one Allow statement.
async function inlinePolicy(role: string, statement: Props, label = 'IamRole'): Promise<string> {
  await vertex(label, role);
  await vertex('IamPolicyDocument', `${role}/inline`);
  await vertex('IamPolicyStatement', `${role}/inline/0`, { effect: 'Allow', ...statement });
  await edge(role, 'ATTACHED_TO', `${role}/inline`);
  await edge(`${role}/inline`, 'CONTAINS', `${role}/inline/0`);
  return `${role}/inline/0`;
}

// The collector's managed shape: principal -> IamPolicy -> IamPolicyDocument.
async function managedPolicy(role: string, statement: Props): Promise<string> {
  await vertex('IamRole', role);
  await vertex('IamPolicy', `${role}-policy`);
  await vertex('IamPolicyDocument', `${role}-policy/version/v1`);
  await vertex('IamPolicyStatement', `${role}-policy/version/v1/0`, {
    effect: 'Allow',
    ...statement,
  });
  await edge(role, 'ATTACHED_TO', `${role}-policy`);
  await edge(`${role}-policy`, 'CONTAINS', `${role}-policy/version/v1`);
  await edge(`${role}-policy/version/v1`, 'CONTAINS', `${role}-policy/version/v1/0`);
  return `${role}-policy/version/v1/0`;
}

beforeEach(() => neptune.submit('g.V().drop().iterate()'));
afterAll(() => neptune.close());

describe('rule queries against a Gremlin Server', () => {
  it('RULE-001 matches an exposed instance whose role reaches restricted S3', async () => {
    for (const [ec2, exposed, classification] of [
      ['ec2-hit', true, 'restricted'],
      ['ec2-internal', false, 'restricted'],
      ['ec2-public-data', true, 'public'],
    ] as const) {
      await vertex('Ec2Instance', ec2, { is_internet_exposed: exposed });
      const statement = await inlinePolicy(`${ec2}-role`, {});
      await vertex('S3Bucket', `${ec2}-bucket`, { data_classification: classification });
      await edge(ec2, 'HAS_IAM_ROLE', `${ec2}-role`);
      await edge(statement, 'GRANTS', `${ec2}-bucket`);
    }
    expect(starts(await run('RULE-001'))).toEqual(['ec2-hit']);
  });

  it('RULE-006 matches a trusted role with a wildcard Allow', async () => {
    await vertex('ExternalAccount', 'ext-999', { account_id: '999999999999' });
    await inlinePolicy('role-trusted', { has_wildcard_resource: true });
    await edge('role-trusted', 'TRUSTS', 'ext-999');
    await inlinePolicy('role-untrusted', { has_wildcard_resource: true });
    expect(starts(await run('RULE-006'))).toEqual(['role-trusted']);
  });

  it('RULE-009 matches an internet-reaching Lambda whose role reaches classified data', async () => {
    await vertex('LambdaFunction', 'fn', { is_in_vpc: true, has_internet_access: true });
    const statement = await inlinePolicy('fn-role', {});
    await vertex('DynamoDBTable', 'table', { data_classification: 'internal' });
    await edge('fn', 'HAS_IAM_ROLE', 'fn-role');
    await edge(statement, 'GRANTS', 'table');
    expect(starts(await run('RULE-009'))).toEqual(['fn']);
  });

  it('RULE-010 matches a database secret granted by a wildcard statement on a role', async () => {
    for (const [secret, type] of [
      ['secret-db', 'database'],
      ['secret-api', 'api_key'],
    ]) {
      await vertex('Secret', secret, { secret_type: type });
      const statement = await inlinePolicy(`${secret}-role`, { has_wildcard_resource: true });
      await edge(statement, 'GRANTS', secret);
    }
    expect(starts(await run('RULE-010'))).toEqual(['secret-db']);
  });

  it('RULE-016 matches wildcard secret reads attached to a principal', async () => {
    const wildcard = await inlinePolicy('role-wild', {
      grants_secret_read: true,
      secret_grant_scope: 'wildcard',
    });
    await inlinePolicy('role-scoped', { grants_secret_read: true, secret_grant_scope: 'explicit' });
    expect(starts(await run('RULE-016'))).toEqual([wildcard]);
  });

  it('RULE-016 follows a managed policy to its principal', async () => {
    const statement = await managedPolicy('role-managed', {
      grants_secret_read: true,
      secret_grant_scope: 'wildcard',
    });
    expect(starts(await run('RULE-016'))).toEqual([statement]);
  });

  it('RULE-006 follows a managed policy from a trusted role', async () => {
    await vertex('ExternalAccount', 'ext-999', { account_id: '999999999999' });
    await managedPolicy('role-managed', { has_wildcard_resource: true });
    await edge('role-managed', 'TRUSTS', 'ext-999');
    expect(starts(await run('RULE-006'))).toEqual(['role-managed']);
  });

  it('RULE-006 ignores trusts between collected accounts', async () => {
    await vertex('AwsAccount', 'arn:aws:iam::111111111111:root', { account_id: '111111111111' });
    await vertex('ExternalAccount', 'ext-111', { account_id: '111111111111' });
    await vertex('ExternalAccount', 'ext-999', { account_id: '999999999999' });
    await inlinePolicy('role-collector', { has_wildcard_resource: true });
    await edge('role-collector', 'TRUSTS', 'ext-111');
    await inlinePolicy('role-mixed', { has_wildcard_resource: true });
    await edge('role-mixed', 'TRUSTS', 'ext-111');
    await edge('role-mixed', 'TRUSTS', 'ext-999');
    expect(starts(await run('RULE-006'))).toEqual(['role-mixed']);
  });

  it('RULE-001, 009 and 010 follow managed policies', async () => {
    await vertex('Ec2Instance', 'ec2', { is_internet_exposed: true });
    const ec2Statement = await managedPolicy('ec2-role', {});
    await vertex('S3Bucket', 'bucket', { data_classification: 'restricted' });
    await edge('ec2', 'HAS_IAM_ROLE', 'ec2-role');
    await edge(ec2Statement, 'GRANTS', 'bucket');

    await vertex('LambdaFunction', 'fn', { is_in_vpc: true, has_internet_access: true });
    const fnStatement = await managedPolicy('fn-role', {});
    await vertex('DynamoDBTable', 'table', { data_classification: 'secret' });
    await edge('fn', 'HAS_IAM_ROLE', 'fn-role');
    await edge(fnStatement, 'GRANTS', 'table');

    await vertex('Secret', 'secret-db', { secret_type: 'database' });
    const secretStatement = await managedPolicy('secret-role', { has_wildcard_resource: true });
    await edge(secretStatement, 'GRANTS', 'secret-db');

    expect(starts(await run('RULE-001'))).toEqual(['ec2']);
    expect(starts(await run('RULE-009'))).toEqual(['fn']);
    expect(starts(await run('RULE-010'))).toEqual(['secret-db']);
  });
});

describe('identity and data rules', () => {
  it('RULE-001 and RULE-009 ignore a Deny statement', async () => {
    await vertex('Ec2Instance', 'ec2', { is_internet_exposed: true });
    const ec2Statement = await inlinePolicy('ec2-role', { effect: 'Deny' });
    await vertex('S3Bucket', 'bucket', { data_classification: 'restricted' });
    await edge('ec2', 'HAS_IAM_ROLE', 'ec2-role');
    await edge(ec2Statement, 'GRANTS', 'bucket');

    await vertex('LambdaFunction', 'fn', { is_in_vpc: true, has_internet_access: true });
    const fnStatement = await inlinePolicy('fn-role', { effect: 'Deny' });
    await vertex('DynamoDBTable', 'table', { data_classification: 'secret' });
    await edge('fn', 'HAS_IAM_ROLE', 'fn-role');
    await edge(fnStatement, 'GRANTS', 'table');

    expect(await run('RULE-001')).toEqual([]);
    expect(await run('RULE-009')).toEqual([]);
  });

  it('RULE-004 matches an exposed workload whose role is admin', async () => {
    for (const [workload, label, exposed, admin] of [
      ['ec2-admin', 'Ec2Instance', true, true],
      ['fn-admin', 'LambdaFunction', true, true],
      ['ec2-internal', 'Ec2Instance', false, true],
      ['ec2-scoped', 'Ec2Instance', true, false],
    ] as const) {
      await vertex(label, workload, { is_internet_exposed: exposed });
      await vertex('IamRole', `${workload}-role`, { is_admin: admin });
      await edge(workload, 'HAS_IAM_ROLE', `${workload}-role`);
    }
    // Many policies alone no longer count.
    await vertex('Ec2Instance', 'ec2-many', { is_internet_exposed: true });
    await vertex('IamRole', 'ec2-many-role');
    await edge('ec2-many', 'HAS_IAM_ROLE', 'ec2-many-role');
    for (let index = 0; index < 6; index++) {
      await vertex('IamPolicy', `ec2-many-policy-${index}`);
      await edge('ec2-many-role', 'ATTACHED_TO', `ec2-many-policy-${index}`);
    }
    expect(starts(await run('RULE-004'))).toEqual(['ec2-admin', 'fn-admin']);
  });

  it('RULE-030 matches a critical or high escalation link to a role', async () => {
    await vertex('IamRole', 'admin');
    for (const [source, label, risk] of [
      ['acct-root', 'AwsAccount', 'critical'],
      ['ci-role', 'IamRole', 'high'],
      ['dev-user', 'IamUser', 'critical'],
      ['lateral-role', 'IamRole', 'medium'],
    ] as const) {
      await vertex(label, source);
      await edge(source, 'CAN_ESCALATE_TO', 'admin', { risk_level: risk });
    }
    // A plain trust is not an escalation link.
    await vertex('IamRole', 'trusted-only');
    await edge('trusted-only', 'TRUSTS', 'admin');
    expect(starts(await run('RULE-030'))).toEqual(['acct-root', 'ci-role', 'dev-user']);
  });

  it('RULE-006 ignores an untrusted role and a non-wildcard or Deny statement', async () => {
    await vertex('ExternalAccount', 'ext-999', { account_id: '999999999999' });
    for (const [role, statement] of [
      ['role-scoped', { has_wildcard_resource: false }],
      ['role-deny', { has_wildcard_resource: true, effect: 'Deny' }],
    ] as const) {
      await inlinePolicy(role, statement);
      await edge(role, 'TRUSTS', 'ext-999');
    }
    expect(await run('RULE-006')).toEqual([]);
  });

  it('RULE-007 matches a public bucket holding restricted or secret data', async () => {
    for (const [bucket, open, classification] of [
      ['public-restricted', true, 'restricted'],
      ['public-secret', true, 'secret'],
      ['public-internal', true, 'internal'],
      ['private-secret', false, 'secret'],
    ] as const) {
      await vertex('S3Bucket', bucket, {
        is_publicly_accessible: open,
        data_classification: classification,
      });
    }
    expect(starts(await run('RULE-007'))).toEqual(['public-restricted', 'public-secret']);
  });

  it('RULE-008 matches a public RDS instance holding sensitive data', async () => {
    await vertex('RdsInstance', 'rds-hit', {
      is_publicly_accessible: true,
      data_classification: 'restricted',
    });
    await vertex('RdsInstance', 'rds-private', {
      is_publicly_accessible: false,
      data_classification: 'restricted',
    });
    expect(starts(await run('RULE-008'))).toEqual(['rds-hit']);
  });

  it('RULE-009 ignores a Lambda without internet access and public data', async () => {
    for (const [fn, internet, classification] of [
      ['fn-offline', false, 'restricted'],
      ['fn-public-data', true, 'public'],
    ] as const) {
      await vertex('LambdaFunction', fn, { is_in_vpc: true, has_internet_access: internet });
      const statement = await inlinePolicy(`${fn}-role`, {});
      await vertex('S3Bucket', `${fn}-bucket`, { data_classification: classification });
      await edge(fn, 'HAS_IAM_ROLE', `${fn}-role`);
      await edge(statement, 'GRANTS', `${fn}-bucket`);
    }
    expect(await run('RULE-009')).toEqual([]);
  });

  it('RULE-010 matches a cross-account statement and a secret resource policy', async () => {
    await vertex('Secret', 'secret-cross', { secret_type: 'database' });
    const cross = await inlinePolicy('role-cross', { has_cross_account_principal: true });
    await edge(cross, 'GRANTS', 'secret-cross');

    await vertex('Secret', 'secret-resource', { secret_type: 'database' });
    await vertex('IamPolicyDocument', 'secret-resource/policy');
    await vertex('IamPolicyStatement', 'secret-resource/policy/0', {
      effect: 'Allow',
      has_wildcard_resource: true,
    });
    await edge('secret-resource', 'HAS_RESOURCE_POLICY', 'secret-resource/policy');
    await edge('secret-resource/policy', 'CONTAINS', 'secret-resource/policy/0');
    await edge('secret-resource/policy/0', 'GRANTS', 'secret-resource');

    await vertex('Secret', 'secret-scoped', { secret_type: 'database' });
    const scoped = await inlinePolicy('role-scoped', { has_wildcard_resource: false });
    await edge(scoped, 'GRANTS', 'secret-scoped');

    expect(starts(await run('RULE-010'))).toEqual(['secret-cross', 'secret-resource']);
  });

  it('RULE-011 matches a public bucket with a restricted or secret DSPM finding', async () => {
    for (const [bucket, open, classification] of [
      ['public-pii', true, 'restricted'],
      ['public-clean', true, 'internal'],
      ['private-pii', false, 'restricted'],
    ] as const) {
      await vertex('S3Bucket', bucket, { is_publicly_accessible: open });
      await vertex('DataClassificationFinding', `${bucket}/dspm-finding`, {
        data_classification: classification,
      });
      await edge(`${bucket}/dspm-finding`, 'CLASSIFIES', bucket);
    }
    expect(starts(await run('RULE-011'))).toEqual(['public-pii']);
  });

  it('RULE-012 matches secrets found in a bucket or Lambda environment', async () => {
    for (const [resource, label, count] of [
      ['bucket-leak', 'S3Bucket', 2],
      ['fn-leak', 'LambdaFunction', 1],
      ['bucket-clean', 'S3Bucket', 0],
    ] as const) {
      await vertex(label, resource);
      await vertex('DataClassificationFinding', `${resource}/dspm-finding`, {
        secret_count: count,
      });
      await edge(`${resource}/dspm-finding`, 'CLASSIFIES', resource);
    }
    expect(starts(await run('RULE-012'))).toEqual([
      'bucket-leak/dspm-finding',
      'fn-leak/dspm-finding',
    ]);
  });

  it('RULE-016 ignores a Deny and a grant on no principal', async () => {
    await inlinePolicy('role-deny', {
      effect: 'Deny',
      grants_secret_read: true,
      secret_grant_scope: 'wildcard',
    });
    await vertex('IamPolicyDocument', 'orphan');
    await vertex('IamPolicyStatement', 'orphan/0', {
      effect: 'Allow',
      grants_secret_read: true,
      secret_grant_scope: 'wildcard',
    });
    await edge('orphan', 'CONTAINS', 'orphan/0');
    expect(await run('RULE-016')).toEqual([]);
  });
});

describe('credential rules', () => {
  async function userKey(user: string, key: Props): Promise<void> {
    await vertex('IamUser', user);
    await vertex('AccessKey', `${user}/key`, key);
    await edge(user, 'HAS_ACCESS_KEY', `${user}/key`);
  }

  it('RULE-013 matches an active key older than 90 days', async () => {
    await userKey('old', { status: 'Active', key_age_days: 91 });
    await userKey('day-90', { status: 'Active', key_age_days: 90 });
    await userKey('inactive', { status: 'Inactive', key_age_days: 400 });
    expect(starts(await run('RULE-013'))).toEqual(['old/key']);
  });

  it('RULE-014 matches an active key unused for more than 90 days', async () => {
    await userKey('stale', { status: 'Active', last_used_days_ago: 120 });
    await userKey('recent', { status: 'Active', last_used_days_ago: 3 });
    await userKey('inactive', { status: 'Inactive', last_used_days_ago: 400 });
    expect(starts(await run('RULE-014'))).toEqual(['stale/key']);
  });

  it('RULE-015 matches a console user without MFA', async () => {
    await vertex('IamUser', 'no-mfa', { password_enabled: true, mfa_enabled: false });
    await vertex('IamUser', 'mfa', { password_enabled: true, mfa_enabled: true });
    await vertex('IamUser', 'no-console', { password_enabled: false, mfa_enabled: false });
    expect(starts(await run('RULE-015'))).toEqual(['no-mfa']);
  });
});

describe('exposure rules', () => {
  async function securityGroupRule(id: string, rule: Props, instance = `${id}-ec2`) {
    await vertex('SecurityGroupRule', id, { direction: 'ingress', protocol: 'tcp', ...rule });
    await vertex('SecurityGroup', `${id}-sg`);
    await vertex('NetworkInterface', `${id}-eni`);
    await vertex('Ec2Instance', instance);
    await edge(id, 'PART_OF', `${id}-sg`);
    await edge(`${id}-sg`, 'PROTECTS', `${id}-eni`);
    await edge(`${id}-eni`, 'ATTACHED_TO', instance);
  }

  it('RULE-002 matches SSH or RDP open to the IPv4 or IPv6 internet', async () => {
    await securityGroupRule('ssh-v4', { cidr_block: '0.0.0.0/0', port_from: 22, port_to: 22 });
    await securityGroupRule('rdp-v6', { cidr_block: '::/0', port_from: 3389, port_to: 3389 });
    await securityGroupRule('range', { cidr_block: '0.0.0.0/0', port_from: 1, port_to: 1024 });
    await securityGroupRule('all-traffic', {
      cidr_block: '0.0.0.0/0',
      protocol: '-1',
      port_from: 0,
      port_to: 0,
    });
    await securityGroupRule('https', { cidr_block: '0.0.0.0/0', port_from: 443, port_to: 443 });
    await securityGroupRule('internal', { cidr_block: '10.0.0.0/8', port_from: 22, port_to: 22 });
    await securityGroupRule('udp', {
      cidr_block: '0.0.0.0/0',
      protocol: 'udp',
      port_from: 22,
      port_to: 22,
    });
    await securityGroupRule('egress', {
      direction: 'egress',
      cidr_block: '0.0.0.0/0',
      port_from: 22,
      port_to: 22,
    });
    expect(starts(await run('RULE-002'))).toEqual(['all-traffic', 'range', 'rdp-v6', 'ssh-v4']);
  });

  it('RULE-005 matches a crown jewel within four hops of the internet', async () => {
    await vertex('Internet', 'internet');
    for (const id of ['igw', 'lb', 'ec2', 'role', 'far-role']) await vertex('Node', id);
    await vertex('S3Bucket', 'near-jewel', { crown_jewel: true });
    await vertex('S3Bucket', 'far-jewel', { crown_jewel: true });
    await edge('internet', 'EXPOSES', 'igw');
    await edge('igw', 'CONTAINS', 'lb');
    await edge('lb', 'CONTAINS', 'ec2');
    await edge('ec2', 'HAS_IAM_ROLE', 'role');
    await edge('ec2', 'HAS_IAM_ROLE', 'near-jewel');
    await edge('role', 'GRANTS', 'far-role');
    await edge('far-role', 'GRANTS', 'far-jewel');
    const targets = (await run('RULE-005')).map((path) => path[path.length - 1]);
    expect(targets).toEqual(['near-jewel']);
  });

  it('RULE-018 matches an active critical or high Security Hub finding on an exposed resource', async () => {
    for (const [finding, finding_props, exposed] of [
      ['critical', { severity: 'CRITICAL' }, true],
      ['high', { severity: 'HIGH' }, true],
      ['medium', { severity: 'MEDIUM' }, true],
      ['suppressed', { severity: 'CRITICAL', workflow_state: 'SUPPRESSED' }, true],
      ['archived', { severity: 'CRITICAL', record_state: 'ARCHIVED' }, true],
      ['internal', { severity: 'CRITICAL' }, false],
    ] as const) {
      await vertex('SecurityHubFinding', finding, { record_state: 'ACTIVE', ...finding_props });
      await vertex('Ec2Instance', `${finding}-ec2`, { is_internet_exposed: exposed });
      await edge(finding, 'DETECTS_ON', `${finding}-ec2`);
    }
    expect(starts(await run('RULE-018'))).toEqual(['critical', 'high']);
  });

  it('RULE-019 matches an EKS endpoint public to the world', async () => {
    await vertex('EksCluster', 'open', { endpoint_public_access: true, endpoint_world_open: true });
    await vertex('EksCluster', 'allowlisted', {
      endpoint_public_access: true,
      endpoint_world_open: false,
    });
    await vertex('EksCluster', 'private', {
      endpoint_public_access: false,
      endpoint_world_open: false,
    });
    expect(starts(await run('RULE-019'))).toEqual(['open']);
  });

  it('RULE-024 matches a running IMDSv1 instance with a role', async () => {
    for (const [ec2, tokens, state, withRole] of [
      ['v1-running', 'optional', 'running', true],
      ['v1-stopped', 'optional', 'stopped', true],
      ['v1-terminated', 'optional', 'terminated', true],
      ['v2', 'required', 'running', true],
      ['v1-no-role', 'optional', 'running', false],
    ] as const) {
      await vertex('Ec2Instance', ec2, { metadata_http_tokens: tokens, state });
      if (withRole) {
        await vertex('IamRole', `${ec2}-role`);
        await edge(ec2, 'HAS_IAM_ROLE', `${ec2}-role`);
      }
    }
    expect(starts(await run('RULE-024'))).toEqual(['v1-running', 'v1-stopped']);
  });

  it('RULE-029 matches a medium-or-worse attack-class GuardDuty finding on an exposed resource', async () => {
    for (const [finding, findingClass, severity, exposed] of [
      ['backdoor', 'Backdoor', 8, true],
      ['crypto', 'CryptoCurrency', 4, true],
      ['low', 'UnauthorizedAccess', 2, true],
      ['recon', 'Recon', 8, true],
      ['internal', 'Backdoor', 8, false],
    ] as const) {
      await vertex('GuardDutyFinding', finding, { finding_class: findingClass, severity });
      await vertex('Ec2Instance', `${finding}-ec2`, { is_internet_exposed: exposed });
      await edge(finding, 'DETECTS_ON', `${finding}-ec2`);
    }
    expect(starts(await run('RULE-029'))).toEqual(['backdoor', 'crypto']);
  });

  // RULE-003 is disabled. It walks RUNS_ON into the CVE, but RUNS_ON runs from the
  // image to its workload (ARCHITECTURE.md), so it can never match.
  it.failing(
    'RULE-003 matches a critical CVE on an image running on an exposed workload',
    async () => {
      await vertex('ContainerImage', 'image');
      await vertex('Vulnerability', 'cve', { severity: 'CRITICAL', cvss_base_score: 9.8 });
      await vertex('Ec2Instance', 'ec2', { is_internet_exposed: true });
      await edge('image', 'HAS_CVE', 'cve');
      await edge('image', 'RUNS_ON', 'ec2');
      expect(starts(await run('RULE-003'))).toEqual(['image']);
    }
  );
});

describe('detection and posture rules', () => {
  it('RULE-017 matches a disabled or missing GuardDuty detector', async () => {
    for (const status of ['DISABLED', 'MISSING', 'ENABLED']) {
      await vertex('GuardDutyDetector', `detector-${status}`, { status });
    }
    expect(starts(await run('RULE-017'))).toEqual(['detector-DISABLED', 'detector-MISSING']);
  });

  it.each([
    ['RULE-020', 'ROOT_USAGE'],
    ['RULE-021', 'SECRET_READ_NEW_SOURCE_IP'],
    ['RULE-022', 'ACCESS_DENIED_SPIKE'],
    ['RULE-023', 'CANARY_USED'],
  ])('%s matches only %s anomalies', async (ruleId, type) => {
    for (const anomaly of [
      'ROOT_USAGE',
      'SECRET_READ_NEW_SOURCE_IP',
      'ACCESS_DENIED_SPIKE',
      'CANARY_USED',
    ]) {
      await vertex('CloudTrailAnomaly', `anomaly-${anomaly}`, { anomaly_type: anomaly });
    }
    expect(starts(await run(ruleId))).toEqual([`anomaly-${type}`]);
  });

  it('RULE-025 matches an Access Analyzer that is not active', async () => {
    for (const status of ['ACTIVE', 'DISABLED', 'FAILED']) {
      await vertex('AccessAnalyzer', `analyzer-${status}`, { status });
    }
    expect(starts(await run('RULE-025'))).toEqual(['analyzer-DISABLED', 'analyzer-FAILED']);
  });

  it('RULE-026 matches an enabled customer-managed key without rotation', async () => {
    for (const [key, props] of [
      ['no-rotation', { key_manager: 'CUSTOMER', key_state: 'Enabled', rotation_enabled: false }],
      ['unknown-rotation', { key_manager: 'CUSTOMER', key_state: 'Enabled' }],
      ['rotating', { key_manager: 'CUSTOMER', key_state: 'Enabled', rotation_enabled: true }],
      ['aws-managed', { key_manager: 'AWS', key_state: 'Enabled', rotation_enabled: false }],
      ['disabled', { key_manager: 'CUSTOMER', key_state: 'Disabled', rotation_enabled: false }],
    ] as const) {
      await vertex('KmsKey', key, props);
    }
    expect(starts(await run('RULE-026'))).toEqual(['no-rotation', 'unknown-rotation']);
  });

  it('RULE-027 matches a VPC without flow logs', async () => {
    await vertex('Vpc', 'no-logs', { flow_logs_enabled: false });
    await vertex('Vpc', 'logged', { flow_logs_enabled: true });
    expect(starts(await run('RULE-027'))).toEqual(['no-logs']);
  });

  it('RULE-028 matches a Config recorder that is not recording', async () => {
    await vertex('ConfigRecorder', 'stopped', { recording: false });
    await vertex('ConfigRecorder', 'recording', { recording: true });
    expect(starts(await run('RULE-028'))).toEqual(['stopped']);
  });
});

it('every rule has a graph test', () => {
  const tested = new Set(readFileSync(__filename, 'utf8').match(/RULE-\d{3}/g));
  expect(riskRules.map((rule) => rule.id).filter((id) => !tested.has(id))).toEqual([]);
});
