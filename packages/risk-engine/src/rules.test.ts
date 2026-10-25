import { riskRules, getEnabledRules, getRuleById } from './rules';
import { ADMIN_PORT_RANGE_PREDICATE } from './admin-ports';

const MANAGED_HOP = "optional(outE('CONTAINS').inV().hasLabel('IamPolicyDocument'))";

describe('riskRules', () => {
  test('should have exactly 34 rules', () => {
    expect(riskRules.length).toBe(34);
  });

  test('each rule should have required fields', () => {
    for (const rule of riskRules) {
      expect(rule.id).toBeDefined();
      expect(rule.name).toBeDefined();
      expect(rule.description).toBeDefined();
      expect(rule.severityHint).toBeDefined();
      expect(rule.gremlinQueryTemplate).toBeDefined();
      expect(rule.ownerTeam).toBeDefined();
      expect(rule.enabled).toBeDefined();
      expect(rule.riskFactors).toBeDefined();
    }
  });

  test('each rule should have a valid severity hint', () => {
    const validSeverities = ['critical', 'high', 'medium', 'low'];
    for (const rule of riskRules) {
      expect(validSeverities).toContain(rule.severityHint);
    }
  });

  test('each rule should have non-empty gremlin query', () => {
    for (const rule of riskRules) {
      expect(rule.gremlinQueryTemplate.trim().length).toBeGreaterThan(0);
    }
  });

  test('each rule uses graph labels and a single read-only traversal', () => {
    for (const rule of riskRules) {
      expect(rule.gremlinQueryTemplate).toContain('.hasLabel(');
      expect(rule.gremlinQueryTemplate).not.toContain(".has('label'");
    }
  });

  test('each rule traverses path hops as explicit edges so paths carry edge labels', () => {
    for (const rule of riskRules) {
      expect(rule.gremlinQueryTemplate).not.toMatch(/\.(out|in|both)\(/);
      expect(rule.gremlinQueryTemplate).not.toContain('repeat(out(');
    }
  });

  test('each rule projects only the path properties the runner reads', () => {
    for (const rule of riskRules) {
      expect(rule.gremlinQueryTemplate).toContain(
        "path().by(valueMap(true, 'arn', 'name', 'Name', 'is_internet_exposed', 'data_classification', 'crown_jewel', 'env', 'is_admin', 'is_admin_role', 'has_cross_account_trust', 'is_cross_account'))"
      );
      expect(rule.gremlinQueryTemplate).not.toContain('valueMap(true))');
    }
  });
});

describe('getEnabledRules', () => {
  test('should return only enabled rules', () => {
    const enabledRules = getEnabledRules();
    for (const rule of enabledRules) {
      expect(rule.enabled).toBe(true);
    }
  });

  test('should return 34 enabled rules', () => {
    const enabledRules = getEnabledRules();
    expect(enabledRules.length).toBe(34);
  });
});

describe('getRuleById', () => {
  test.each([
    [
      'RULE-001',
      'Internet-Exposed EC2',
      ['Ec2Instance', 'data_classification', 'restricted', MANAGED_HOP],
    ],
    [
      'RULE-002',
      'SSH',
      [
        '0.0.0.0/0',
        "has('direction', 'ingress')",
        "has('port_from', lte(22)).has('port_to', gte(22))",
      ],
    ],
    [
      'RULE-003',
      'Critical CVEs',
      ['Ec2Instance', 'LambdaFunction', 'HAS_CVE', 'ContainerImage', 'CRITICAL', 'cvss_base_score'],
    ],
    ['RULE-004', 'IAM', ['HAS_IAM_ROLE', "has('is_admin', true)"]],
    ['RULE-005', 'Crown Jewel', ['crown_jewel']],
    [
      'RULE-006',
      'Cross-Account',
      [
        "out('TRUSTS').hasLabel('ExternalAccount')",
        "V().hasLabel('AwsAccount')",
        "eq('trusted')",
        MANAGED_HOP,
      ],
    ],
    ['RULE-007', 'S3', ['is_publicly_accessible']],
    ['RULE-008', 'RDS', ['RdsInstance']],
    ['RULE-009', 'Lambda', ['LambdaFunction', "has('is_internet_exposed', true)", MANAGED_HOP]],
    [
      'RULE-010',
      'Secret Shared Outside',
      ['HAS_RESOURCE_POLICY', 'SHARES_WITH', 'principal_org_restricted'],
    ],
    [
      'RULE-011',
      'Public S3 Bucket with PII',
      ['DataClassificationFinding', 'is_publicly_accessible'],
    ],
    ['RULE-012', 'Secret Committed', ['secret_count', 'CLASSIFIES']],
    ['RULE-013', 'Access Key Older', ['AccessKey', 'key_age_days', 'HAS_ACCESS_KEY']],
    ['RULE-014', 'Access Key Unused', ['last_used_days_ago', 'gt(90)']],
    ['RULE-015', 'Console Access and No MFA', ['password_enabled', 'mfa_enabled']],
    [
      'RULE-016',
      'Wildcard Secrets',
      [
        'grants_secret_read',
        'secret_grant_scope',
        "optional(inE('CONTAINS').outV().hasLabel('IamPolicy'))",
      ],
    ],
    ['RULE-017', 'GuardDuty', ['GuardDutyDetector', 'MISSING', 'DISABLED']],
    ['RULE-018', 'Security Hub', ['SecurityHubFinding', 'DETECTS_ON', 'is_internet_exposed']],
    ['RULE-019', 'EKS', ['EksCluster', 'endpoint_public_access', 'endpoint_world_open']],
    ['RULE-020', 'Root', ['CloudTrailAnomaly', 'ROOT_USAGE']],
    ['RULE-021', 'Secrets Read', ['CloudTrailAnomaly', 'SECRET_READ_NEW_SOURCE_IP']],
    ['RULE-022', 'AccessDenied', ['CloudTrailAnomaly', 'ACCESS_DENIED_SPIKE']],
    ['RULE-023', 'Canary', ['CloudTrailAnomaly', 'CANARY_USED']],
    ['RULE-024', 'IMDS', ['Ec2Instance', 'metadata_http_tokens', 'HAS_IAM_ROLE']],
    [
      'RULE-029',
      'GuardDuty',
      ['GuardDutyFinding', 'finding_class', 'gte(4)', 'DETECTS_ON', 'is_internet_exposed'],
    ],
    ['RULE-030', 'Escalate', ['CAN_ESCALATE_TO', "within('critical', 'high')"]],
    ['RULE-031', 'Admin IAM User', ["has('is_admin', true)", 'HAS_ACCESS_KEY', 'Active']],
    ['RULE-032', 'Prod Secret', ["has('env', 'prod')", "has('is_prod', false)"]],
    ['RULE-033', 'Another Collected Account', ['HAS_RESOURCE_POLICY', 'SHARES_WITH']],
    ['RULE-034', 'Pass an Admin Role', ['CAN_ESCALATE_TO', "has('escalation_type', 'pass_role')"]],
  ])('returns %s with its expected graph contract', (id, name, queryTokens) => {
    const rule = getRuleById(id);
    expect(rule?.id).toBe(id);
    expect(rule?.name).toContain(name);
    for (const token of queryTokens) expect(rule?.gremlinQueryTemplate).toContain(token);
  });

  test('should return undefined for invalid ID', () => {
    const rule = getRuleById('RULE-999');
    expect(rule).toBeUndefined();
  });
});

describe('Rule gremlin queries', () => {
  test('rules should use snake_case property names', () => {
    for (const rule of riskRules) {
      expect(rule.gremlinQueryTemplate).not.toContain('isInternetExposed');
      expect(rule.gremlinQueryTemplate).not.toContain('isPubliclyAccessible');
      expect(rule.gremlinQueryTemplate).not.toContain('cidrBlock');
      expect(rule.gremlinQueryTemplate).not.toContain('portRange');
      expect(rule.gremlinQueryTemplate).not.toContain('isInVpc');
      expect(rule.gremlinQueryTemplate).not.toContain('hasInternetAccess');
    }
  });

  test('repeat() uses until() or times(), not both', () => {
    for (const rule of riskRules) {
      expect(rule.gremlinQueryTemplate).not.toMatch(
        /\.repeat\([\s\S]*?\)\s*\.times\(\d+\)\s*\.until\(/
      );
    }
    expect(getRuleById('RULE-005')?.gremlinQueryTemplate).toContain(
      "until(or(has('crown_jewel', true), loops().is(4)))"
    );
  });

  test('rules should not reference non-existent edges', () => {
    for (const rule of riskRules) {
      expect(rule.gremlinQueryTemplate).not.toContain('ALLOWS_ACCESS_TO');
      expect(rule.gremlinQueryTemplate).not.toContain('ALLOWS_INGRESS');
      expect(rule.gremlinQueryTemplate).not.toContain('STORES');
    }
  });
});

// These three rules fed the compliance evaluators added alongside them, and
// carried the same defects: each failed toward reporting nothing wrong.
describe('rule predicates that were silently wrong', () => {
  const q = (id: string) => riskRules.find((r) => r.id === id)!.gremlinQueryTemplate;

  // DescribeInstances is called unfiltered, so terminated instances linger in
  // the graph and produced findings nobody could remediate.
  it('RULE-024 ignores terminated instances', () => {
    expect(q('RULE-024')).toContain("not(has('state', within('terminated', 'shutting-down')))");
  });

  // The collector leaves rotation_enabled undefined when GetKeyRotationStatus
  // throws, and normalizeProperties drops undefined -- so the property is absent,
  // not false. Matching false alone missed every key it could not read.
  it('RULE-026 treats an unreadable rotation status as a finding', () => {
    expect(q('RULE-026')).toContain("hasNot('rotation_enabled')");
  });

  // RULE-025 cannot fire on an account with no analyzer, because there is no
  // vertex to attach a finding to. The collector now emits a synthetic MISSING
  // analyzer for that case, the way it already did for GuardDuty.
  it('RULE-025 matches any analyzer that is not ACTIVE, including MISSING', () => {
    expect(q('RULE-025')).toContain("not(has('status', 'ACTIVE'))");
  });
});

// RULE-002 maps to CIS 5.2/5.3, so it must match exactly what they match:
// a range containing 22 or 3389, or 0-0 (all traffic). It matched port_from
// alone, missing 20-25 and flagging 0-21, and fired on egress rules.
describe('RULE-002 admin-port predicate', () => {
  it('uses the predicate the CIS 5.x controls use', () => {
    expect(getRuleById('RULE-002')?.gremlinQueryTemplate).toContain(ADMIN_PORT_RANGE_PREDICATE);
  });

  it('no longer matches on port_from alone', () => {
    expect(getRuleById('RULE-002')?.gremlinQueryTemplate).not.toContain("has('port_from', 22),");
  });

  it('groups route-only differences into one issue for the rules that fan out per path', () => {
    const routed = riskRules.filter((rule) => rule.routeLabels).map((rule) => rule.id);
    expect(routed).toEqual([
      'RULE-002',
      'RULE-006',
      'RULE-010',
      'RULE-016',
      'RULE-018',
      'RULE-032',
      'RULE-033',
    ]);
    expect(getRuleById('RULE-018')?.routeLabels).toEqual(['SecurityHubFinding']);
  });

  it('skips Security Hub findings already suppressed or resolved in Security Hub', () => {
    expect(getRuleById('RULE-018')?.gremlinQueryTemplate).toContain(
      ".not(has('workflow_state', within('SUPPRESSED', 'RESOLVED')))"
    );
  });
});
