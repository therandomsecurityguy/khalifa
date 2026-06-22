import { riskRules, getEnabledRules, getRuleById } from './rules';

describe('riskRules', () => {
  test('should have at least 5 rules', () => {
    expect(riskRules.length).toBeGreaterThanOrEqual(5);
  });

  test('should have exactly 10 rules', () => {
    expect(riskRules.length).toBe(10);
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
});

describe('getEnabledRules', () => {
  test('should return only enabled rules', () => {
    const enabledRules = getEnabledRules();
    for (const rule of enabledRules) {
      expect(rule.enabled).toBe(true);
    }
  });

  test('RULE-003 should be disabled (vulnerability scanning not yet built)', () => {
    const rule = getRuleById('RULE-003');
    expect(rule?.enabled).toBe(false);
  });

  test('should return 9 enabled rules (RULE-003 disabled)', () => {
    const enabledRules = getEnabledRules();
    expect(enabledRules.length).toBe(9);
  });
});

describe('getRuleById', () => {
  test('should return rule by valid ID', () => {
    const rule = getRuleById('RULE-001');
    expect(rule).toBeDefined();
    expect(rule?.id).toBe('RULE-001');
  });

  test('should return undefined for invalid ID', () => {
    const rule = getRuleById('RULE-999');
    expect(rule).toBeUndefined();
  });

  test('should find internet-exposed EC2 rule', () => {
    const rule = getRuleById('RULE-001');
    expect(rule?.name).toContain('Internet-Exposed EC2');
    expect(rule?.gremlinQueryTemplate).toContain('Ec2Instance');
    expect(rule?.gremlinQueryTemplate).toContain('data_classification');
  });

  test('should find security group SSH/RDP rule', () => {
    const rule = getRuleById('RULE-002');
    expect(rule?.name).toContain('SSH');
    expect(rule?.gremlinQueryTemplate).toContain('0.0.0.0/0');
  });

  test('should find container CVE rule', () => {
    const rule = getRuleById('RULE-003');
    expect(rule?.name).toContain('Container');
    expect(rule?.gremlinQueryTemplate).toContain('ContainerImage');
    expect(rule?.gremlinQueryTemplate).toContain('HAS_CVE');
  });

  test('should find over-privileged IAM rule', () => {
    const rule = getRuleById('RULE-004');
    expect(rule?.name).toContain('IAM');
    expect(rule?.gremlinQueryTemplate).toContain('HAS_IAM_ROLE');
  });

  test('should find crown jewel attack path rule', () => {
    const rule = getRuleById('RULE-005');
    expect(rule?.name).toContain('Crown Jewel');
    expect(rule?.gremlinQueryTemplate).toContain('crown_jewel');
  });

  test('should find cross-account IAM trust rule', () => {
    const rule = getRuleById('RULE-006');
    expect(rule?.name).toContain('Cross-Account');
    expect(rule?.gremlinQueryTemplate).toContain('TRUSTS');
  });

  test('should find public S3 bucket rule', () => {
    const rule = getRuleById('RULE-007');
    expect(rule?.name).toContain('S3');
    expect(rule?.gremlinQueryTemplate).toContain('is_publicly_accessible');
  });

  test('should find RDS public access rule', () => {
    const rule = getRuleById('RULE-008');
    expect(rule?.name).toContain('RDS');
    expect(rule?.gremlinQueryTemplate).toContain('RdsInstance');
  });

  test('should find Lambda VPC rule', () => {
    const rule = getRuleById('RULE-009');
    expect(rule?.name).toContain('Lambda');
    expect(rule?.gremlinQueryTemplate).toContain('LambdaFunction');
  });

  test('should find Secrets Manager rule', () => {
    const rule = getRuleById('RULE-010');
    expect(rule?.name).toContain('Secrets');
    expect(rule?.gremlinQueryTemplate).toContain('Secret');
  });
});

describe('Rule gremlin queries', () => {
  test('RULE-001 should query for restricted S3 access', () => {
    const rule = getRuleById('RULE-001');
    expect(rule?.gremlinQueryTemplate).toContain('restricted');
  });

  test('RULE-002 should query for SSH and RDP ports', () => {
    const rule = getRuleById('RULE-002');
    expect(rule?.gremlinQueryTemplate).toContain('22');
    expect(rule?.gremlinQueryTemplate).toContain('3389');
  });

  test('RULE-003 should query for CRITICAL CVEs', () => {
    const rule = getRuleById('RULE-003');
    expect(rule?.gremlinQueryTemplate).toContain('CRITICAL');
    expect(rule?.gremlinQueryTemplate).toContain('cvss_base_score');
  });

  test('RULE-004 should have threshold for permission count', () => {
    const rule = getRuleById('RULE-004');
    expect(rule?.gremlinQueryTemplate).toContain('gt(5)');
  });

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

  test('rules should not reference non-existent edges', () => {
    for (const rule of riskRules) {
      expect(rule.gremlinQueryTemplate).not.toContain('ALLOWS_ACCESS_TO');
      expect(rule.gremlinQueryTemplate).not.toContain('ALLOWS_INGRESS');
      expect(rule.gremlinQueryTemplate).not.toContain('STORES');
    }
  });
});