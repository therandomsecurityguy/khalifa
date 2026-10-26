import {
  computeRiskScore,
  getRemediationHint,
  extractResourcesFromPath,
  calculatePathSummary,
  riskInputFromPath,
} from './scoring';
import type { RiskScoreInput } from './types';
import { riskRules } from './rules';

describe('computeRiskScore', () => {
  const baseInput: RiskScoreInput = {
    exposureLevel: 'internal',
    dataClassification: 'public',
    environment: 'dev',
    isCrownJewel: false,
  };

  test('should return low severity for minimal risk input', () => {
    const result = computeRiskScore(baseInput);
    expect(result.severity).toBe('low');
    expect(result.score).toBeLessThan(20);
  });

  test('should return critical severity for high risk input', () => {
    const input: RiskScoreInput = {
      exposureLevel: 'internet',
      identityBlastRadius: { type: 'admin', scope: 1 },
      dataClassification: 'restricted',
      environment: 'prod',
      isCrownJewel: true,
      attackPathLength: 2,
    };
    const result = computeRiskScore(input);
    expect(result.severity).toBe('critical');
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  test('should return high severity for medium-high risk input', () => {
    const input: RiskScoreInput = {
      exposureLevel: 'cross-account',
      dataClassification: 'secret',
      environment: 'prod',
      isCrownJewel: true,
      attackPathLength: 2,
    };
    const result = computeRiskScore(input);
    expect(result.severity).toBe('critical');
    expect(result.score).toBeGreaterThanOrEqual(60);
  });

  test('reaches critical for a critical-hinted finding without CVSS data', () => {
    const result = computeRiskScore({
      exposureLevel: 'internet',
      identityBlastRadius: { type: 'admin', scope: 1 },
      dataClassification: 'restricted',
      environment: 'prod',
      isCrownJewel: false,
    });
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(result.severity).toBe('critical');
  });

  test('applies crown jewel bonus', () => {
    const withCrownJewel = computeRiskScore({ ...baseInput, isCrownJewel: true });
    const withoutCrownJewel = computeRiskScore({ ...baseInput, isCrownJewel: false });
    expect(withCrownJewel.score).toBeGreaterThan(withoutCrownJewel.score);
  });

  test('should apply environment weights correctly', () => {
    const prodInput = computeRiskScore({ ...baseInput, environment: 'prod' });
    const devInput = computeRiskScore({ ...baseInput, environment: 'dev' });
    expect(prodInput.score).toBeGreaterThan(devInput.score);
  });

  test('should apply data classification weights correctly', () => {
    const restrictedInput = computeRiskScore({ ...baseInput, dataClassification: 'restricted' });
    const publicInput = computeRiskScore({ ...baseInput, dataClassification: 'public' });
    expect(restrictedInput.score).toBeGreaterThan(publicInput.score);
  });

  test('should apply exposure level weights correctly', () => {
    const internetInput = computeRiskScore({ ...baseInput, exposureLevel: 'internet' });
    const internalInput = computeRiskScore({ ...baseInput, exposureLevel: 'internal' });
    expect(internetInput.score).toBeGreaterThan(internalInput.score);
  });

  test('should apply identity blast radius correctly', () => {
    const adminInput = computeRiskScore({
      ...baseInput,
      identityBlastRadius: { type: 'admin', scope: 1 },
    });
    const noIdentityInput = computeRiskScore({ ...baseInput });
    expect(adminInput.score).toBeGreaterThan(noIdentityInput.score);
  });

  test('should return all factor contributions', () => {
    const input: RiskScoreInput = {
      exposureLevel: 'internet',
      dataClassification: 'secret',
      environment: 'prod',
      isCrownJewel: true,
    };
    const result = computeRiskScore(input);
    expect(result.factors).toHaveProperty('exposureContribution');
    expect(result.factors).toHaveProperty('dataClassificationContribution');
    expect(result.factors).toHaveProperty('environmentContribution');
  });

  test('should handle missing optional fields', () => {
    const result = computeRiskScore({
      exposureLevel: 'internal',
      dataClassification: 'public',
      environment: 'dev',
      isCrownJewel: false,
    });
    expect(result.score).toBeDefined();
    expect(result.severity).toBeDefined();
  });
});

describe('getRemediationHint', () => {
  test('every rule has its own hint', () => {
    const fallback = getRemediationHint('RULE-999', {});
    expect(fallback).toContain('best practices');
    const missing = riskRules
      .map((rule) => rule.id)
      .filter((id) => getRemediationHint(id, {}) === fallback);
    expect(missing).toEqual([]);
  });

  test('names the concrete fix', () => {
    expect(getRemediationHint('RULE-002', {})).toContain('0.0.0.0/0');
    expect(getRemediationHint('RULE-013', {})).toContain('IAM role');
  });
});

describe('extractResourcesFromPath', () => {
  test('should extract resource IDs from path', () => {
    const path = [
      { id: 'ec2-1', label: 'EC2Instance', properties: {} },
      { id: 'role-1', label: 'IAMRole', properties: {} },
      { id: 's3-1', label: 'S3Bucket', properties: {} },
    ];
    const result = extractResourcesFromPath(path);
    expect(result.resourceIds).toContain('ec2-1');
    expect(result.resourceIds).toContain('s3-1');
    expect(result.resourceIds).toContain('role-1');
  });

  test('should return unique resource IDs', () => {
    const path = [
      { id: 'ec2-1', label: 'EC2Instance', properties: {} },
      { id: 'ec2-1', label: 'EC2Instance', properties: {} },
    ];
    const result = extractResourcesFromPath(path);
    expect(result.resourceIds.length).toBe(1);
  });

  test('should return empty arrays for empty path', () => {
    const result = extractResourcesFromPath([]);
    expect(result.resourceIds).toEqual([]);
    expect(result.resourceTypes).toEqual([]);
  });
});

describe('calculatePathSummary', () => {
  test('should calculate path segments correctly', () => {
    const path = [
      { id: 'ec2-1', label: 'EC2Instance', properties: {} },
      { id: 'role-1', label: 'IAMRole', properties: {} },
      { id: 's3-1', label: 'S3Bucket', properties: {} },
    ];
    const result = calculatePathSummary(path);
    expect(result.segments).toHaveLength(2);
    expect(result.segments[0]).toEqual({ from: 'ec2-1', to: 'role-1', edgeType: 'IAMRole' });
    expect(result.segments[1]).toEqual({ from: 'role-1', to: 's3-1', edgeType: 'S3Bucket' });
  });

  test('should return empty segments for path with less than 2 nodes', () => {
    const path = [{ id: 'ec2-1', label: 'EC2Instance', properties: {} }];
    const result = calculatePathSummary(path);
    expect(result.segments).toHaveLength(0);
  });
});

describe('exploitability factor', () => {
  const vulnerable: RiskScoreInput = {
    exposureLevel: 'internet',
    dataClassification: 'restricted',
    environment: 'prod',
    isCrownJewel: false,
  };

  test('adds nothing for findings with no vulnerability data', () => {
    const result = computeRiskScore(vulnerable);
    expect(result.factors.exploitabilityContribution).toBe(0);
  });

  test('raises the score by the CVSS share, more when an exploit is known', () => {
    const noCve = computeRiskScore(vulnerable);
    const cve = computeRiskScore({
      ...vulnerable,
      exploitability: { cvssBaseScore: 9.8 },
    });
    const exploited = computeRiskScore({
      ...vulnerable,
      exploitability: { cvssBaseScore: 9.8, exploitAvailable: true },
    });

    expect(cve.factors.exploitabilityContribution).toBe(14.7);
    expect(exploited.factors.exploitabilityContribution).toBe(15);
    expect(cve.score).toBeGreaterThan(noCve.score);
    expect(exploited.score).toBeGreaterThan(cve.score);
  });

  test('caps at the weight even with an exploit and an unreadable CVSS', () => {
    const result = computeRiskScore({
      ...vulnerable,
      exploitability: { exploitAvailable: true },
    });
    expect(result.factors.exploitabilityContribution).toBe(10.5);
  });
});

describe('riskInputFromPath exploitability', () => {
  test('reads the highest CVSS and exploit flag from Vulnerability vertices', () => {
    const input = riskInputFromPath([
      { id: 'ec2', label: 'Ec2Instance', properties: { is_internet_exposed: true } },
      {
        id: 'cve-low',
        label: 'Vulnerability',
        properties: { cvss_base_score: 7.5, exploit_available: false },
      },
      {
        id: 'cve-high',
        label: 'Vulnerability',
        properties: { cvss_base_score: 9.8, exploit_available: true },
      },
    ]);
    expect(input.exploitability).toEqual({ cvssBaseScore: 9.8, exploitAvailable: true });
  });

  test('leaves exploitability unset when the path has no findings', () => {
    const input = riskInputFromPath([
      { id: 'ec2', label: 'Ec2Instance', properties: { is_internet_exposed: true } },
    ]);
    expect(input.exploitability).toBeUndefined();
  });
});

describe('riskInputFromPath reachability', () => {
  test('marks reachability restricted when a vertex read was restricted', () => {
    const input = riskInputFromPath([
      { id: 'ec2', label: 'Ec2Instance', properties: { is_internet_exposed: true } },
      {
        id: 'fn',
        label: 'LambdaFunction',
        properties: { lambda_exposure_restricted: true },
      },
    ]);
    expect(input.reachabilityRestricted).toBe(true);
  });

  test('leaves reachability derived when every vertex was readable', () => {
    const input = riskInputFromPath([
      { id: 'ec2', label: 'Ec2Instance', properties: { is_internet_exposed: true } },
    ]);
    expect(input.reachabilityRestricted).toBeUndefined();
  });
});

describe('riskInputFromPath observed reachability', () => {
  test('reads traffic_observed from a workload vertex', () => {
    const input = riskInputFromPath([
      {
        id: 'ec2',
        label: 'Ec2Instance',
        properties: { is_internet_exposed: true, traffic_observed: true },
      },
    ]);
    expect(input.reachabilityObserved).toBe(true);
  });

  test('leaves observation unset without the fact', () => {
    const input = riskInputFromPath([
      { id: 'ec2', label: 'Ec2Instance', properties: { is_internet_exposed: true } },
    ]);
    expect(input.reachabilityObserved).toBeUndefined();
  });
});
