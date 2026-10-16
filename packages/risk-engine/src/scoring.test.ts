import {
  computeRiskScore,
  getRemediationHint,
  extractResourcesFromPath,
  calculatePathSummary,
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
