"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const scoring_1 = require("./scoring");
describe('computeRiskScore', () => {
    const baseInput = {
        exposureLevel: 'internal',
        dataClassification: 'public',
        environment: 'dev',
        isCrownJewel: false,
    };
    test('should return low severity for minimal risk input', () => {
        const result = (0, scoring_1.computeRiskScore)(baseInput);
        expect(result.severity).toBe('low');
        expect(result.score).toBeLessThan(20);
    });
    test('should return critical severity for high risk input', () => {
        const input = {
            cvss: {
                baseScore: 9.8,
                exploitabilitySubScore: 3.9,
                impactSubScore: 5.9,
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            },
            exploitabilityFlags: { hasExploit: true, hasPublicExploit: true, malwareAvailable: false },
            exposureLevel: 'internet',
            identityBlastRadius: { type: 'admin', scope: 1 },
            dataClassification: 'restricted',
            environment: 'prod',
            isCrownJewel: true,
            attackPathLength: 2,
        };
        const result = (0, scoring_1.computeRiskScore)(input);
        expect(result.severity).toBe('critical');
        expect(result.score).toBeGreaterThanOrEqual(80);
    });
    test('should return high severity for medium-high risk input', () => {
        const input = {
            cvss: {
                baseScore: 7.5,
                exploitabilitySubScore: 2.5,
                impactSubScore: 5.9,
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            },
            exposureLevel: 'cross-account',
            dataClassification: 'secret',
            environment: 'prod',
            isCrownJewel: true,
            attackPathLength: 2,
        };
        const result = (0, scoring_1.computeRiskScore)(input);
        expect(result.severity).toBe('critical');
        expect(result.score).toBeGreaterThanOrEqual(60);
    });
    test('should apply crown jewel bonus', () => {
        const withCrownJewel = (0, scoring_1.computeRiskScore)({ ...baseInput, isCrownJewel: true });
        const withoutCrownJewel = (0, scoring_1.computeRiskScore)({ ...baseInput, isCrownJewel: false });
        expect(withCrownJewel.score).toBeGreaterThan(withoutCrownJewel.score);
    });
    test('should apply environment weights correctly', () => {
        const prodInput = (0, scoring_1.computeRiskScore)({ ...baseInput, environment: 'prod' });
        const devInput = (0, scoring_1.computeRiskScore)({ ...baseInput, environment: 'dev' });
        expect(prodInput.score).toBeGreaterThan(devInput.score);
    });
    test('should apply data classification weights correctly', () => {
        const restrictedInput = (0, scoring_1.computeRiskScore)({ ...baseInput, dataClassification: 'restricted' });
        const publicInput = (0, scoring_1.computeRiskScore)({ ...baseInput, dataClassification: 'public' });
        expect(restrictedInput.score).toBeGreaterThan(publicInput.score);
    });
    test('should apply exposure level weights correctly', () => {
        const internetInput = (0, scoring_1.computeRiskScore)({ ...baseInput, exposureLevel: 'internet' });
        const internalInput = (0, scoring_1.computeRiskScore)({ ...baseInput, exposureLevel: 'internal' });
        expect(internetInput.score).toBeGreaterThan(internalInput.score);
    });
    test('should apply identity blast radius correctly', () => {
        const adminInput = (0, scoring_1.computeRiskScore)({
            ...baseInput,
            identityBlastRadius: { type: 'admin', scope: 1 },
        });
        const noIdentityInput = (0, scoring_1.computeRiskScore)({ ...baseInput });
        expect(adminInput.score).toBeGreaterThan(noIdentityInput.score);
    });
    test('should return all factor contributions', () => {
        const input = {
            cvss: {
                baseScore: 9.0,
                exploitabilitySubScore: 3.0,
                impactSubScore: 5.0,
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            },
            exposureLevel: 'internet',
            dataClassification: 'secret',
            environment: 'prod',
            isCrownJewel: true,
        };
        const result = (0, scoring_1.computeRiskScore)(input);
        expect(result.factors).toHaveProperty('cvssContribution');
        expect(result.factors).toHaveProperty('exposureContribution');
        expect(result.factors).toHaveProperty('dataClassificationContribution');
        expect(result.factors).toHaveProperty('environmentContribution');
    });
    test('should handle missing optional fields', () => {
        const result = (0, scoring_1.computeRiskScore)({
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
    test('should return specific hint for RULE-001', () => {
        const hint = (0, scoring_1.getRemediationHint)('RULE-001', {});
        expect(hint).toContain('IAM role');
    });
    test('should return specific hint for RULE-002', () => {
        const hint = (0, scoring_1.getRemediationHint)('RULE-002', {});
        expect(hint).toContain('SSH');
    });
    test('should return default hint for unknown rule', () => {
        const hint = (0, scoring_1.getRemediationHint)('RULE-999', {});
        expect(hint).toContain('best practices');
    });
});
describe('extractResourcesFromPath', () => {
    test('should extract resource IDs from path', () => {
        const path = [
            { id: 'ec2-1', label: 'EC2Instance', properties: {} },
            { id: 'role-1', label: 'IAMRole', properties: {} },
            { id: 's3-1', label: 'S3Bucket', properties: {} },
        ];
        const result = (0, scoring_1.extractResourcesFromPath)(path);
        expect(result.resourceIds).toContain('ec2-1');
        expect(result.resourceIds).toContain('s3-1');
        expect(result.resourceIds).toContain('role-1');
    });
    test('should return unique resource IDs', () => {
        const path = [
            { id: 'ec2-1', label: 'EC2Instance', properties: {} },
            { id: 'ec2-1', label: 'EC2Instance', properties: {} },
        ];
        const result = (0, scoring_1.extractResourcesFromPath)(path);
        expect(result.resourceIds.length).toBe(1);
    });
    test('should return empty arrays for empty path', () => {
        const result = (0, scoring_1.extractResourcesFromPath)([]);
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
        const result = (0, scoring_1.calculatePathSummary)(path);
        expect(result.segments).toHaveLength(2);
        expect(result.segments[0]).toEqual({ from: 'ec2-1', to: 'role-1', edgeType: 'IAMRole' });
        expect(result.segments[1]).toEqual({ from: 'role-1', to: 's3-1', edgeType: 'S3Bucket' });
    });
    test('should return empty segments for path with less than 2 nodes', () => {
        const path = [{ id: 'ec2-1', label: 'EC2Instance', properties: {} }];
        const result = (0, scoring_1.calculatePathSummary)(path);
        expect(result.segments).toHaveLength(0);
    });
});
//# sourceMappingURL=scoring.test.js.map