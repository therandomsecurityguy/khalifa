"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
describe('Types', () => {
    describe('Severity type', () => {
        test('should accept valid severity values', () => {
            const severities = ['critical', 'high', 'medium', 'low'];
            for (const severity of severities) {
                expect(severity).toBeDefined();
            }
        });
    });
    describe('IssueStatus type', () => {
        test('should accept valid issue status values', () => {
            const statuses = ['open', 'resolved', 'suppressed'];
            for (const status of statuses) {
                expect(status).toBeDefined();
            }
        });
    });
    describe('ExposureLevel type', () => {
        test('should accept valid exposure level values', () => {
            const levels = ['internet', 'cross-account', 'internal'];
            for (const level of levels) {
                expect(level).toBeDefined();
            }
        });
    });
    describe('DataClassification type', () => {
        test('should accept valid data classification values', () => {
            const classifications = ['public', 'internal', 'restricted', 'secret'];
            for (const classification of classifications) {
                expect(classification).toBeDefined();
            }
        });
    });
    describe('Environment type', () => {
        test('should accept valid environment values', () => {
            const environments = ['prod', 'staging', 'dev'];
            for (const env of environments) {
                expect(env).toBeDefined();
            }
        });
    });
    describe('RiskFactor interface', () => {
        test('should create valid RiskFactor object', () => {
            const riskFactor = {
                name: 'cvss',
                weight: 0.25,
                value: 9.8,
            };
            expect(riskFactor.name).toBe('cvss');
            expect(riskFactor.weight).toBe(0.25);
            expect(riskFactor.value).toBe(9.8);
        });
    });
    describe('RiskRule interface', () => {
        test('should create valid RiskRule object', () => {
            const rule = {
                id: 'RULE-001',
                name: 'Test Rule',
                description: 'Test description',
                severityHint: 'high',
                riskFactors: [],
                gremlinQueryTemplate: 'g.V()',
                ownerTeam: 'security',
                enabled: true,
                autoTicketConfig: { enabled: false },
            };
            expect(rule.id).toBe('RULE-001');
            expect(rule.enabled).toBe(true);
        });
    });
    describe('Issue interface', () => {
        test('should create valid Issue object', () => {
            const issue = {
                id: 'issue-001',
                ruleId: 'RULE-001',
                resourcesInvolved: [],
                pathSummary: [],
                riskScore: 85,
                severity: 'high',
                status: 'open',
                createdAt: '2024-01-01T00:00:00Z',
                updatedAt: '2024-01-01T00:00:00Z',
                owningTeam: 'security',
                remediationHint: 'Fix this issue',
                metadata: {},
            };
            expect(issue.id).toBeDefined();
            expect(issue.riskScore).toBe(85);
            expect(issue.severity).toBe('high');
        });
    });
    describe('RuleExecutionResult interface', () => {
        test('should create valid RuleExecutionResult object', () => {
            const result = {
                ruleId: 'RULE-001',
                executionTime: 1000,
                matches: [],
                issuesCreated: 5,
                issuesResolved: 2,
            };
            expect(result.ruleId).toBe('RULE-001');
            expect(result.executionTime).toBe(1000);
            expect(result.issuesCreated).toBe(5);
            expect(result.issuesResolved).toBe(2);
        });
        test('should include errors when present', () => {
            const result = {
                ruleId: 'RULE-001',
                executionTime: 1000,
                matches: [],
                issuesCreated: 0,
                issuesResolved: 0,
                errors: ['Error 1', 'Error 2'],
            };
            expect(result.errors).toHaveLength(2);
        });
    });
    describe('GraphVertex interface', () => {
        test('should create valid GraphVertex object', () => {
            const vertex = {
                id: 'vertex-001',
                label: 'EC2Instance',
                properties: { name: 'test-instance' },
            };
            expect(vertex.id).toBe('vertex-001');
            expect(vertex.label).toBe('EC2Instance');
        });
    });
    describe('GraphEdge interface', () => {
        test('should create valid GraphEdge object', () => {
            const edge = {
                id: 'edge-001',
                label: 'ALLOWS_ACCESS_TO',
                from: 'from-001',
                to: 'to-001',
            };
            expect(edge.id).toBe('edge-001');
            expect(edge.label).toBe('ALLOWS_ACCESS_TO');
        });
    });
    describe('CvssScore interface', () => {
        test('should create valid CvssScore object', () => {
            const cvss = {
                baseScore: 9.8,
                exploitabilitySubScore: 3.9,
                impactSubScore: 5.9,
                vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            };
            expect(cvss.baseScore).toBe(9.8);
            expect(cvss.vectorString).toContain('CVSS:3.1');
        });
    });
    describe('IdentityBlastRadius interface', () => {
        test('should create valid IdentityBlastRadius object', () => {
            const blastRadius = {
                type: 'admin',
                scope: 10,
            };
            expect(blastRadius.type).toBe('admin');
            expect(blastRadius.scope).toBe(10);
        });
    });
    describe('RiskScoreInput interface', () => {
        test('should create valid RiskScoreInput object', () => {
            const input = {
                cvss: { baseScore: 9.0, exploitabilitySubScore: 3.0, impactSubScore: 5.0, vectorString: 'test' },
                exploitabilityFlags: { hasExploit: true, hasPublicExploit: false, malwareAvailable: false },
                exposureLevel: 'internet',
                identityBlastRadius: { type: 'admin', scope: 1 },
                dataClassification: 'restricted',
                environment: 'prod',
                attackPathLength: 3,
                isCrownJewel: true,
            };
            expect(input.exposureLevel).toBe('internet');
            expect(input.isCrownJewel).toBe(true);
        });
        test('should allow minimal RiskScoreInput', () => {
            const input = {
                exposureLevel: 'internal',
                dataClassification: 'public',
                environment: 'dev',
                isCrownJewel: false,
            };
            expect(input.exposureLevel).toBe('internal');
        });
    });
    describe('RiskScoreOutput interface', () => {
        test('should create valid RiskScoreOutput object', () => {
            const output = {
                score: 85,
                severity: 'high',
                factors: {
                    cvssContribution: 22.5,
                    exposureContribution: 20,
                    identityContribution: 20,
                    dataClassificationContribution: 16,
                    environmentContribution: 15,
                    crownJewelContribution: 0,
                },
            };
            expect(output.score).toBe(85);
            expect(output.severity).toBe('high');
            expect(output.factors.cvssContribution).toBe(22.5);
        });
    });
});
//# sourceMappingURL=types.test.js.map