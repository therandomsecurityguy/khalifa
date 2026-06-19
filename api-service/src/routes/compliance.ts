import type { Request, Response } from 'express';

type ComplianceFramework = 'CIS_AWS_FOUNDATIONS' | 'SOC2' | 'ISO27001';

interface ComplianceReportItem {
  framework: ComplianceFramework;
  generatedAt: string;
  summary: {
    totalControls: number;
    passed: number;
    failed: number;
    manual: number;
    notApplicable: number;
    notEvaluated: number;
    coveragePercent: number;
  };
}

interface ComplianceControl {
  id: string;
  title: string;
  section: string;
  severity: string;
  automated: boolean;
  status: string;
  relatedRules: string[];
}

interface ComplianceControlResult {
  control: {
    id: string;
    title: string;
    section: string;
    severity: string;
    automated: boolean;
  };
  status: string;
  evidence: unknown[];
  issues: string[];
  lastEvaluated: string;
}

interface ComplianceFullReport {
  framework: ComplianceFramework;
  generatedAt: string;
  summary: ComplianceReportItem['summary'];
  controls: ComplianceControlResult[];
}

const mockReports: Map<ComplianceFramework, ComplianceReportItem> = new Map([
  [
    'CIS_AWS_FOUNDATIONS',
    {
      framework: 'CIS_AWS_FOUNDATIONS',
      generatedAt: new Date().toISOString(),
      summary: {
        totalControls: 78,
        passed: 45,
        failed: 12,
        manual: 8,
        notApplicable: 5,
        notEvaluated: 8,
        coveragePercent: 72,
      },
    },
  ],
  [
    'SOC2',
    {
      framework: 'SOC2',
      generatedAt: new Date().toISOString(),
      summary: {
        totalControls: 22,
        passed: 14,
        failed: 4,
        manual: 4,
        notApplicable: 0,
        notEvaluated: 0,
        coveragePercent: 82,
      },
    },
  ],
  [
    'ISO27001',
    {
      framework: 'ISO27001',
      generatedAt: new Date().toISOString(),
      summary: {
        totalControls: 24,
        passed: 16,
        failed: 3,
        manual: 5,
        notApplicable: 0,
        notEvaluated: 0,
        coveragePercent: 84,
      },
    },
  ],
]);

const mockControls: Record<string, ComplianceControl[]> = {
  CIS_AWS_FOUNDATIONS: [
    {
      id: '1.4',
      title: 'Ensure no root account access key exists',
      section: '1. Identity and Access Management',
      severity: 'critical',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-004'],
    },
    {
      id: '1.5',
      title: 'Ensure MFA is enabled for the root account',
      section: '1. Identity and Access Management',
      severity: 'critical',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-004'],
    },
    {
      id: '1.7',
      title: 'Ensure MFA is enabled for all IAM users with console password',
      section: '1. Identity and Access Management',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-004'],
    },
    {
      id: '1.10',
      title: 'Ensure access keys are rotated every 90 days or less',
      section: '1. Identity and Access Management',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-004'],
    },
    {
      id: '1.11',
      title: 'Ensure IAM users have no unused access keys',
      section: '1. Identity and Access Management',
      severity: 'medium',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-004'],
    },
    {
      id: '1.12',
      title: 'Ensure no IAM users have inline policies',
      section: '1. Identity and Access Management',
      severity: 'medium',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-004', 'RULE-006'],
    },
    {
      id: '1.13',
      title: 'Ensure IAM password policy requires minimum length of 14',
      section: '1. Identity and Access Management',
      severity: 'medium',
      automated: true,
      status: 'PASS',
      relatedRules: [],
    },
    {
      id: '1.14',
      title: 'Ensure IAM password policy prevents password reuse',
      section: '1. Identity and Access Management',
      severity: 'medium',
      automated: true,
      status: 'PASS',
      relatedRules: [],
    },
    {
      id: '1.15',
      title: 'Ensure IAM password policy expires passwords within 90 days',
      section: '1. Identity and Access Management',
      severity: 'medium',
      automated: true,
      status: 'PASS',
      relatedRules: [],
    },
    {
      id: '2.1',
      title: 'Ensure S3 buckets are not publicly accessible',
      section: '2. Storage',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-007'],
    },
    {
      id: '2.2',
      title: 'Ensure S3 buckets have versioning enabled',
      section: '2. Storage',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '2.3',
      title: 'Ensure S3 buckets have server-side encryption enabled',
      section: '2. Storage',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-007'],
    },
    {
      id: '2.4',
      title: 'Ensure S3 bucket access logging is enabled',
      section: '2. Storage',
      severity: 'medium',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '2.6',
      title: 'Ensure EBS volumes are encrypted',
      section: '2. Storage',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: [],
    },
    {
      id: '2.7',
      title: 'Ensure RDS instances are encrypted',
      section: '2. Storage',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-008'],
    },
    {
      id: '2.8',
      title: 'Ensure RDS instances have backup retention >= 7 days',
      section: '2. Storage',
      severity: 'medium',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '2.9',
      title: 'Ensure RDS instances are not publicly accessible',
      section: '2. Storage',
      severity: 'critical',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-008'],
    },
    {
      id: '2.10',
      title: 'Ensure RDS instances have deletion protection enabled',
      section: '2. Storage',
      severity: 'medium',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '3.1',
      title: 'Ensure CloudTrail is enabled in all regions',
      section: '3. Logging',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '3.2',
      title: 'Ensure CloudTrail log file validation is enabled',
      section: '3. Logging',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: [],
    },
    {
      id: '3.3',
      title: 'Ensure CloudTrail logs are encrypted with KMS',
      section: '3. Logging',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '3.4',
      title: 'Ensure CloudTrail logs are sent to CloudWatch Logs',
      section: '3. Logging',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '3.7',
      title: 'Ensure VPC flow logs are enabled',
      section: '3. Logging',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '3.9',
      title: 'Ensure Config is enabled in all regions',
      section: '3. Logging',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '4.1',
      title: 'Ensure GuardDuty is enabled in all regions',
      section: '4. Monitoring',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '4.2',
      title: 'Ensure Security Hub is enabled in all regions',
      section: '4. Monitoring',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '5.1',
      title: 'Ensure no security groups allow 0.0.0.0/0 on port 22',
      section: '5. Networking',
      severity: 'critical',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-002'],
    },
    {
      id: '5.2',
      title: 'Ensure no security groups allow 0.0.0.0/0 on port 3389',
      section: '5. Networking',
      severity: 'critical',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-002'],
    },
    {
      id: '5.3',
      title: 'Ensure default security group restricts all traffic',
      section: '5. Networking',
      severity: 'medium',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-002'],
    },
    {
      id: '5.4',
      title: 'Ensure VPC flow logs are enabled',
      section: '5. Networking',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: '5.7',
      title: 'Ensure VPC endpoints are used for AWS service access',
      section: '5. Networking',
      severity: 'medium',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-009'],
    },
  ],
  SOC2: [
    {
      id: 'CC6.1',
      title: 'Logical Access Security',
      section: 'CC6.1 - Logical Access Security',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-001', 'RULE-002', 'RULE-004', 'RULE-006', 'RULE-010'],
    },
    {
      id: 'CC6.2',
      title: 'Access Credentials',
      section: 'CC6.2 - Access Credentials',
      severity: 'high',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'CC6.3',
      title: 'Access Removal',
      section: 'CC6.3 - Access Removal',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-004'],
    },
    {
      id: 'CC6.4',
      title: 'Access Review',
      section: 'CC6.4 - Access Review',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-004'],
    },
    {
      id: 'CC6.5',
      title: 'Network Segmentation',
      section: 'CC6.5 - Network Segmentation',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-002', 'RULE-005', 'RULE-009'],
    },
    {
      id: 'CC6.6',
      title: 'Encryption',
      section: 'CC6.6 - Encryption',
      severity: 'critical',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-007', 'RULE-008', 'RULE-010'],
    },
    {
      id: 'CC6.7',
      title: 'Mobile/Remote Access',
      section: 'CC6.7 - Mobile/Remote Access',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-001', 'RULE-002'],
    },
    {
      id: 'CC6.8',
      title: 'Data Classification',
      section: 'CC6.8 - Data Classification',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-001', 'RULE-007', 'RULE-008'],
    },
    {
      id: 'CC7.1',
      title: 'System Monitoring',
      section: 'CC7.1 - System Monitoring',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: 'CC7.2',
      title: 'Security Event Monitoring',
      section: 'CC7.2 - Security Event Monitoring',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: 'CC7.3',
      title: 'Vulnerability Management',
      section: 'CC7.3 - Vulnerability Management',
      severity: 'high',
      automated: false,
      status: 'MANUAL',
      relatedRules: ['RULE-003'],
    },
    {
      id: 'CC7.4',
      title: 'Incident Response',
      section: 'CC7.4 - Incident Response',
      severity: 'high',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'CC7.5',
      title: 'Monitoring Personnel',
      section: 'CC7.5 - Monitoring Personnel',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-004', 'RULE-006'],
    },
    {
      id: 'CC8.1',
      title: 'Change Management',
      section: 'CC8.1 - Change Management',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
  ],
  ISO27001: [
    {
      id: 'A.5.1',
      title: 'Policies for information security',
      section: 'A.5 - Information Security Policies',
      severity: 'high',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'A.6.1',
      title: 'Internal organization',
      section: 'A.6 - Organization of Information Security',
      severity: 'high',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'A.8.1',
      title: 'Responsibility for assets',
      section: 'A.8 - Asset Management',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: [],
    },
    {
      id: 'A.8.2',
      title: 'Information classification',
      section: 'A.8 - Asset Management',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-001', 'RULE-007', 'RULE-008'],
    },
    {
      id: 'A.8.3',
      title: 'Media handling',
      section: 'A.8 - Asset Management',
      severity: 'medium',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'A.9.1',
      title: 'Access control policy',
      section: 'A.9 - Access Control',
      severity: 'high',
      automated: false,
      status: 'MANUAL',
      relatedRules: ['RULE-004', 'RULE-006'],
    },
    {
      id: 'A.9.2',
      title: 'User access management',
      section: 'A.9 - Access Control',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-004', 'RULE-006'],
    },
    {
      id: 'A.9.3',
      title: 'User responsibilities',
      section: 'A.9 - Access Control',
      severity: 'medium',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'A.9.4',
      title: 'System and application access control',
      section: 'A.9 - Access Control',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-001', 'RULE-002', 'RULE-004', 'RULE-009', 'RULE-010'],
    },
    {
      id: 'A.10.1',
      title: 'Cryptographic controls',
      section: 'A.10 - Cryptography',
      severity: 'critical',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-007', 'RULE-008', 'RULE-010'],
    },
    {
      id: 'A.12.1',
      title: 'Operational procedures and responsibilities',
      section: 'A.12 - Operations Security',
      severity: 'high',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'A.12.2',
      title: 'Change management',
      section: 'A.12 - Operations Security',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: 'A.12.3',
      title: 'Capacity management',
      section: 'A.12 - Operations Security',
      severity: 'medium',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'A.12.4',
      title: 'Logging and monitoring',
      section: 'A.12 - Operations Security',
      severity: 'critical',
      automated: true,
      status: 'FAIL',
      relatedRules: [],
    },
    {
      id: 'A.12.5',
      title: 'Control of operational software',
      section: 'A.12 - Operations Security',
      severity: 'medium',
      automated: false,
      status: 'MANUAL',
      relatedRules: [],
    },
    {
      id: 'A.12.6',
      title: 'Technical vulnerability management',
      section: 'A.12 - Operations Security',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-003'],
    },
    {
      id: 'A.13.1',
      title: 'Network controls',
      section: 'A.13 - Communications Security',
      severity: 'high',
      automated: true,
      status: 'FAIL',
      relatedRules: ['RULE-002', 'RULE-005', 'RULE-009'],
    },
    {
      id: 'A.13.2',
      title: 'Information transfer',
      section: 'A.13 - Communications Security',
      severity: 'high',
      automated: true,
      status: 'PASS',
      relatedRules: ['RULE-007', 'RULE-008', 'RULE-009', 'RULE-010'],
    },
  ],
};

export async function listFrameworks(req: Request, res: Response): Promise<void> {
  try {
    const frameworks = Array.from(mockReports.entries()).map(([framework, report]) => ({
      framework,
      ...report.summary,
      lastAssessment: report.generatedAt,
    }));

    res.json({
      frameworks,
      totalFrameworks: frameworks.length,
    });
  } catch (error) {
    console.error('Error listing frameworks:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to list frameworks',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getFrameworkSummary(req: Request, res: Response): Promise<void> {
  try {
    const { framework } = req.params;

    if (!['CIS_AWS_FOUNDATIONS', 'SOC2', 'ISO27001'].includes(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: 'Invalid framework. Must be one of: CIS_AWS_FOUNDATIONS, SOC2, ISO27001',
      });
      return;
    }

    const report = mockReports.get(framework as ComplianceFramework);
    if (!report) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `No assessment found for framework: ${framework}`,
      });
      return;
    }

    const controls = mockControls[framework] || [];
    const sections = [...new Set(controls.map((c) => c.section))];

    res.json({
      framework: report.framework,
      version: framework === 'CIS_AWS_FOUNDATIONS' ? '3.0.0' : '2022',
      totalControls: report.summary.totalControls,
      automatedControls: controls.filter((c) => c.automated).length,
      manualControls: controls.filter((c) => !c.automated).length,
      coveragePercent: report.summary.coveragePercent,
      lastAssessment: report.generatedAt,
      sections,
      summary: report.summary,
    });
  } catch (error) {
    console.error('Error getting framework summary:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get framework summary',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getFrameworkControls(req: Request, res: Response): Promise<void> {
  try {
    const { framework } = req.params;
    const { section, status, severity, automated } = req.query;

    if (!['CIS_AWS_FOUNDATIONS', 'SOC2', 'ISO27001'].includes(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: 'Invalid framework. Must be one of: CIS_AWS_FOUNDATIONS, SOC2, ISO27001',
      });
      return;
    }

    let controls = mockControls[framework] || [];

    if (section) {
      controls = controls.filter((c) => c.section === section);
    }
    if (status) {
      controls = controls.filter((c) => c.status === status);
    }
    if (severity) {
      controls = controls.filter((c) => c.severity === severity);
    }
    if (automated !== undefined) {
      const isAutomated = automated === 'true';
      controls = controls.filter((c) => c.automated === isAutomated);
    }

    const report = mockReports.get(framework as ComplianceFramework);

    res.json({
      framework,
      totalControls: controls.length,
      controls: controls.map((c) => ({
        ...c,
        lastEvaluated: report?.generatedAt,
      })),
    });
  } catch (error) {
    console.error('Error getting framework controls:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get framework controls',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getControlDetails(req: Request, res: Response): Promise<void> {
  try {
    const { framework, controlId } = req.params;

    if (!['CIS_AWS_FOUNDATIONS', 'SOC2', 'ISO27001'].includes(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: 'Invalid framework',
      });
      return;
    }

    const controls = mockControls[framework] || [];
    const control = controls.find((c) => c.id === controlId);

    if (!control) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `Control ${controlId} not found in ${framework}`,
      });
      return;
    }

    const report = mockReports.get(framework as ComplianceFramework);

    res.json({
      ...control,
      framework,
      lastEvaluated: report?.generatedAt,
      evidence: [
        {
          controlId: control.id,
          resourceId: 'example-resource',
          resourceType: 'ExampleResource',
          status: control.status,
          details: { checkedAt: new Date().toISOString() },
          collectedAt: new Date().toISOString(),
          collectedBy: 'compliance-engine',
        },
      ],
      relatedIssues:
        control.relatedRules?.map((ruleId: string) => ({
          ruleId,
          severity: 'high',
          status: 'open',
        })) || [],
    });
  } catch (error) {
    console.error('Error getting control details:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get control details',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getComplianceReport(req: Request, res: Response): Promise<void> {
  try {
    const { framework } = req.params;
    const { format } = req.query;

    if (!['CIS_AWS_FOUNDATIONS', 'SOC2', 'ISO27001'].includes(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: 'Invalid framework',
      });
      return;
    }

    const report = mockReports.get(framework as ComplianceFramework);
    const controls = mockControls[framework] || [];

    if (!report) {
      res.status(404).json({
        code: 'NOT_FOUND',
        message: `No assessment found for ${framework}`,
      });
      return;
    }

    const controlResults = controls.map((c) => ({
      control: {
        id: c.id,
        title: c.title,
        section: c.section,
        severity: c.severity,
        automated: c.automated,
      },
      status: c.status,
      evidence: [],
      issues: c.status === 'FAIL' ? [`Control ${c.id} failed`] : [],
      lastEvaluated: report.generatedAt,
    }));

    const fullReport = {
      framework: report.framework,
      generatedAt: report.generatedAt,
      summary: report.summary,
      controls: controlResults,
    };

    if (format === 'csv') {
      const csv = generateCSVReport(fullReport);
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader(
        'Content-Disposition',
        `attachment; filename="${framework}-report-${Date.now()}.csv"`
      );
      res.send(csv);
      return;
    }

    res.json(fullReport);
  } catch (error) {
    console.error('Error generating compliance report:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to generate compliance report',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

export async function getDriftReport(req: Request, res: Response): Promise<void> {
  try {
    const { framework } = req.params;

    if (!['CIS_AWS_FOUNDATIONS', 'SOC2', 'ISO27001'].includes(framework)) {
      res.status(400).json({
        code: 'INVALID_FRAMEWORK',
        message: 'Invalid framework',
      });
      return;
    }

    const controls = mockControls[framework] || [];
    const failedControls = controls.filter((c) => c.status === 'FAIL' && c.automated);

    const driftItems = failedControls.map((c) => ({
      controlId: c.id,
      controlTitle: c.title,
      section: c.section,
      severity: c.severity,
      detectedAt: new Date().toISOString(),
      description: `Control ${c.id} (${c.title}) is currently failing`,
      relatedRules: c.relatedRules,
      remediation: getRemediationHint(c.id),
    }));

    res.json({
      framework,
      generatedAt: new Date().toISOString(),
      totalDriftItems: driftItems.length,
      criticalDrift: driftItems.filter((d) => d.severity === 'critical').length,
      highDrift: driftItems.filter((d) => d.severity === 'high').length,
      mediumDrift: driftItems.filter((d) => d.severity === 'medium').length,
      lowDrift: driftItems.filter((d) => d.severity === 'low').length,
      driftItems,
    });
  } catch (error) {
    console.error('Error getting drift report:', error);
    res.status(500).json({
      code: 'INTERNAL_ERROR',
      message: 'Failed to get drift report',
      details: error instanceof Error ? error.message : undefined,
    });
  }
}

function getRemediationHint(controlId: string): string {
  const hints: Record<string, string> = {
    '1.4': 'Delete any root access keys. Use IAM users/roles instead.',
    '1.5': 'Enable MFA for the root account in IAM console.',
    '1.7': 'Enforce MFA for all IAM users with console access.',
    '1.10': 'Rotate access keys older than 90 days. Implement automated rotation.',
    '1.11': 'Delete access keys unused for 90+ days.',
    '1.12': 'Move inline policies to managed policies.',
    '2.1': 'Enable S3 Block Public Access. Remove public bucket policies/ACLs.',
    '2.2': 'Enable versioning on all S3 buckets.',
    '2.3': 'Enable default encryption (SSE-S3 or SSE-KMS) on all S3 buckets.',
    '2.4': 'Configure access logging on all S3 buckets.',
    '2.8': 'Set RDS backup retention to 7 days or more.',
    '2.10': 'Enable deletion protection on all RDS instances.',
    '3.1': 'Create a multi-region CloudTrail trail.',
    '3.3': 'Configure KMS encryption for CloudTrail logs.',
    '3.4': 'Configure CloudTrail to send logs to CloudWatch Logs.',
    '3.7': 'Enable VPC flow logs for all VPCs.',
    '3.9': 'Enable AWS Config in all regions with all resource types.',
    '4.1': 'Enable GuardDuty in all regions.',
    '4.2': 'Enable Security Hub in all regions.',
    '5.3': 'Remove all rules from default security groups.',
    '5.4': 'Enable VPC flow logs for all VPCs.',
    '5.7': 'Create VPC endpoints for S3, DynamoDB, and other services.',
    'CC6.1': 'Implement least-privilege IAM. Enforce MFA. Encrypt data at rest and in transit.',
    'CC6.4': 'Conduct quarterly access reviews. Use IAM Access Analyzer.',
    'CC6.5': 'Implement network segmentation with separate VPCs/subnets per environment.',
    'CC6.8': 'Implement data classification tagging. Apply controls based on classification.',
    'CC7.1': 'Enable GuardDuty, Security Hub. Create CloudWatch alarms for critical events.',
    'CC7.2': 'Centralize logs in SIEM. Correlate CloudTrail, VPC flow logs, GuardDuty findings.',
    'CC8.1': 'Implement IaC with PR reviews. Use Config for drift detection.',
    'A.8.2':
      'Define classification levels (Public, Internal, Restricted, Secret). Tag all data stores.',
    'A.9.2': 'Automate user lifecycle. Conduct regular access reviews. Revoke access promptly.',
    'A.9.4': 'Implement least-privilege access. Use IAM roles, security groups, application RBAC.',
    'A.12.2': 'Implement IaC with PR reviews. Use Config for drift detection.',
    'A.12.4':
      'Enable comprehensive logging. Protect log integrity. Implement centralized analysis.',
    'A.12.6':
      'Implement continuous vulnerability scanning. Define remediation SLAs. Track CVE exposure.',
    'A.13.1':
      'Segment networks. Restrict traffic with security groups and NACLs. Monitor network traffic.',
  };

  return (
    hints[controlId] ||
    'Review and remediate the identified security issue according to best practices.'
  );
}

function generateCSVReport(report: ComplianceFullReport): string {
  const headers = [
    'Control ID',
    'Title',
    'Section',
    'Severity',
    'Automated',
    'Status',
    'Last Evaluated',
    'Issues',
  ];
  const rows = report.controls.map((c) => [
    c.control.id,
    c.control.title,
    c.control.section,
    c.control.severity,
    c.control.automated ? 'Yes' : 'No',
    c.status,
    c.lastEvaluated,
    c.issues.join('; '),
  ]);

  return [headers.join(','), ...rows.map((r: string[]) => r.map((v) => `"${v}"`).join(','))].join(
    '\n'
  );
}
