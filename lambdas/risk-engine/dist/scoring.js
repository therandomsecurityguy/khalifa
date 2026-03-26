"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeRiskScore = computeRiskScore;
exports.extractResourcesFromPath = extractResourcesFromPath;
exports.calculatePathSummary = calculatePathSummary;
exports.getRemediationHint = getRemediationHint;
const EXPOSURE_WEIGHTS = {
    internet: 1.0,
    "cross-account": 0.7,
    internal: 0.3,
};
const DATA_CLASSIFICATION_WEIGHTS = {
    secret: 1.0,
    restricted: 0.8,
    internal: 0.5,
    public: 0.1,
};
const ENVIRONMENT_WEIGHTS = {
    prod: 1.0,
    staging: 0.6,
    dev: 0.3,
};
const IDENTITY_BLAST_RADIUS_WEIGHTS = {
    admin: 1.0,
    wildcard: 0.9,
    'cross-account': 0.7,
    'service-linked': 0.4,
};
const SEVERITY_THRESHOLDS = {
    critical: 80,
    high: 60,
    medium: 40,
    low: 20,
};
function computeRiskScore(input) {
    let cvssContribution = 0;
    let exposureContribution = 0;
    let identityContribution = 0;
    let dataClassificationContribution = 0;
    let environmentContribution = 0;
    let crownJewelContribution = 0;
    if (input.cvss) {
        cvssContribution = input.cvss.baseScore * 10 * 0.25;
    }
    if (input.exploitabilityFlags) {
        const { hasExploit, hasPublicExploit, malwareAvailable } = input.exploitabilityFlags;
        if (hasPublicExploit)
            cvssContribution *= 1.5;
        else if (hasExploit)
            cvssContribution *= 1.25;
        if (malwareAvailable)
            cvssContribution *= 1.3;
    }
    exposureContribution = EXPOSURE_WEIGHTS[input.exposureLevel] * 100 * 0.2;
    if (input.identityBlastRadius) {
        const blastWeight = IDENTITY_BLAST_RADIUS_WEIGHTS[input.identityBlastRadius.type];
        identityContribution = blastWeight * input.identityBlastRadius.scope * 100 * 0.2;
    }
    dataClassificationContribution =
        DATA_CLASSIFICATION_WEIGHTS[input.dataClassification] * 100 * 0.2;
    environmentContribution =
        ENVIRONMENT_WEIGHTS[input.environment] * 100 * 0.15;
    if (input.isCrownJewel) {
        crownJewelContribution = 50;
    }
    if (input.attackPathLength !== undefined) {
        const pathPenalty = Math.max(0, (6 - input.attackPathLength) * 10);
        crownJewelContribution += pathPenalty;
    }
    const totalScore = Math.min(100, cvssContribution +
        exposureContribution +
        identityContribution +
        dataClassificationContribution +
        environmentContribution +
        crownJewelContribution);
    const severity = mapScoreToSeverity(totalScore);
    return {
        score: Math.round(totalScore * 10) / 10,
        severity,
        factors: {
            cvssContribution: Math.round(cvssContribution * 10) / 10,
            exposureContribution: Math.round(exposureContribution * 10) / 10,
            identityContribution: Math.round(identityContribution * 10) / 10,
            dataClassificationContribution: Math.round(dataClassificationContribution * 10) / 10,
            environmentContribution: Math.round(environmentContribution * 10) / 10,
            crownJewelContribution: Math.round(crownJewelContribution * 10) / 10,
        },
    };
}
function mapScoreToSeverity(score) {
    if (score >= SEVERITY_THRESHOLDS.critical)
        return 'critical';
    if (score >= SEVERITY_THRESHOLDS.high)
        return 'high';
    if (score >= SEVERITY_THRESHOLDS.medium)
        return 'medium';
    return 'low';
}
function extractResourcesFromPath(path) {
    const resourceIds = [];
    const resourceTypes = [];
    for (const item of path) {
        if (item && typeof item === 'object') {
            if (item.id)
                resourceIds.push(item.id);
            if (item.label)
                resourceTypes.push(item.label);
        }
    }
    return { resourceIds: [...new Set(resourceIds)], resourceTypes: [...new Set(resourceTypes)] };
}
function calculatePathSummary(path) {
    const segments = [];
    for (let i = 0; i < path.length - 1; i++) {
        const fromNode = path[i];
        const toNode = path[i + 1];
        if (fromNode && toNode && fromNode.id && toNode.id) {
            segments.push({
                from: fromNode.id,
                to: toNode.id,
                edgeType: toNode.label || 'unknown',
            });
        }
    }
    return { segments };
}
function getRemediationHint(ruleId, context) {
    const hints = {
        'RULE-001': 'Restrict IAM role permissions to specific S3 buckets, enable VPC endpoints for S3 access, or move sensitive data to private buckets.',
        'RULE-002': 'Restrict SSH/RDP access to specific IP ranges or VPN endpoints. Implement bastion hosts for administrative access.',
        'RULE-003': 'Update container images to latest patches, scan for CVEs in CI/CD pipeline, or remove internet exposure from workloads.',
        'RULE-004': 'Review IAM role permissions using AWS IAM Access Analyzer, implement least-privilege permissions, and remove unnecessary access.',
        'RULE-005': 'Implement additional network segmentation, add monitoring/alerts on crown jewel resources, and review trust relationships.',
        'RULE-006': 'Remove cross-account trust relationships unless strictly required, implement AWS Organizations service control policies.',
        'RULE-007': 'Enable S3 block public access, review bucket policies, and move sensitive data to restricted buckets.',
        'RULE-008': 'Disable public access on RDS instances, implement VPC endpoints, and review security group rules.',
        'RULE-009': 'Review Lambda execution role permissions, implement VPC endpoints without internet access, and use private subnets.',
        'RULE-010': 'Restrict IAM policy statements to specific secrets, implement resource-based policies, and enable secret rotation.',
    };
    return hints[ruleId] || 'Review and remediate the identified security issue according to best practices.';
}
//# sourceMappingURL=scoring.js.map