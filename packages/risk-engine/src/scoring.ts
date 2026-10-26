import type {
  DataClassification,
  Environment,
  ExposureLevel,
  GraphVertex,
  IdentityBlastRadius,
  RiskScoreInput,
  RiskScoreOutput,
  Severity,
} from './types';

const EXPOSURE_WEIGHTS: Record<ExposureLevel, number> = {
  internet: 1.0,
  'cross-account': 0.7,
  internal: 0.3,
};

const DATA_CLASSIFICATION_WEIGHTS: Record<DataClassification, number> = {
  secret: 1.0,
  restricted: 0.8,
  internal: 0.5,
  public: 0.1,
};

const ENVIRONMENT_WEIGHTS: Record<Environment, number> = {
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

// Factor weights sum to 1.0. CVSS was removed because nothing populated it (no
// vulnerability source existed), so it contributed zero to every score while
// still consuming a share of the range; its weight was redistributed across
// the factors that have real data.
const FACTOR_WEIGHTS = {
  exposure: 0.3,
  identity: 0.25,
  dataClassification: 0.25,
  environment: 0.2,
} as const;

// Exploitability (CVSS from Amazon Inspector findings on the path, up to the
// full range when an exploit is known) is deliberately additive rather than a
// reweighting: findings with no CVE data keep exactly the scores they had, and
// a known vulnerability raises the score by at most this share of the range —
// enough to order a vulnerable workload above an otherwise identical one.
const EXPLOITABILITY_WEIGHT = 0.15;

// A customer threat-intel match (an anomaly's source IP or a trusted external
// account on the customer's list) is additive too, and flat rather than
// proportional: the indicator is a fact about the path, not a strength. Ten
// points ranks a matched path above the same path without the match without
// crossing a severity threshold on its own; auto-ticketing still waits on
// measured precision (rule-quality.ts).
const THREAT_INTEL_BONUS = 10;

const SEVERITY_THRESHOLDS: Record<Severity, number> = {
  critical: 80,
  high: 60,
  medium: 40,
  low: 20,
};

export function computeRiskScore(input: RiskScoreInput): RiskScoreOutput {
  const exposureContribution =
    EXPOSURE_WEIGHTS[input.exposureLevel] * 100 * FACTOR_WEIGHTS.exposure;

  let identityContribution = 0;
  if (input.identityBlastRadius) {
    const blastWeight = IDENTITY_BLAST_RADIUS_WEIGHTS[input.identityBlastRadius.type];
    identityContribution =
      blastWeight * input.identityBlastRadius.scope * 100 * FACTOR_WEIGHTS.identity;
  }

  const dataClassificationContribution =
    DATA_CLASSIFICATION_WEIGHTS[input.dataClassification] * 100 * FACTOR_WEIGHTS.dataClassification;

  const environmentContribution =
    ENVIRONMENT_WEIGHTS[input.environment] * 100 * FACTOR_WEIGHTS.environment;

  let crownJewelContribution = 0;
  if (input.isCrownJewel) {
    crownJewelContribution = 50;
  }
  if (input.attackPathLength !== undefined) {
    const pathPenalty = Math.max(0, (6 - input.attackPathLength) * 10);
    crownJewelContribution += pathPenalty;
  }

  const threatIntelContribution = input.threatIntel?.indicators?.length ? THREAT_INTEL_BONUS : 0;

  let exploitabilityContribution = 0;
  if (input.exploitability) {
    const cvss = input.exploitability.cvssBaseScore;
    let value = typeof cvss === 'number' && Number.isFinite(cvss) ? cvss / 10 : 0.5;
    if (input.exploitability.exploitAvailable) value += 0.2;
    value = Math.min(1, Math.max(0, value));
    exploitabilityContribution = value * 100 * EXPLOITABILITY_WEIGHT;
  }

  const totalScore = Math.min(
    100,
    exposureContribution +
      identityContribution +
      dataClassificationContribution +
      environmentContribution +
      crownJewelContribution +
      exploitabilityContribution +
      threatIntelContribution
  );

  const severity = mapScoreToSeverity(totalScore);

  return {
    score: Math.round(totalScore * 10) / 10,
    severity,
    factors: {
      exposureContribution: Math.round(exposureContribution * 10) / 10,
      identityContribution: Math.round(identityContribution * 10) / 10,
      dataClassificationContribution: Math.round(dataClassificationContribution * 10) / 10,
      environmentContribution: Math.round(environmentContribution * 10) / 10,
      crownJewelContribution: Math.round(crownJewelContribution * 10) / 10,
      exploitabilityContribution: Math.round(exploitabilityContribution * 10) / 10,
      threatIntelContribution,
    },
  };
}

function mapScoreToSeverity(score: number): Severity {
  if (score >= SEVERITY_THRESHOLDS.critical) return 'critical';
  if (score >= SEVERITY_THRESHOLDS.high) return 'high';
  if (score >= SEVERITY_THRESHOLDS.medium) return 'medium';
  return 'low';
}

export function extractResourcesFromPath(path: any[]): {
  resourceIds: string[];
  resourceTypes: string[];
} {
  const resourceIds: string[] = [];
  const resourceTypes: string[] = [];

  for (const item of path) {
    if (item && typeof item === 'object') {
      if (item.id) resourceIds.push(item.id);
      if (item.label) resourceTypes.push(item.label);
    }
  }

  return { resourceIds: [...new Set(resourceIds)], resourceTypes: [...new Set(resourceTypes)] };
}

export function calculatePathSummary(path: any[]): {
  segments: { from: string; to: string; edgeType: string }[];
} {
  const segments: { from: string; to: string; edgeType: string }[] = [];

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

export function getRemediationHint(ruleId: string, _context: Record<string, any>): string {
  const hints: Record<string, string> = {
    'RULE-001':
      "Scope the instance role's S3 permissions to the buckets the workload needs, require IMDSv2, and remove the instance's public IP or open security group if it does not need internet access.",
    'RULE-002':
      'Remove the 0.0.0.0/0 or ::/0 ingress on port 22/3389 from the security group. Use SSM Session Manager, a VPN or a bastion for administration instead.',
    'RULE-003':
      "Rebuild the image on a patched base, redeploy, and add CVE scanning to CI. Until then, remove the workload's internet exposure.",
    'RULE-004':
      'Replace the admin policy on this role with one scoped to the actions and resources the workload uses (check IAM last-accessed data), or remove the internet exposure.',
    'RULE-005':
      "Break the path: remove the entry point's internet exposure, or the permission or trust hop that reaches the crown jewel. Alert on access to the crown-jewel resource.",
    'RULE-006':
      "Scope the role's wildcard-resource statements to specific ARNs, and require sts:ExternalId or aws:PrincipalOrgID in its trust policy.",
    'RULE-007':
      'Turn on S3 Block Public Access for the bucket and account, and remove public grants from its bucket policy and ACLs.',
    'RULE-008':
      'Make the instance private (aws rds modify-db-instance --no-publicly-accessible) and limit its security group to private sources.',
    'RULE-009':
      'Put authentication on the function URL or API in front of it (AWS_IAM, an authorizer), and scope the function role to the tables and buckets it uses.',
    'RULE-010':
      "Remove the outside account or '*' from the secret's resource policy, or limit '*' with aws:PrincipalOrgID. If the account is ours but not collected, add it to collection; if the share is intended, suppress with the reason.",
    'RULE-011':
      'Block public access on the bucket now, then review the objects DSPM classified as restricted or secret and move or delete them.',
    'RULE-012':
      'Rotate the exposed secret, remove it from the S3 object or Lambda environment (use Secrets Manager or SSM instead), and scan for other copies.',
    'RULE-013':
      'Replace the user with an IAM role (IRSA, an instance role or GitHub OIDC) so no static key is needed. Otherwise rotate: create a new key, switch the workload, then deactivate and delete the old one (aws iam update-access-key --status Inactive).',
    'RULE-014':
      'Deactivate the unused key (aws iam update-access-key --status Inactive), confirm nothing breaks, then delete it.',
    'RULE-015':
      'Assign an MFA device to the user, or remove its console password (aws iam delete-login-profile). Prefer SSO for human access.',
    'RULE-016':
      'Scope GetSecretValue to the specific secret ARNs the principal needs (for example secret:app-name-*). For read-only SSO permission sets, add an explicit Deny on secretsmanager:GetSecretValue.',
    'RULE-017':
      'Enable GuardDuty in this region, or have the GuardDuty delegated administrator auto-enable it for the account.',
    'RULE-018':
      "Remediate the Security Hub finding using its linked guidance, or remove the resource's internet exposure until it is fixed.",
    'RULE-019':
      'Make the EKS endpoint private, or limit public access to known CIDRs (aws eks update-cluster-config --resources-vpc-config publicAccessCidrs=...).',
    'RULE-020':
      'Confirm who used root and why. If it was not approved break-glass use, rotate the root password, check root MFA, delete any root access keys and review the session in CloudTrail.',
    'RULE-021':
      "Confirm the new source IP belongs to the principal's expected infrastructure. If not, rotate the secrets it read and the principal's credentials, and review its CloudTrail activity.",
    'RULE-022':
      "Review the principal's denied calls: a broken deployment or probing with stolen credentials. Disable the credentials if the activity is not expected.",
    'RULE-023':
      'Treat as a compromise: the decoy key was used. Find where it was exposed, block the source, and rotate any real credentials stored alongside it.',
    'RULE-024':
      'Require IMDSv2 on the instance (aws ec2 modify-instance-metadata-options --http-tokens required) so SSRF cannot steal its role credentials.',
    'RULE-025':
      'Re-enable or recreate IAM Access Analyzer in this account and region so external-access findings keep reporting.',
    'RULE-026':
      'Enable automatic rotation on the customer-managed key (aws kms enable-key-rotation --key-id ...).',
    'RULE-027': 'Enable VPC flow logs to the central logging bucket (aws ec2 create-flow-logs).',
    'RULE-028':
      'Start the Config recorder (aws configservice start-configuration-recorder) and confirm its delivery channel delivers.',
    'RULE-029':
      'Treat as an active intrusion on an internet-facing resource: isolate or restrict its exposure, rotate credentials it holds, and investigate the GuardDuty finding.',
    'RULE-031':
      "Replace the user's access key with a role (SSO, IRSA, an instance role or GitHub OIDC), or move the user off admin. Deactivate the key once nothing uses it (check its last use).",
    'RULE-032':
      'Narrow the resource policy to the prod accounts that use the secret, or give the non-prod account its own secret. If the share is intended, suppress with the reason.',
    'RULE-033':
      'Confirm each account in the resource policy still needs the secret, and narrow it to the specific role ARNs that read it.',
    'RULE-034':
      "Scope the principal's iam:PassRole to the specific non-admin roles its workloads use, and add an iam:PassedToService condition. If it must pass this role, narrow the role instead.",
    'RULE-030':
      "Narrow the target role's trust policy to the specific roles that need it, not the account root, and add conditions (sts:ExternalId, aws:PrincipalArn). If the access is intended, suppress with the reason.",
  };

  return (
    hints[ruleId] ||
    'Review and remediate the identified security issue according to best practices.'
  );
}

// Scoring inputs read off a path's vertices; shared by the rule runner and the
// attack-path explorer so both rank the same path the same way.
export function riskInputFromPath(path: GraphVertex[]): RiskScoreInput {
  let exposureLevel: 'internet' | 'cross-account' | 'internal' = 'internal';
  let dataClassification: 'public' | 'internal' | 'restricted' | 'secret' = 'public';
  let environment: 'prod' | 'staging' | 'dev' = 'dev';
  let isCrownJewel = false;
  let identityBlastRadius: IdentityBlastRadius | undefined;
  let cvssBaseScore: number | undefined;
  let exploitAvailable = false;
  let reachabilityRestricted = false;
  let reachabilityObserved = false;
  const attackPathLength = path.length;

  for (const v of path) {
    // A restricted read means this vertex's exposure or state is unknown, so
    // the path's reachability is a guess rather than a derivation; observed
    // traffic (flow logs) proves it despite that.
    if (
      v.properties?.lambda_exposure_restricted === true ||
      v.properties?.collection_restricted === true
    ) {
      reachabilityRestricted = true;
    }
    if (v.properties?.traffic_observed === true) {
      reachabilityObserved = true;
    }
    // Amazon Inspector findings on the path (collector writes them as
    // Vulnerability vertices): the highest CVSS and whether an exploit is known.
    if (v.label === 'Vulnerability') {
      const cvss = v.properties?.cvss_base_score;
      if (typeof cvss === 'number' && Number.isFinite(cvss)) {
        cvssBaseScore = cvssBaseScore === undefined ? cvss : Math.max(cvssBaseScore, cvss);
      }
      if (v.properties?.exploit_available === true) exploitAvailable = true;
    }
    if (v.properties?.is_internet_exposed === true) {
      exposureLevel = 'internet';
    }
    if (
      v.properties?.data_classification === 'restricted' ||
      v.properties?.data_classification === 'secret'
    ) {
      dataClassification = v.properties.data_classification;
    }
    if (v.properties?.crown_jewel === true) {
      isCrownJewel = true;
    }
    if (v.properties?.env === 'prod') {
      environment = 'prod';
    } else if (v.properties?.env === 'staging' && environment !== 'prod') {
      environment = 'staging';
    }
    // Identity blast radius from the CIEM properties the collector writes on
    // IamRole vertices. Admin dominates and cannot be downgraded by a later
    // cross-account vertex.
    if (v.properties?.is_admin === true || v.properties?.is_admin_role === true) {
      identityBlastRadius = { type: 'admin', scope: 1 };
    } else if (
      identityBlastRadius?.type !== 'admin' &&
      (v.properties?.has_cross_account_trust === true || v.properties?.is_cross_account === true)
    ) {
      identityBlastRadius = { type: 'cross-account', scope: 1 };
    }
  }

  return {
    exposureLevel,
    dataClassification,
    environment,
    isCrownJewel,
    attackPathLength,
    identityBlastRadius,
    ...(cvssBaseScore !== undefined || exploitAvailable
      ? { exploitability: { cvssBaseScore, exploitAvailable } }
      : {}),
    ...(reachabilityRestricted ? { reachabilityRestricted: true } : {}),
    ...(reachabilityObserved ? { reachabilityObserved: true } : {}),
  };
}
