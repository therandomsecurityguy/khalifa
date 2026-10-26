import { RULE_CATALOGUE, SEVERITY_RANK, type PlanSeverity } from './catalogue';
import type { PlannedResource } from './plan';

export interface PlanFinding {
  /** The catalogue rule a live engine would fire, when one covers this change. */
  ruleId: string | null;
  ruleName: string;
  severity: PlanSeverity;
  address: string;
  detail: string;
  /** Where the change leads: the shape of the path the live graph would draw. */
  predictedPath: string;
}

const WORLD_CIDRS = new Set(['0.0.0.0/0', '::/0']);

interface RawFinding {
  ruleId: string | null;
  address: string;
  detail: string;
  predictedPath: string;
  fallbackName?: string;
  fallbackSeverity?: PlanSeverity;
}

// One finding per resource and rule, with the details joined: a security group
// with three world-open rules is one thing to fix, not three.
export function analyzePlan(resources: PlannedResource[]): PlanFinding[] {
  const raw: RawFinding[] = [];
  for (const resource of resources) {
    // Defensive: only creations and updates can introduce risk.
    if (!resource.actions.includes('create') && !resource.actions.includes('update')) continue;
    switch (resource.type) {
      case 'aws_security_group':
      case 'aws_security_group_rule':
      case 'aws_vpc_security_group_ingress_rule':
        raw.push(...securityGroupFindings(resource));
        break;
      case 'aws_s3_bucket_acl':
      case 'aws_s3_bucket_public_access_block':
      case 'aws_s3_bucket_policy':
        raw.push(...bucketFindings(resource));
        break;
      case 'aws_db_instance':
        if (resource.after.publicly_accessible === true) {
          raw.push({
            ruleId: 'RULE-008',
            address: resource.address,
            detail:
              'publicly_accessible = true (data classification is known only after collection)',
            predictedPath: `Internet → ${resource.address}`,
          });
        }
        break;
      case 'aws_eks_cluster':
        raw.push(...eksFindings(resource));
        break;
      case 'aws_iam_role':
        raw.push(...roleTrustFindings(resource));
        break;
      case 'aws_secretsmanager_secret_policy':
        raw.push(...secretPolicyFindings(resource));
        break;
      case 'aws_lambda_function_url':
        if (resource.after.authorization_type === 'NONE') {
          raw.push({
            ruleId: 'RULE-009',
            address: resource.address,
            detail:
              'function URL needs no authentication (the role-reaches-sensitive-data check runs at collection time)',
            predictedPath: `Internet → ${resource.address} → function`,
          });
        }
        break;
      case 'aws_instance':
        raw.push(...imdsFindings(resource));
        break;
      default:
        break;
    }
  }

  const merged = new Map<string, PlanFinding>();
  for (const finding of raw) {
    const key = `${finding.address}\0${finding.ruleId ?? finding.fallbackName}`;
    const existing = merged.get(key);
    if (existing) {
      existing.detail = `${existing.detail}; ${finding.detail}`;
      continue;
    }
    const catalogue = finding.ruleId ? RULE_CATALOGUE[finding.ruleId] : undefined;
    merged.set(key, {
      ruleId: finding.ruleId,
      ruleName: catalogue?.name ?? finding.fallbackName ?? 'Exposure',
      severity: catalogue?.severity ?? finding.fallbackSeverity ?? 'high',
      address: finding.address,
      detail: finding.detail,
      predictedPath: finding.predictedPath,
    });
  }

  return [...merged.values()].sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.address.localeCompare(b.address)
  );
}

interface IngressRule {
  cidrs: string[];
  fromPort?: number;
  toPort?: number;
  protocol?: string;
}

function securityGroupFindings(resource: PlannedResource): RawFinding[] {
  const findings: RawFinding[] = [];
  const rules: IngressRule[] = [];

  if (resource.type === 'aws_security_group') {
    const ingress = resource.after.ingress;
    if (Array.isArray(ingress)) {
      for (const entry of ingress) {
        if (!entry || typeof entry !== 'object') continue;
        const block = entry as Record<string, unknown>;
        rules.push({
          cidrs: cidrList(block.cidr_blocks, block.ipv6_cidr_blocks),
          fromPort: numberOrUndefined(block.from_port),
          toPort: numberOrUndefined(block.to_port),
          protocol: stringOrUndefined(block.protocol),
        });
      }
    }
  } else if (resource.type === 'aws_security_group_rule') {
    if (resource.after.type === 'ingress') {
      rules.push({
        cidrs: cidrList(resource.after.cidr_blocks, resource.after.ipv6_cidr_blocks),
        fromPort: numberOrUndefined(resource.after.from_port),
        toPort: numberOrUndefined(resource.after.to_port),
        protocol: stringOrUndefined(resource.after.protocol),
      });
    }
  } else {
    rules.push({
      cidrs: cidrList(resource.after.cidr_ipv4, resource.after.cidr_ipv6),
      fromPort: numberOrUndefined(resource.after.from_port),
      toPort: numberOrUndefined(resource.after.to_port),
      protocol: stringOrUndefined(resource.after.ip_protocol),
    });
  }

  for (const rule of rules) {
    const open = rule.cidrs.filter((cidr) => WORLD_CIDRS.has(cidr));
    if (open.length === 0) continue;
    const coversAdminPorts = coversPort(rule, 22) || coversPort(rule, 3389);
    findings.push({
      ruleId: coversAdminPorts ? 'RULE-002' : null,
      address: resource.address,
      detail: `world-open ingress from ${open.join(', ')} on ${describePorts(rule)}`,
      predictedPath: `Internet → ${resource.address} → attached resources`,
      ...(coversAdminPorts
        ? {}
        : {
            fallbackName: 'World-open ingress (no catalogue rule fires for these ports yet)',
            fallbackSeverity: 'high',
          }),
    });
  }
  return findings;
}

function coversPort(rule: IngressRule, port: number): boolean {
  if (rule.protocol === '-1' || rule.fromPort === -1) return true;
  if (rule.protocol !== undefined && rule.protocol !== 'tcp') return false;
  if (rule.fromPort === undefined || rule.toPort === undefined) {
    // Ports unknown: treat as potentially covering the port rather than miss it.
    return true;
  }
  return rule.fromPort <= port && rule.toPort >= port;
}

function describePorts(rule: IngressRule): string {
  if (rule.protocol === '-1' || rule.fromPort === -1) return 'all protocols';
  if (rule.fromPort === undefined || rule.toPort === undefined) return 'unknown ports';
  return rule.fromPort === rule.toPort
    ? `port ${rule.fromPort}`
    : `ports ${rule.fromPort}-${rule.toPort}`;
}

function bucketFindings(resource: PlannedResource): RawFinding[] {
  const path = `Internet → ${resource.address} → objects in the bucket`;
  if (resource.type === 'aws_s3_bucket_acl') {
    if (resource.after.acl === 'public-read' || resource.after.acl === 'public-read-write') {
      return [
        {
          ruleId: 'RULE-007',
          address: resource.address,
          detail: `bucket ACL is ${resource.after.acl}`,
          predictedPath: path,
        },
      ];
    }
    return [];
  }
  if (resource.type === 'aws_s3_bucket_public_access_block') {
    const disabled = [
      'block_public_acls',
      'block_public_policy',
      'ignore_public_acls',
      'restrict_public_buckets',
    ].filter((key) => resource.after[key] === false);
    return disabled.length > 0
      ? [
          {
            ruleId: 'RULE-007',
            address: resource.address,
            detail: `public access block disabled for ${disabled.join(', ')}`,
            predictedPath: path,
          },
        ]
      : [];
  }
  const statements = allowStatements(resource.after.policy);
  const anyone = statements.some(
    (statement) => principalIsAnyone(statement) && !orgRestricted(statement)
  );
  return anyone
    ? [
        {
          ruleId: 'RULE-007',
          address: resource.address,
          detail: 'bucket policy allows anyone (no aws:PrincipalOrgID condition)',
          predictedPath: path,
        },
      ]
    : [];
}

function eksFindings(resource: PlannedResource): RawFinding[] {
  const vpc = resource.after.vpc_config;
  if (!vpc || typeof vpc !== 'object') return [];
  const config = vpc as Record<string, unknown>;
  if (config.endpoint_public_access === false) return [];
  const cidrs = Array.isArray(config.public_access_cidrs) ? config.public_access_cidrs : [];
  if (!cidrs.includes('0.0.0.0/0')) return [];
  return [
    {
      ruleId: 'RULE-019',
      address: resource.address,
      detail: 'public API endpoint open to 0.0.0.0/0',
      predictedPath: `Internet → ${resource.address} → cluster API`,
    },
  ];
}

function roleTrustFindings(resource: PlannedResource): RawFinding[] {
  const statements = allowStatements(resource.after.assume_role_policy);
  const findings: RawFinding[] = [];
  for (const statement of statements) {
    if (principalIsAnyone(statement)) {
      findings.push({
        ruleId: 'RULE-006',
        address: resource.address,
        detail: 'trust policy allows any AWS principal (Principal *)',
        predictedPath: `Anyone → TRUSTS → ${resource.address}`,
      });
      continue;
    }
    const accounts = rootAccountIds(statement);
    if (accounts.length > 0) {
      findings.push({
        ruleId: 'RULE-006',
        address: resource.address,
        detail: `trust policy allows account root ${accounts.join(', ')} (the wildcard-resource and collection checks run at collection time)`,
        predictedPath: `ExternalAccount → TRUSTS → ${resource.address}`,
      });
    }
  }
  return findings;
}

function secretPolicyFindings(resource: PlannedResource): RawFinding[] {
  const statements = allowStatements(resource.after.policy);
  const findings: RawFinding[] = [];
  for (const statement of statements) {
    if (principalIsAnyone(statement) && !orgRestricted(statement)) {
      findings.push({
        ruleId: 'RULE-010',
        address: resource.address,
        detail: 'resource policy allows anyone (no aws:PrincipalOrgID condition)',
        predictedPath: `${resource.address} → any AWS principal`,
      });
      continue;
    }
    const accounts = rootAccountIds(statement);
    if (accounts.length > 0) {
      findings.push({
        ruleId: 'RULE-010',
        address: resource.address,
        detail: `resource policy allows account root ${accounts.join(', ')} (the collected-account check runs at collection time)`,
        predictedPath: `${resource.address} → readers outside the organization`,
      });
    }
  }
  return findings;
}

function imdsFindings(resource: PlannedResource): RawFinding[] {
  const options = Array.isArray(resource.after.metadata_options)
    ? resource.after.metadata_options[0]
    : resource.after.metadata_options;
  const tokens =
    options && typeof options === 'object'
      ? (options as Record<string, unknown>).http_tokens
      : undefined;
  if (tokens === 'required') return [];
  return [
    {
      ruleId: 'RULE-024',
      address: resource.address,
      detail:
        tokens === undefined
          ? 'no metadata_options block, so IMDSv1 remains allowed'
          : `metadata_options.http_tokens = ${tokens}`,
      predictedPath: `SSRF on ${resource.address} → instance role credentials`,
    },
  ];
}

function allowStatements(policy: unknown): Record<string, unknown>[] {
  if (typeof policy !== 'string' || !policy.trim()) return [];
  let document: unknown;
  try {
    document = JSON.parse(policy);
  } catch {
    return [];
  }
  const statements = (document as { Statement?: unknown })?.Statement;
  const list = Array.isArray(statements) ? statements : statements ? [statements] : [];
  return list.filter(
    (statement): statement is Record<string, unknown> =>
      !!statement &&
      typeof statement === 'object' &&
      (statement as Record<string, unknown>).Effect === 'Allow'
  );
}

function principalIsAnyone(statement: Record<string, unknown>): boolean {
  const principal = statement.Principal;
  if (principal === '*') return true;
  if (!principal || typeof principal !== 'object') return false;
  const aws = (principal as Record<string, unknown>).AWS;
  return asList(aws).includes('*');
}

function rootAccountIds(statement: Record<string, unknown>): string[] {
  const principal = statement.Principal;
  const aws =
    principal && typeof principal === 'object'
      ? (principal as Record<string, unknown>).AWS
      : undefined;
  const ids: string[] = [];
  for (const value of asList(aws)) {
    if (typeof value !== 'string') continue;
    const match = value.match(/^arn:aws(?:-us-gov|-cn)?:iam::(\d{12}):root$/);
    if (match) ids.push(match[1]);
    else if (/^\d{12}$/.test(value)) ids.push(value);
  }
  return ids;
}

function orgRestricted(statement: Record<string, unknown>): boolean {
  const condition = statement.Condition;
  if (!condition || typeof condition !== 'object') return false;
  return Object.values(condition as Record<string, unknown>).some(
    (keys) =>
      !!keys &&
      typeof keys === 'object' &&
      Object.keys(keys as Record<string, unknown>).some(
        (key) => key.toLowerCase() === 'aws:principalorgid'
      )
  );
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function cidrList(...values: unknown[]): string[] {
  return values.flatMap((value) =>
    asList(value).filter((item): item is string => typeof item === 'string')
  );
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}
