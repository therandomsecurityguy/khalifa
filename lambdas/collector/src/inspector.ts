import { Inspector2Client, ListFindingsCommand, type Finding } from '@aws-sdk/client-inspector2';
import type { GraphEdge, GraphNode } from '../../shared/types';
import { Logger } from '../../shared/types';

const logger = new Logger('inspector');

// Inspector findings can number in the thousands per account/region. CRITICAL
// and HIGH is what RULE-003 and the exploitability factor read; the cap bounds
// graph volume and a truncation is logged (the Security Hub cap works the same
// way at 500).
export const INSPECTOR_MAX_FINDINGS = 5000;

export interface InspectorCollection {
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: number;
  truncated: boolean;
  // Inspector is not enabled in this account/region: no CVE data exists, and
  // the stage records SKIPPED instead of an empty success.
  notEnabled: boolean;
}

// The Inspector resource for a finding is not the graph's vertex id: an EC2
// resource may carry only the instance id, and an ECR image carries
// registry/repository/digest. Reassemble the ids the other stages write.
export function findingResourceId(
  finding: Finding,
  accountId: string,
  region: string
): string | undefined {
  const resource = finding.resources?.[0];
  if (!resource) return undefined;
  switch (resource.type) {
    case 'AWS_EC2_INSTANCE': {
      // Inspector's EC2 resource id is the instance id (i-…); the details
      // object carries no id of its own.
      return resource.id ? `arn:aws:ec2:${region}:${accountId}:instance/${resource.id}` : undefined;
    }
    case 'AWS_ECR_CONTAINER_IMAGE': {
      const image = resource.details?.awsEcrContainerImage;
      const repository = image?.repositoryName;
      const digest = image?.imageHash;
      if (!repository || !digest) return undefined;
      // containers.ts writes `arn:…:repository/<name>@<digest>` for the same image.
      return `arn:aws:ecr:${region}:${accountId}:repository/${repository}@${digest}`;
    }
    case 'AWS_LAMBDA_FUNCTION': {
      const name = resource.details?.awsLambdaFunction?.functionName;
      return name ? `arn:aws:lambda:${region}:${accountId}:function:${name}` : undefined;
    }
    default:
      return undefined;
  }
}

// The highest CVSS base score Inspector reports for the finding, falling back
// to its own score when no CVSS vector is attached.
export function maxCvssBaseScore(finding: Finding): number | undefined {
  const scores = (finding.packageVulnerabilityDetails?.cvss ?? [])
    .map((cvss) => cvss.baseScore)
    .filter((score): score is number => typeof score === 'number' && Number.isFinite(score));
  if (scores.length > 0) return Math.max(...scores);
  const inspectorScore = finding.inspectorScore;
  return typeof inspectorScore === 'number' && Number.isFinite(inspectorScore)
    ? inspectorScore
    : undefined;
}

function fixedVersions(finding: Finding): string | undefined {
  const versions = [
    ...new Set(
      (finding.packageVulnerabilityDetails?.vulnerablePackages ?? [])
        .map((pkg) => pkg.fixedInVersion)
        .filter((version): version is string => !!version)
    ),
  ];
  return versions.length > 0 ? versions.join(', ') : undefined;
}

function isNotEnabled(error: unknown): boolean {
  return error instanceof Error && /^AccessDenied/.test(error.name);
}

// Amazon Inspector findings for the resources the graph already holds: one
// Vulnerability vertex per finding (id = finding ARN, so a finding that stops
// being ACTIVE leaves the next run and the reconcile removes it) and a HAS_CVE
// edge from the affected instance, image or function. Findings for resources
// not in the graph are skipped; the graph writer would drop the edge anyway.
export async function collectInspectorFindings(
  client: Inspector2Client,
  accountId: string,
  region: string,
  knownVertexIds: ReadonlySet<string>,
  limit: number = INSPECTOR_MAX_FINDINGS
): Promise<InspectorCollection> {
  const findings: Finding[] = [];
  let truncated = false;
  try {
    let nextToken: string | undefined;
    do {
      const page = await client.send(
        new ListFindingsCommand({
          nextToken,
          maxResults: 100,
          filterCriteria: {
            findingStatus: [{ comparison: 'EQUALS', value: 'ACTIVE' }],
            severity: [
              { comparison: 'EQUALS', value: 'CRITICAL' },
              { comparison: 'EQUALS', value: 'HIGH' },
            ],
            resourceType: [
              { comparison: 'EQUALS', value: 'AWS_EC2_INSTANCE' },
              { comparison: 'EQUALS', value: 'AWS_ECR_CONTAINER_IMAGE' },
              { comparison: 'EQUALS', value: 'AWS_LAMBDA_FUNCTION' },
            ],
          },
        })
      );
      for (const finding of page.findings ?? []) {
        if (findings.length >= limit) {
          truncated = true;
          break;
        }
        findings.push(finding);
      }
      nextToken = truncated ? undefined : page.nextToken;
    } while (nextToken);
    if (truncated) {
      logger.warn('Inspector findings truncated', { accountId, region, limit });
    }
  } catch (error) {
    if (isNotEnabled(error)) {
      return { nodes: [], edges: [], findings: 0, truncated: false, notEnabled: true };
    }
    throw error;
  }

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seen = new Set<string>();
  for (const finding of findings) {
    const findingArn = finding.findingArn;
    if (!findingArn || seen.has(findingArn)) continue;
    seen.add(findingArn);
    const target = findingResourceId(finding, accountId, region);
    if (!target || !knownVertexIds.has(target)) continue;
    nodes.push({
      id: findingArn,
      label: 'Vulnerability',
      properties: {
        id: findingArn,
        finding_arn: findingArn,
        cve_id: finding.packageVulnerabilityDetails?.vulnerabilityId,
        title: finding.title,
        severity: finding.severity,
        cvss_base_score: maxCvssBaseScore(finding),
        exploit_available: finding.exploitAvailable === 'YES',
        fixed_versions: fixedVersions(finding),
        inspector_score: finding.inspectorScore,
        first_observed_at: finding.firstObservedAt?.toISOString(),
        last_observed_at: finding.lastObservedAt?.toISOString(),
        source: 'inspector',
      },
    });
    edges.push({ from: target, to: findingArn, label: 'HAS_CVE' });
  }

  return { nodes, edges, findings: findings.length, truncated, notEnabled: false };
}
