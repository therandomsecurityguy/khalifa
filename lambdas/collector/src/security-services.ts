import {
  GuardDutyClient,
  ListDetectorsCommand,
  GetAdministratorAccountCommand,
  GetDetectorCommand,
} from '@aws-sdk/client-guardduty';
import {
  SecurityHubClient,
  DescribeHubCommand,
  GetEnabledStandardsCommand,
  GetFindingsCommand,
} from '@aws-sdk/client-securityhub';
import type { GraphNode, GraphEdge } from '../../shared/types';
import { collectPaginated, collectPaginatedBounded } from '../../shared/pagination';

export interface CollectResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const FEATURE_PROPS: Record<string, string> = {
  EKS_AUDIT_LOGS: 'eks_audit_logs',
  EKS_RUNTIME_MONITORING: 'eks_runtime_monitoring',
  RUNTIME_MONITORING: 'runtime_monitoring',
  S3_DATA_EVENTS: 's3_data_events',
  EBS_MALWARE_PROTECTION: 'ebs_malware_protection',
  RDS_LOGIN_EVENTS: 'rds_login_events',
  LAMBDA_NETWORK_LOGS: 'lambda_network_logs',
};

const SECURITY_HUB_MAX_FINDINGS = 500;

export async function collectGuardDuty(
  client: GuardDutyClient,
  accountId: string,
  region: string
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const detectors = await collectPaginated(
    (token) => client.send(new ListDetectorsCommand({ NextToken: token })),
    (page) => page.DetectorIds,
    (page) => page.NextToken
  );

  if (detectors.length === 0) {
    const missingArn = `arn:aws:guardduty:${region}:${accountId}:detector/missing`;
    nodes.push({
      id: missingArn,
      label: 'GuardDutyDetector',
      properties: {
        id: 'missing',
        arn: missingArn,
        account_id: accountId,
        region,
        status: 'MISSING',
      },
    });
    return { nodes, edges };
  }

  for (const detectorId of detectors) {
    const detector = await client.send(new GetDetectorCommand({ DetectorId: detectorId }));
    const detectorArn = `arn:aws:guardduty:${region}:${accountId}:detector/${detectorId}`;

    let administratorAccountId: string | undefined;
    try {
      const administrator = await client.send(
        new GetAdministratorAccountCommand({ DetectorId: detectorId })
      );
      administratorAccountId = administrator.Administrator?.AccountId;
    } catch (e) {
      if (
        !(e instanceof Error) ||
        (e.name !== 'BadRequestException' && e.name !== 'InvalidInputException')
      ) {
        throw e;
      }
    }

    const featureProps: Record<string, boolean> = {};
    for (const feature of detector.Features || []) {
      const propName = feature.Name ? FEATURE_PROPS[feature.Name] : undefined;
      if (propName) {
        featureProps[`${propName}_enabled`] = feature.Status === 'ENABLED';
      }
    }

    nodes.push({
      id: detectorArn,
      label: 'GuardDutyDetector',
      properties: {
        id: detectorId,
        arn: detectorArn,
        account_id: accountId,
        region,
        status: detector.Status,
        finding_publishing_frequency: detector.FindingPublishingFrequency,
        created_at: detector.CreatedAt,
        updated_at: detector.UpdatedAt,
        administrator_account_id: administratorAccountId,
        ...featureProps,
      },
    });
  }

  return { nodes, edges };
}

export async function collectSecurityHub(
  client: SecurityHubClient,
  accountId: string,
  region: string,
  knownResourceArns: ReadonlySet<string>,
  options: { excludeGuardDuty?: boolean } = {}
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  let hubArn: string;
  let hubNode: GraphNode;
  try {
    const hub = await client.send(new DescribeHubCommand({}));
    const standards = await collectPaginated(
      (token) => client.send(new GetEnabledStandardsCommand({ NextToken: token })),
      (page) => page.StandardsSubscriptions,
      (page) => page.NextToken
    );
    hubArn = `arn:aws:securityhub:${region}:${accountId}:hub/default`;
    hubNode = {
      id: hubArn,
      label: 'SecurityHub',
      properties: {
        id: 'default',
        arn: hubArn,
        account_id: accountId,
        region,
        enabled: true,
        subscribed_at: hub.SubscribedAt,
        enabled_standards: standards.map((standard) => standard.StandardsArn).filter(Boolean),
      },
    };
    nodes.push(hubNode);
  } catch (e) {
    if (
      e instanceof Error &&
      (e.name === 'ResourceNotFoundException' || e.name === 'InvalidInputException')
    ) {
      return { nodes, edges };
    }
    throw e;
  }

  // Two windows with separate caps. RULE-018 reads only critical and high, so
  // those get a window of their own: anything sharing it would push them out
  // on some runs, and the issues they raise would resolve and reopen. Medium
  // and low come in a second window for the resource explorer. Both take
  // active findings not already suppressed or resolved in Security Hub, worst
  // first; informational (mostly passed checks) is left out.
  const fetchFindings = (severities: string[]) =>
    collectPaginatedBounded(
      (token) =>
        client.send(
          new GetFindingsCommand({
            MaxResults: 100,
            NextToken: token,
            SortCriteria: [{ Field: 'SeverityNormalized', SortOrder: 'desc' }],
            Filters: {
              RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }],
              SeverityLabel: severities.map((Value) => ({ Value, Comparison: 'EQUALS' as const })),
              WorkflowStatus: [
                { Value: 'NEW', Comparison: 'EQUALS' },
                { Value: 'NOTIFIED', Comparison: 'EQUALS' },
              ],
              // Once GuardDuty findings come from the delegated administrator's
              // detectors (guardduty-findings.ts), taking them here as well would
              // write them twice and spend the caps Config and Inspector need.
              // Until then this is the only path they have.
              ...(options.excludeGuardDuty
                ? { ProductName: [{ Value: 'GuardDuty', Comparison: 'NOT_EQUALS' as const }] }
                : {}),
            },
          })
        ),
      (page) => page.Findings,
      (page) => page.NextToken,
      Math.ceil(SECURITY_HUB_MAX_FINDINGS / 100)
    );
  const severe = await fetchFindings(['CRITICAL', 'HIGH']);
  const other = await fetchFindings(['MEDIUM', 'LOW']);
  const findings = [...severe.items, ...other.items];
  hubNode.properties.findings_truncated = severe.truncated;
  hubNode.properties.other_findings_truncated = other.truncated;

  for (const finding of findings) {
    if (!finding.Id) continue;
    const findingArn = `arn:aws:securityhub:${region}:${accountId}:finding/${finding.Id}`;
    const primaryResource = finding.Resources?.[0];

    nodes.push({
      id: findingArn,
      label: 'SecurityHubFinding',
      properties: {
        id: finding.Id,
        arn: findingArn,
        account_id: accountId,
        region,
        title: finding.Title,
        severity: finding.Severity?.Label,
        record_state: finding.RecordState,
        workflow_state: finding.Workflow?.Status,
        product_arn: finding.ProductArn,
        generator_id: finding.GeneratorId,
        finding_types: finding.Types,
        resource_arn: primaryResource?.Id,
        resource_type: primaryResource?.Type,
        created_at: finding.CreatedAt,
        updated_at: finding.UpdatedAt,
      },
    });
    edges.push({ from: hubArn, to: findingArn, label: 'HAS_FINDING' });

    if (primaryResource?.Id && knownResourceArns.has(primaryResource.Id)) {
      edges.push({ from: findingArn, to: primaryResource.Id, label: 'DETECTS_ON' });
    }
  }

  return { nodes, edges };
}
