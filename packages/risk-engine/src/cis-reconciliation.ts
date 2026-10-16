import { GetFindingsCommand, SecurityHubClient } from '@aws-sdk/client-securityhub';
import { AssumeRoleCommand, STSClient } from '@aws-sdk/client-sts';
import { DynamoDBClient, PutItemCommand, QueryCommand } from '@aws-sdk/client-dynamodb';
import { marshall, unmarshall } from '@aws-sdk/util-dynamodb';
import type { ComplianceControlResult, ComplianceReport } from './compliance-types';
import {
  CIS_V3_STANDARDS_ID,
  SECURITY_HUB_CIS_V3_REQUIREMENT,
  controlsByRequirement,
} from './securityhub-cis-v3';

/**
 * Khalifa vs Security Hub CIS v3.0.0 reconciliation.
 *
 * Security Hub runs CIS v3.0.0 in the accounts Khalifa collects, independently of
 * Khalifa's graph, so the two should agree wherever both have a result. Each
 * compliance run compares them per requirement x account (x region), records the
 * disagreements, and tracks how long each requirement has agreed. A requirement
 * is publishable (e.g. to a trust page) only after minAgreementDays of unbroken
 * agreement and only if it is allowlisted. Anything unreadable fails closed.
 */

export const RECONCILIATION_FRAMEWORK = 'CIS_RECONCILIATION';

export type Outcome =
  | 'AGREE_PASS'
  | 'AGREE_FAIL'
  | 'DISAGREE'
  // Khalifa reports only an org-wide count for this requirement, so a single
  // account's Security Hub result cannot be checked against it.
  | 'KHALIFA_AGGREGATE_ONLY'
  | 'KHALIFA_NO_RESULT'
  // Security Hub has no usable result: no finding, or NOT_AVAILABLE / WARNING
  // (typically AWS Config not recording).
  | 'SH_NO_RESULT';

const OUTCOMES: Outcome[] = [
  'AGREE_PASS',
  'AGREE_FAIL',
  'DISAGREE',
  'KHALIFA_AGGREGATE_ONLY',
  'KHALIFA_NO_RESULT',
  'SH_NO_RESULT',
];

type ShStatus = 'PASSED' | 'FAILED' | 'NO_DATA';

export interface ShControlFinding {
  controlId: string;
  accountId: string;
  region: string;
  /** Compliance.Status: PASSED, FAILED, WARNING or NOT_AVAILABLE. */
  status: string;
}

export interface Disagreement {
  accountId: string;
  region?: string;
  khalifa: 'PASS' | 'FAIL';
  securityHub: 'PASSED' | 'FAILED';
}

export interface RequirementReconciliation {
  requirement: string;
  securityHubControls: string[];
  khalifaStatus: string | null;
  /** How Khalifa reports this requirement, which decides what can be compared. */
  khalifaScope: 'account' | 'account-region' | 'aggregate' | 'none';
  counts: Record<Outcome, number>;
  disagreements: Disagreement[];
  /** Start of the current unbroken agreement, or null. */
  agreeingSince: string | null;
  agreementDays: number;
  allowlisted: boolean;
  publishable: boolean;
}

export interface ReconciliationRecord {
  framework: typeof RECONCILIATION_FRAMEWORK;
  generatedAt: string;
  status: 'OK' | 'STALE';
  error?: string;
  khalifaReportGeneratedAt: string | null;
  minAgreementDays: number;
  securityHubFindingsRead: number;
  requirements: RequirementReconciliation[];
}

export interface ReconciliationConfig {
  minAgreementDays: number;
  allowlist: ReadonlySet<string>;
}

// FAILED wins over everything; any non-PASSED result without a failure is no data.
function combine(a: ShStatus | undefined, b: ShStatus): ShStatus {
  if (a === 'FAILED' || b === 'FAILED') return 'FAILED';
  if (a === 'NO_DATA' || b === 'NO_DATA') return 'NO_DATA';
  return 'PASSED';
}

function shStatus(raw: string): ShStatus {
  if (raw === 'FAILED') return 'FAILED';
  if (raw === 'PASSED') return 'PASSED';
  return 'NO_DATA';
}

/** Security Hub results per requirement, keyed by account and by "account region". */
export function aggregateSecurityHub(findings: ShControlFinding[]): {
  byAccount: Map<string, Map<string, ShStatus>>;
  byAccountRegion: Map<string, Map<string, ShStatus>>;
} {
  const byAccount = new Map<string, Map<string, ShStatus>>();
  const byAccountRegion = new Map<string, Map<string, ShStatus>>();
  for (const f of findings) {
    const requirement = SECURITY_HUB_CIS_V3_REQUIREMENT[f.controlId];
    if (!requirement) continue;
    const status = shStatus(f.status);
    const account = byAccount.get(requirement) ?? new Map<string, ShStatus>();
    account.set(f.accountId, combine(account.get(f.accountId), status));
    byAccount.set(requirement, account);
    const regional = byAccountRegion.get(requirement) ?? new Map<string, ShStatus>();
    const key = `${f.accountId} ${f.region}`;
    regional.set(key, combine(regional.get(key), status));
    byAccountRegion.set(requirement, regional);
  }
  return { byAccount, byAccountRegion };
}

interface KhalifaView {
  scope: RequirementReconciliation['khalifaScope'];
  status: string | null;
  /** Per-key result for account / account-region scopes. */
  results: Map<string, 'PASS' | 'FAIL'>;
}

function khalifaView(result: ComplianceControlResult | undefined): KhalifaView {
  if (!result) return { scope: 'none', status: null, results: new Map() };
  const status = result.status;
  if (status !== 'PASS' && status !== 'FAIL') return { scope: 'none', status, results: new Map() };
  const details = result.evidence[0]?.details ?? {};
  if (Array.isArray(details.assessedAccounts) && Array.isArray(details.failingAccounts)) {
    const failing = new Set<string>(details.failingAccounts);
    return {
      scope: 'account',
      status,
      results: new Map(
        (details.assessedAccounts as string[]).map((a) => [a, failing.has(a) ? 'FAIL' : 'PASS'])
      ),
    };
  }
  if (
    Array.isArray(details.assessedAccountRegions) &&
    Array.isArray(details.failingAccountRegions)
  ) {
    const failing = new Set<string>(details.failingAccountRegions);
    return {
      scope: 'account-region',
      status,
      results: new Map(
        (details.assessedAccountRegions as string[]).map((k) => [
          k,
          failing.has(k) ? 'FAIL' : 'PASS',
        ])
      ),
    };
  }
  return { scope: 'aggregate', status, results: new Map() };
}

function emptyCounts(): Record<Outcome, number> {
  return Object.fromEntries(OUTCOMES.map((o) => [o, 0])) as Record<Outcome, number>;
}

function compareOne(
  khalifa: KhalifaView,
  sh: { byAccount: Map<string, ShStatus>; byAccountRegion: Map<string, ShStatus> }
): { counts: Record<Outcome, number>; disagreements: Disagreement[] } {
  const counts = emptyCounts();
  const disagreements: Disagreement[] = [];

  if (khalifa.scope === 'none') {
    counts.KHALIFA_NO_RESULT = sh.byAccount.size;
    return { counts, disagreements };
  }

  if (khalifa.scope === 'aggregate') {
    // An org-wide PASS says no account fails, so any Security Hub failure
    // contradicts it. An org-wide FAIL can't be checked per account.
    for (const [accountId, status] of sh.byAccount) {
      if (khalifa.status === 'PASS' && status === 'FAILED') {
        counts.DISAGREE++;
        disagreements.push({ accountId, khalifa: 'PASS', securityHub: 'FAILED' });
      } else {
        counts.KHALIFA_AGGREGATE_ONLY++;
      }
    }
    return { counts, disagreements };
  }

  const shByKey = khalifa.scope === 'account' ? sh.byAccount : sh.byAccountRegion;
  const keys = new Set([...khalifa.results.keys(), ...shByKey.keys()]);
  for (const key of [...keys].sort()) {
    const k = khalifa.results.get(key);
    const s = shByKey.get(key);
    if (!k) {
      counts.KHALIFA_NO_RESULT++;
    } else if (!s || s === 'NO_DATA') {
      counts.SH_NO_RESULT++;
    } else if ((k === 'PASS') === (s === 'PASSED')) {
      counts[k === 'PASS' ? 'AGREE_PASS' : 'AGREE_FAIL']++;
    } else {
      counts.DISAGREE++;
      const [accountId, region] = key.split(' ');
      disagreements.push({
        accountId,
        ...(khalifa.scope === 'account-region' ? { region } : {}),
        khalifa: k,
        securityHub: s,
      });
    }
  }
  return { counts, disagreements };
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Pure reconciliation. `previous` carries each requirement's agreement start
 * forward; a disagreement, or no comparable pair at all, resets it.
 */
export function reconcile(
  report: ComplianceReport,
  findings: ShControlFinding[],
  previous: ReconciliationRecord | null,
  config: ReconciliationConfig,
  now: Date
): ReconciliationRecord {
  const sh = aggregateSecurityHub(findings);
  const byId = new Map(report.controls.map((c) => [c.control.id, c]));
  const previousSince = new Map(
    (previous?.status === 'OK' ? previous.requirements : []).map((r) => [
      r.requirement,
      r.agreeingSince,
    ])
  );
  const requirements: RequirementReconciliation[] = [];
  for (const [requirement, controls] of [...controlsByRequirement()].sort(([a], [b]) =>
    a.localeCompare(b, undefined, { numeric: true })
  )) {
    const khalifa = khalifaView(byId.get(requirement));
    const { counts, disagreements } = compareOne(khalifa, {
      byAccount: sh.byAccount.get(requirement) ?? new Map(),
      byAccountRegion: sh.byAccountRegion.get(requirement) ?? new Map(),
    });
    const compared = counts.AGREE_PASS + counts.AGREE_FAIL + counts.DISAGREE;
    const agrees = compared > 0 && counts.DISAGREE === 0;
    const agreeingSince = agrees ? (previousSince.get(requirement) ?? now.toISOString()) : null;
    const agreementDays = agreeingSince
      ? Math.floor((now.getTime() - Date.parse(agreeingSince)) / DAY_MS)
      : 0;
    const allowlisted = config.allowlist.has(requirement);
    requirements.push({
      requirement,
      securityHubControls: controls.sort(),
      khalifaStatus: khalifa.status,
      khalifaScope: khalifa.scope,
      counts,
      disagreements,
      agreeingSince,
      agreementDays,
      allowlisted,
      publishable: allowlisted && agreementDays >= config.minAgreementDays,
    });
  }
  return {
    framework: RECONCILIATION_FRAMEWORK,
    generatedAt: now.toISOString(),
    status: 'OK',
    khalifaReportGeneratedAt: report.generatedAt,
    minAgreementDays: config.minAgreementDays,
    securityHubFindingsRead: findings.length,
    requirements,
  };
}

/** A record that publishes nothing and resets every agreement. */
export function staleRecord(
  error: string,
  report: ComplianceReport | null,
  config: ReconciliationConfig,
  now: Date
): ReconciliationRecord {
  return {
    framework: RECONCILIATION_FRAMEWORK,
    generatedAt: now.toISOString(),
    status: 'STALE',
    error,
    khalifaReportGeneratedAt: report?.generatedAt ?? null,
    minAgreementDays: config.minAgreementDays,
    securityHubFindingsRead: 0,
    requirements: [],
  };
}

// Pages of 100. Far above the org's CIS finding count; reaching it means
// something is wrong, and truncating silently would bias the comparison.
const MAX_PAGES = 2000;

export async function readSecurityHubCisFindings(
  client: Pick<SecurityHubClient, 'send'>
): Promise<ShControlFinding[]> {
  const findings: ShControlFinding[] = [];
  let nextToken: string | undefined;
  for (let page = 0; page < MAX_PAGES; page++) {
    const response = await client.send(
      new GetFindingsCommand({
        MaxResults: 100,
        NextToken: nextToken,
        Filters: {
          ComplianceAssociatedStandardsId: [{ Value: CIS_V3_STANDARDS_ID, Comparison: 'EQUALS' }],
          RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }],
        },
      })
    );
    for (const f of response.Findings ?? []) {
      const controlId = f.Compliance?.SecurityControlId;
      if (!controlId || !f.AwsAccountId || !f.Region || !f.Compliance?.Status) continue;
      findings.push({
        controlId,
        accountId: f.AwsAccountId,
        region: f.Region,
        status: f.Compliance.Status,
      });
    }
    nextToken = response.NextToken;
    if (!nextToken) return findings;
  }
  throw new Error(`Security Hub returned more than ${MAX_PAGES} pages of CIS findings`);
}

export interface ReconciliationStore {
  getLatest(): Promise<ReconciliationRecord | null>;
  save(record: ReconciliationRecord): Promise<void>;
}

/** Stored in the compliance reports table under its own partition key. */
export class DynamoDBReconciliationStore implements ReconciliationStore {
  constructor(
    private readonly tableName: string,
    private readonly client: Pick<DynamoDBClient, 'send'> = new DynamoDBClient({
      region: process.env.AWS_REGION || 'us-east-1',
    })
  ) {}

  async getLatest(): Promise<ReconciliationRecord | null> {
    const result = await this.client.send(
      new QueryCommand({
        TableName: this.tableName,
        KeyConditionExpression: 'framework = :framework',
        ExpressionAttributeValues: { ':framework': { S: RECONCILIATION_FRAMEWORK } },
        ScanIndexForward: false,
        Limit: 1,
      })
    );
    const item = result.Items?.[0];
    return item ? (unmarshall(item).report as ReconciliationRecord) : null;
  }

  async save(record: ReconciliationRecord): Promise<void> {
    await this.client.send(
      new PutItemCommand({
        TableName: this.tableName,
        Item: marshall(
          { framework: record.framework, generatedAt: record.generatedAt, report: record },
          { removeUndefinedValues: true }
        ),
      })
    );
  }
}

export interface ReconciliationDependencies {
  readFindings: () => Promise<ShControlFinding[]>;
  store: ReconciliationStore;
  now?: () => Date;
}

/**
 * One reconciliation pass. Never throws: a failure is recorded as STALE (fails
 * closed) so the compliance run itself is unaffected.
 */
export async function runReconciliation(
  report: ComplianceReport | null,
  config: ReconciliationConfig,
  deps: ReconciliationDependencies
): Promise<ReconciliationRecord> {
  const now = (deps.now ?? (() => new Date()))();
  let record: ReconciliationRecord;
  try {
    if (!report) throw new Error('No CIS_AWS_FOUNDATIONS report from this run');
    const [findings, previous] = await Promise.all([deps.readFindings(), deps.store.getLatest()]);
    record = reconcile(report, findings, previous, config, now);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error('CIS reconciliation failed; recording STALE', { error: message });
    record = staleRecord(message, report, config, now);
  }
  try {
    await deps.store.save(record);
  } catch (error) {
    console.error('CIS reconciliation record could not be saved', {
      error: error instanceof Error ? error.message : String(error),
    });
  }
  return record;
}

export interface ReconciliationSettings extends ReconciliationConfig {
  roleArn: string;
  region: string;
}

/** Reads RECONCILIATION_* settings; null when the role ARN is unset (disabled). */
export function reconciliationSettingsFromEnv(
  env: NodeJS.ProcessEnv = process.env
): ReconciliationSettings | null {
  const roleArn = (env.RECONCILIATION_SECURITY_HUB_ROLE_ARN ?? '').trim();
  if (!roleArn) return null;
  const days = Number(env.RECONCILIATION_MIN_AGREEMENT_DAYS ?? '5');
  if (!Number.isInteger(days) || days < 1) {
    throw new Error('RECONCILIATION_MIN_AGREEMENT_DAYS must be a positive integer');
  }
  return {
    roleArn,
    region:
      (env.RECONCILIATION_SECURITY_HUB_REGION ?? '').trim() ||
      (env.AWS_REGION ?? '').trim() ||
      'us-east-1',
    minAgreementDays: days,
    allowlist: new Set(
      (env.RECONCILIATION_PUBLISH_ALLOWLIST ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    ),
  };
}

/** A Security Hub client using the audit account's read-only role. */
export async function securityHubClientForRole(
  roleArn: string,
  region: string,
  sts: Pick<STSClient, 'send'> = new STSClient({ region })
): Promise<SecurityHubClient> {
  const assumed = await sts.send(
    new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: 'khalifa-cis-reconciliation',
      DurationSeconds: 3600,
    })
  );
  const c = assumed.Credentials;
  if (!c?.AccessKeyId || !c.SecretAccessKey || !c.SessionToken) {
    throw new Error('AssumeRole returned no credentials');
  }
  return new SecurityHubClient({
    region,
    maxAttempts: 8,
    credentials: {
      accessKeyId: c.AccessKeyId,
      secretAccessKey: c.SecretAccessKey,
      sessionToken: c.SessionToken,
    },
  });
}
