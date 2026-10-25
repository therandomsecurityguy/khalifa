import type { Request, Response } from 'express';
import { DynamoDBIssueRepository, getRuleById } from '@khalifa/risk-engine';
import { getApiNeptuneClient } from '../services/api-dependencies';
import type { SecretRecord, SecretShare } from '../services/neptune-client';
import { secretReaders, type SecretReader } from '../services/secret-readers';
import { secretReaderCounts } from '../services/secret-reader-counts';

interface SecretReadersResult {
  items: SecretReader[];
  truncated: boolean;
  unavailable: boolean;
}
import type { SecretInventoryItem, SecretSharing, Severity } from '../types';

const neptuneClient = getApiNeptuneClient();
const issueStore = new DynamoDBIssueRepository();
const MAX_SECRETS = 5_000;
const MAX_READER_ROWS = 20_000;
const MAX_READERS = 500;
// Rules whose issues name a secret among their resources. RULE-021's anomaly
// vertex has no edge to the secret, so its issues never name one.
const SECRET_RULES = ['RULE-010', 'RULE-032', 'RULE-033'];

// The widest share wins: anyone without an org limit, or an account Khalifa
// does not collect, is outside; the whole org next; then collected accounts.
export function secretSharing(shares: SecretShare[], sharedAccounts: number): SecretSharing {
  let scope: SecretSharing['scope'] = 'account';
  for (const share of shares) {
    if ((share.anyone && !share.orgRestricted) || share.collected < share.named) {
      return { scope: 'outside', accounts: 0 };
    }
    if (share.anyone) scope = 'org';
    else if (share.named > 0 && scope === 'account') scope = 'collected';
  }
  return { scope, accounts: scope === 'collected' ? sharedAccounts : 0 };
}

function regionOf(arn: string): string {
  return arn.split(':')[3] ?? '';
}

export function toInventoryItem(
  record: SecretRecord,
  issues: SecretInventoryItem['issues']
): SecretInventoryItem {
  return {
    id: record.id,
    kind: record.kind,
    name: record.name || record.id.split(/[:/]/).pop() || record.id,
    accountId: record.accountId,
    region: regionOf(record.id),
    encryption:
      record.kind === 'ssm-plaintext'
        ? 'none'
        : record.customerManagedKey
          ? 'customer-managed'
          : 'aws-managed',
    env: record.env,
    owner: record.owner,
    rotationEnabled: record.rotationEnabled,
    lastRotated: record.lastRotated,
    createdAt: record.createdAt,
    lastAccessed: record.lastAccessed,
    lastModified: record.lastModified,
    collectionRestricted: record.collectionRestricted,
    // A policy Khalifa could not read says nothing about who it shares with.
    sharing:
      record.kind === 'secrets-manager' && !record.collectionRestricted
        ? secretSharing(record.shares, record.sharedAccounts)
        : null,
    issues,
  };
}

// Open issues from the secret rules, keyed by every resource they name. A rule
// whose lookup fails is skipped and reported, so secrets still load.
async function openSecretIssues(): Promise<{
  byId: Map<string, SecretInventoryItem['issues']>;
  unavailable: boolean;
}> {
  const lists = await Promise.allSettled(
    SECRET_RULES.map((ruleId) => issueStore.getOpenIssuesByRule(ruleId))
  );
  const byId = new Map<string, SecretInventoryItem['issues']>();
  for (const list of lists) {
    if (list.status !== 'fulfilled') continue;
    for (const issue of list.value) {
      const ruleName = issue.metadata?.ruleName;
      const entry = {
        id: issue.id,
        ruleId: issue.ruleId,
        severity: issue.severity as Severity,
        title:
          (typeof ruleName === 'string' && ruleName) ||
          getRuleById(issue.ruleId)?.name ||
          issue.ruleId,
        openedAt: issue.createdAt,
      };
      for (const resource of issue.resourcesInvolved ?? []) {
        const entries = byId.get(resource.resourceId) ?? [];
        if (!entries.some((existing) => existing.id === issue.id)) entries.push(entry);
        byId.set(resource.resourceId, entries);
      }
    }
  }
  const failed = lists.filter((list) => list.status === 'rejected').length;
  if (failed) console.warn(`Secrets: ${failed} issue lookups failed`);
  return { byId, unavailable: failed > 0 };
}

export async function listSecrets(_req: Request, res: Response): Promise<void> {
  try {
    const [inventory, issues] = await Promise.all([
      neptuneClient.listSecrets(MAX_SECRETS),
      openSecretIssues(),
    ]);
    res.json({
      items: inventory.items.map((record) =>
        toInventoryItem(record, issues.byId.get(record.id) ?? [])
      ),
      truncated: inventory.truncated,
      issuesUnavailable: issues.unavailable,
    });
  } catch (error) {
    console.error('Error listing secrets:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to list secrets' });
  }
}

// Readable-by counts for every secret, separate from the list so a slow account
// never holds up the table. Counts only: no principal or policy names.
export async function listSecretReaderCounts(_req: Request, res: Response): Promise<void> {
  try {
    const { secrets, truncated } = await neptuneClient.listSecretAccounts(MAX_SECRETS);
    const result = await secretReaderCounts(
      secrets,
      (accountId, limit) => neptuneClient.secretReaderRows(accountId, limit),
      MAX_READER_ROWS
    );
    if (result.unavailableAccounts) {
      console.warn(`Secrets: reader counts unavailable for ${result.unavailableAccounts} accounts`);
    }
    // A secret list cut short leaves secrets uncounted, not miscounted.
    res.json({ ...result, truncated });
  } catch (error) {
    console.error('Error counting secret readers:', error instanceof Error ? error.name : 'error');
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to count secret readers' });
  }
}

// Only a Secrets Manager secret or SSM parameter ARN is ever looked up.
const SECRET_ARN =
  /^arn:aws(?:-[a-z]+)*:(?:secretsmanager:[a-z0-9-]+:\d{12}:secret:|ssm:[a-z0-9-]+:\d{12}:parameter\/)[\x21-\x7e]{1,512}$/;

// Identity-policy readers in the secret's own account. SSM parameters are read
// through ssm:GetParameter, which this does not evaluate. A failed lookup
// leaves the rest of the page intact.
async function readersOf(record: SecretRecord): Promise<SecretReadersResult | null> {
  if (record.kind !== 'secrets-manager' || !record.accountId) return null;
  try {
    const { rows, truncated } = await neptuneClient.secretReaderRows(
      record.accountId,
      MAX_READER_ROWS
    );
    const result = secretReaders(rows, record.id, MAX_READERS);
    return { items: result.readers, truncated: truncated || result.truncated, unavailable: false };
  } catch (error) {
    console.warn('Secrets: reader lookup failed', error instanceof Error ? error.name : 'error');
    return { items: [], truncated: false, unavailable: true };
  }
}

export async function getSecret(req: Request<{ arn: string }>, res: Response): Promise<void> {
  const { arn } = req.params;
  if (typeof arn !== 'string' || !SECRET_ARN.test(arn)) {
    res.status(400).json({ code: 'BAD_REQUEST', message: 'Invalid secret ARN' });
    return;
  }
  try {
    const [record, issues] = await Promise.all([neptuneClient.getSecret(arn), openSecretIssues()]);
    if (!record) {
      res.status(404).json({ code: 'NOT_FOUND', message: 'Secret not found' });
      return;
    }
    res.json({
      item: toInventoryItem(record, issues.byId.get(record.id) ?? []),
      issuesUnavailable: issues.unavailable,
      readers: await readersOf(record),
    });
  } catch (error) {
    console.error('Error getting secret:', error);
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Failed to get secret' });
  }
}
