import {
  IAMClient,
  ListUsersCommand,
  ListAccessKeysCommand,
  GetAccessKeyLastUsedCommand,
  ListMFADevicesCommand,
  GetLoginProfileCommand,
  GetAccountSummaryCommand,
  GenerateCredentialReportCommand,
  GetCredentialReportCommand,
} from '@aws-sdk/client-iam';
import type { GraphNode, GraphEdge } from '../../shared/types';
import { collectPaginated } from '../../shared/pagination';

export interface CollectResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

const UNUSED_DAYS_THRESHOLD = 90;

function isNoSuchEntity(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.name === 'NoSuchEntity' || error.name === 'NoSuchEntityException')
  );
}

function isCredentialReportAbsent(error: unknown): boolean {
  return (
    isNoSuchEntity(error) ||
    (error instanceof Error &&
      (error.name === 'CredentialReportNotPresentException' ||
        // A report expires 4 hours after it is generated; the collector runs
        // every 4 hours, so the last run's report is often just expired.
        error.name === 'CredentialReportExpiredException'))
  );
}

function isCredentialReportNotReady(error: unknown): boolean {
  return error instanceof Error && error.name === 'CredentialReportNotReadyException';
}

// Generation usually takes seconds; a minute covers large accounts.
export const CREDENTIAL_REPORT_WAIT_MS = 60_000;
const CREDENTIAL_REPORT_POLL_MS = 3_000;

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// The current report, generating one and waiting for it when there is none.
// Throws if none is ready in time, so the stage records as FAILED rather than
// as a complete collection with no rows: the 1.5, 1.10 and 1.12 evaluators
// read this stage's coverage, and an empty "complete" one passed or failed
// accounts on data that was never read.
async function readCredentialReport(
  client: IAMClient,
  wait: (ms: number) => Promise<void>,
  waitMs: number
): Promise<{ content: string; generatedTime?: string }> {
  let waited = 0;
  for (;;) {
    try {
      const report = await client.send(new GetCredentialReportCommand({}));
      if (report.Content) {
        return {
          content: decodeURIComponent(Buffer.from(report.Content).toString('utf-8')),
          generatedTime: report.GeneratedTime?.toISOString(),
        };
      }
    } catch (e) {
      if (isCredentialReportAbsent(e)) {
        const { State } = await client.send(new GenerateCredentialReportCommand({}));
        if (State === 'COMPLETE') continue;
      } else if (!isCredentialReportNotReady(e)) {
        throw e;
      }
    }
    if (waited >= waitMs) {
      throw new Error(`IAM credential report was not ready within ${waitMs / 1000}s`);
    }
    await wait(CREDENTIAL_REPORT_POLL_MS);
    waited += CREDENTIAL_REPORT_POLL_MS;
  }
}

function daysBetween(from: Date | string, to: Date | string): number {
  const start = new Date(from).getTime();
  const end = new Date(to).getTime();
  if (Number.isNaN(start) || Number.isNaN(end)) return 0;
  return Math.max(0, Math.floor((end - start) / 86_400_000));
}

export async function collectIamAccessKeys(
  client: IAMClient,
  accountId: string
): Promise<CollectResult> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const now = new Date();

  const users = await collectPaginated(
    (marker) => client.send(new ListUsersCommand({ Marker: marker })),
    (page) => page.Users,
    (page) => (page.IsTruncated ? page.Marker : undefined)
  );

  for (const user of users) {
    if (!user.UserName) continue;
    const userArn = `arn:aws:iam::${accountId}:user/${user.UserName}`;

    let mfaEnabled = false;
    const mfaDevices = await collectPaginated(
      (marker) =>
        client.send(new ListMFADevicesCommand({ UserName: user.UserName!, Marker: marker })),
      (page) => page.MFADevices,
      (page) => (page.IsTruncated ? page.Marker : undefined)
    );
    mfaEnabled = mfaDevices.length > 0;

    let passwordEnabled = false;
    try {
      await client.send(new GetLoginProfileCommand({ UserName: user.UserName! }));
      passwordEnabled = true;
    } catch (e) {
      if (!isNoSuchEntity(e)) throw e;
    }

    let activeKeyUsedRecently = false;
    const keys = await collectPaginated(
      (marker) =>
        client.send(new ListAccessKeysCommand({ UserName: user.UserName!, Marker: marker })),
      (page) => page.AccessKeyMetadata,
      (page) => (page.IsTruncated ? page.Marker : undefined)
    );

    for (const key of keys) {
      if (!user.UserName || !key.AccessKeyId) continue;
      const createdDate = key.CreateDate ?? now;
      const keyArn = `${userArn}/access-key/${key.AccessKeyId}`;

      let lastUsed: Date | undefined;
      let lastUsedService: string | undefined;
      let lastUsedRegion: string | undefined;
      try {
        const usage = await client.send(
          new GetAccessKeyLastUsedCommand({ AccessKeyId: key.AccessKeyId })
        );
        lastUsed = usage.AccessKeyLastUsed?.LastUsedDate ?? undefined;
        lastUsedService = usage.AccessKeyLastUsed?.ServiceName;
        lastUsedRegion = usage.AccessKeyLastUsed?.Region;
      } catch (e) {
        if (!isNoSuchEntity(e)) throw e;
      }

      const lastUsedDate = lastUsed ?? createdDate;
      const lastUsedDaysAgo = daysBetween(lastUsedDate, now);
      if (key.Status === 'Active' && lastUsedDaysAgo <= UNUSED_DAYS_THRESHOLD) {
        activeKeyUsedRecently = true;
      }

      nodes.push({
        id: keyArn,
        label: 'AccessKey',
        properties: {
          id: key.AccessKeyId,
          arn: keyArn,
          account_id: accountId,
          user_arn: userArn,
          status: key.Status,
          created_date: createdDate.toISOString(),
          key_age_days: daysBetween(createdDate, now),
          last_used_date: lastUsedDate.toISOString(),
          last_used_days_ago: lastUsedDaysAgo,
          last_used_service: lastUsedService,
          last_used_region: lastUsedRegion,
        },
      });
      edges.push({ from: userArn, to: keyArn, label: 'HAS_ACCESS_KEY' });
    }

    nodes.push({
      id: userArn,
      label: 'IamUser',
      properties: {
        id: user.UserName,
        arn: userArn,
        account_id: accountId,
        mfa_enabled: mfaEnabled,
        password_enabled: passwordEnabled,
        likely_workload_identity_candidate: passwordEnabled === false && activeKeyUsedRecently,
      },
    });
  }

  await appendRootPosture(client, accountId, nodes, edges);

  return { nodes, edges };
}

async function appendRootPosture(
  client: IAMClient,
  accountId: string,
  nodes: GraphNode[],
  edges: GraphEdge[]
): Promise<void> {
  const rootArn = `arn:aws:iam::${accountId}:root`;
  const summary = await client.send(new GetAccountSummaryCommand({}));
  const summaryMap = summary.SummaryMap || {};

  const rootMfaEnabled = summaryMap.AccountMFAEnabled === 1;
  const rootAccessKeyPresent = summaryMap.AccountAccessKeysPresent === 1;

  nodes.push({
    id: rootArn,
    label: 'IamUser',
    properties: {
      id: 'root',
      arn: rootArn,
      account_id: accountId,
      mfa_enabled: rootMfaEnabled,
      access_key_present: rootAccessKeyPresent,
    },
  });

  if (rootAccessKeyPresent) {
    const rootKeyArn = `${rootArn}/access-key/present`;
    nodes.push({
      id: rootKeyArn,
      label: 'AccessKey',
      properties: {
        id: 'present',
        arn: rootKeyArn,
        account_id: accountId,
        user_arn: rootArn,
        status: 'Active',
      },
    });
    edges.push({ from: rootArn, to: rootKeyArn, label: 'HAS_ACCESS_KEY' });
  }
}

export interface CredentialReportSummary {
  generatedTime: string;
  userCount: number;
  usersWithMfa: number;
  usersWithConsole: number;
  activeAccessKeys: number;
}

interface CredentialReportRow {
  arn: string;
  user: string;
  password_enabled: boolean;
  password_last_used?: string;
  mfa_active: boolean;
  access_key_1_active: boolean;
  access_key_1_last_used_date?: string;
  access_key_2_active: boolean;
  access_key_2_last_used_date?: string;
  /**
   * Root row only. AWS reports a root password as `not_supported` normally and
   * as `false` only once root credentials are removed (Organizations central
   * root access); the boolean above can't tell the two apart. False when root
   * has no password, access key or signing certificate.
   */
  root_credentials_present?: boolean;
}

export async function collectIamCredentialReport(
  client: IAMClient,
  accountId: string,
  wait: (ms: number) => Promise<void> = sleep,
  waitMs: number = CREDENTIAL_REPORT_WAIT_MS
): Promise<CollectResult & { report: CredentialReportSummary }> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  const { content: reportContent, generatedTime } = await readCredentialReport(
    client,
    wait,
    waitMs
  );

  const rows = parseCredentialReport(reportContent);
  const rootArn = `arn:aws:iam::${accountId}:root`;
  for (const row of rows) {
    nodes.push({
      id: row.arn,
      label: 'IamUser',
      properties: {
        id: row.user,
        arn: row.arn,
        account_id: accountId,
        password_enabled: row.password_enabled,
        password_last_used: row.password_last_used,
        mfa_enabled: row.mfa_active,
        // Undefined except on the root row; undefined properties are not written.
        root_credentials_present: row.root_credentials_present,
      },
    });
    edges.push({ from: `arn:aws:iam::${accountId}:root`, to: row.arn, label: 'OWNS' });
  }

  const reportId = `arn:aws:iam::${accountId}:credential-report`;
  nodes.push({
    id: reportId,
    label: 'IamCredentialReport',
    properties: {
      id: 'credential-report',
      arn: reportId,
      account_id: accountId,
      generated_time: generatedTime,
      user_count: rows.length,
      users_with_mfa: rows.filter((r) => r.mfa_active).length,
      users_with_console: rows.filter((r) => r.password_enabled).length,
      active_access_keys: rows.filter((r) => r.access_key_1_active || r.access_key_2_active).length,
    },
  });
  edges.push({ from: rootArn, to: reportId, label: 'OWNS' });

  return {
    nodes,
    edges,
    report: {
      generatedTime: generatedTime ?? new Date(0).toISOString(),
      userCount: rows.length,
      usersWithMfa: rows.filter((r) => r.mfa_active).length,
      usersWithConsole: rows.filter((r) => r.password_enabled).length,
      activeAccessKeys: rows.filter((r) => r.access_key_1_active || r.access_key_2_active).length,
    },
  };
}

export function parseCredentialReport(csv: string): CredentialReportRow[] {
  const rows: CredentialReportRow[] = [];
  const lines = csv.split(/\r?\n/).filter((line) => line.trim().length > 0);
  if (lines.length < 2) return rows;

  const header = parseCsvLine(lines[0]);
  const column = (name: string) => header.indexOf(name);

  const idx = {
    user: column('user'),
    arn: column('arn'),
    passwordEnabled: column('password_enabled'),
    passwordLastUsed: column('password_last_used'),
    mfaActive: column('mfa_active'),
    key1Active: column('access_key_1_active'),
    key1LastUsed: column('access_key_1_last_used_date'),
    key2Active: column('access_key_2_active'),
    key2LastUsed: column('access_key_2_last_used_date'),
    cert1Active: column('cert_1_active'),
    cert2Active: column('cert_2_active'),
  };

  for (let i = 1; i < lines.length; i += 1) {
    const values = parseCsvLine(lines[i]);
    if (!values[idx.user] && !values[idx.arn]) continue;

    const accessKey1LastUsed = cellDate(values[idx.key1LastUsed]);
    const accessKey2LastUsed = cellDate(values[idx.key2LastUsed]);
    const isRoot = values[idx.user] === '<root_account>';

    rows.push({
      arn: values[idx.arn] || '',
      user: values[idx.user] || '',
      password_enabled: values[idx.passwordEnabled] === 'true',
      password_last_used: cellDate(values[idx.passwordLastUsed]),
      mfa_active: values[idx.mfaActive] === 'true',
      access_key_1_active: values[idx.key1Active] === 'true',
      access_key_1_last_used_date: accessKey1LastUsed,
      access_key_2_active: values[idx.key2Active] === 'true',
      access_key_2_last_used_date: accessKey2LastUsed,
      ...(isRoot
        ? {
            root_credentials_present: !(
              values[idx.passwordEnabled] === 'false' &&
              values[idx.key1Active] !== 'true' &&
              values[idx.key2Active] !== 'true' &&
              values[idx.cert1Active] !== 'true' &&
              values[idx.cert2Active] !== 'true'
            ),
          }
        : {}),
    });
  }

  return rows;
}

function cell(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed === 'not_supported' || trimmed === 'no_information') return undefined;
  return trimmed;
}

function cellDate(value: string | undefined): string | undefined {
  const text = cell(value);
  if (!text) return undefined;
  const date = new Date(text);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toISOString();
}

function parseCsvLine(line: string): string[] {
  const values: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (inQuotes) {
      if (char === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        current += char;
      }
      continue;
    }
    if (char === '"') {
      inQuotes = true;
      continue;
    }
    if (char === ',') {
      values.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  values.push(current);
  return values;
}
