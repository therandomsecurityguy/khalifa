import { IAMClient } from '@aws-sdk/client-iam';
import {
  collectIamAccessKeys,
  collectIamCredentialReport,
  parseCredentialReport,
} from './iam-posture';

interface MockSendMap {
  [commandName: string]: (input: Record<string, unknown>) => unknown;
}

function createIamClient(responses: MockSendMap): IAMClient {
  const send = jest.fn(async (command: { constructor: { name: string } }) => {
    const handler = responses[command.constructor.name];
    if (!handler) {
      throw new Error(`Unexpected command in test: ${command.constructor.name}`);
    }
    return handler((command as unknown as { input: Record<string, unknown> }).input || {});
  });
  return { send } as unknown as IAMClient;
}

const ACCOUNT = '111122223333';
const NOW = new Date('2026-09-12T00:00:00.000Z');

describe('collectIamAccessKeys', () => {
  beforeEach(() => {
    jest.useFakeTimers({ now: NOW });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('creates AccessKey nodes, HAS_ACCESS_KEY edges, and IamUser posture props', async () => {
    const client = createIamClient({
      ListUsersCommand: () => ({
        Users: [{ UserName: 'deploy-bot', CreateDate: new Date('2024-01-01T00:00:00.000Z') }],
      }),
      ListMFADevicesCommand: () => ({ MFADevices: [] }),
      GetLoginProfileCommand: () => {
        const error = new Error('no profile');
        error.name = 'NoSuchEntity';
        throw error;
      },
      ListAccessKeysCommand: () => ({
        AccessKeyMetadata: [
          {
            AccessKeyId: 'AKIAEXAMPLE1',
            Status: 'Active',
            CreateDate: new Date('2025-01-01T00:00:00.000Z'),
          },
        ],
      }),
      GetAccessKeyLastUsedCommand: () => ({
        AccessKeyLastUsed: {
          LastUsedDate: new Date('2026-09-01T00:00:00.000Z'),
          ServiceName: 's3',
          Region: 'us-east-1',
        },
      }),
      GetAccountSummaryCommand: () => ({ SummaryMap: { AccountMFAEnabled: 0 } }),
    });

    const { nodes, edges } = await collectIamAccessKeys(client, ACCOUNT);

    const keyNode = nodes.find((n) => n.id.endsWith('/access-key/AKIAEXAMPLE1'));
    expect(keyNode?.label).toBe('AccessKey');
    expect(keyNode?.properties).toMatchObject({
      account_id: ACCOUNT,
      status: 'Active',
      key_age_days: 619,
      last_used_date: '2026-09-01T00:00:00.000Z',
      last_used_days_ago: 11,
      last_used_service: 's3',
      last_used_region: 'us-east-1',
    });

    expect(edges).toContainEqual({
      from: `arn:aws:iam::${ACCOUNT}:user/deploy-bot`,
      to: keyNode?.id,
      label: 'HAS_ACCESS_KEY',
    });

    const userNode = nodes.find((n) => n.id === `arn:aws:iam::${ACCOUNT}:user/deploy-bot`);
    expect(userNode?.properties).toMatchObject({
      mfa_enabled: false,
      password_enabled: false,
      likely_workload_identity_candidate: true,
    });
  });

  it('falls back to create date when a key has never been used', async () => {
    const client = createIamClient({
      ListUsersCommand: () => ({
        Users: [{ UserName: 'stale', CreateDate: new Date('2024-01-01T00:00:00.000Z') }],
      }),
      ListMFADevicesCommand: () => ({ MFADevices: [{ SerialNumber: 'arn:aws:iam:::mfa/x' }] }),
      GetLoginProfileCommand: () => ({ LoginProfile: {} }),
      ListAccessKeysCommand: () => ({
        AccessKeyMetadata: [
          {
            AccessKeyId: 'AKIAOLD',
            Status: 'Active',
            CreateDate: new Date('2024-01-01T00:00:00.000Z'),
          },
        ],
      }),
      GetAccessKeyLastUsedCommand: () => ({}),
      GetAccountSummaryCommand: () => ({ SummaryMap: {} }),
    });

    const { nodes } = await collectIamAccessKeys(client, ACCOUNT);

    const keyNode = nodes.find((n) => n.id.endsWith('/access-key/AKIAOLD'));
    expect(keyNode?.properties).toMatchObject({
      last_used_date: '2024-01-01T00:00:00.000Z',
      last_used_days_ago: 985,
    });
    const userNode = nodes.find((n) => n.label === 'IamUser' && !n.id.endsWith(':root'));
    expect(userNode?.properties).toMatchObject({
      mfa_enabled: true,
      password_enabled: true,
      likely_workload_identity_candidate: false,
    });
  });

  it('marks root posture and emits a synthetic root access key when present', async () => {
    const client = createIamClient({
      ListUsersCommand: () => ({ Users: [] }),
      GetAccountSummaryCommand: () => ({
        SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 1 },
      }),
    });

    const { nodes, edges } = await collectIamAccessKeys(client, ACCOUNT);

    const rootNode = nodes.find((n) => n.id === `arn:aws:iam::${ACCOUNT}:root`);
    expect(rootNode?.properties).toMatchObject({
      mfa_enabled: true,
      access_key_present: true,
    });
    const rootKey = nodes.find((n) => n.id === `arn:aws:iam::${ACCOUNT}:root/access-key/present`);
    expect(rootKey?.label).toBe('AccessKey');
    expect(edges).toContainEqual({
      from: `arn:aws:iam::${ACCOUNT}:root`,
      to: `arn:aws:iam::${ACCOUNT}:root/access-key/present`,
      label: 'HAS_ACCESS_KEY',
    });
  });

  it('does not emit a root access key when none is present', async () => {
    const client = createIamClient({
      ListUsersCommand: () => ({ Users: [] }),
      GetAccountSummaryCommand: () => ({
        SummaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0 },
      }),
    });

    const { nodes, edges } = await collectIamAccessKeys(client, ACCOUNT);

    expect(nodes).toHaveLength(1);
    expect(edges).toHaveLength(0);
  });
});

describe('collectIamCredentialReport', () => {
  const reportCsv = [
    'user,arn,create_date,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date',
    'deploy-bot,"arn:aws:iam::111122223333:user/deploy-bot",2024-01-01T00:00:00Z,false,not_supported,true,true,2025-01-01T00:00:00Z,2026-01-01T00:00:00Z,false,not_supported,not_supported',
    'console-user,"arn:aws:iam::111122223333:user/console-user",2024-02-01T00:00:00Z,true,2026-09-01T12:00:00Z,false,false,not_supported,not_supported,false,not_supported,not_supported',
  ].join('\n');

  it('parses report rows into IamUser patches and a summary node', async () => {
    const client = createIamClient({
      GetCredentialReportCommand: () => ({
        Content: Buffer.from(reportCsv, 'utf-8'),
        GeneratedTime: new Date('2026-09-12T01:00:00.000Z'),
      }),
    });

    const { nodes, edges, report } = await collectIamCredentialReport(client, ACCOUNT);

    expect(report).toEqual({
      generatedTime: '2026-09-12T01:00:00.000Z',
      userCount: 2,
      usersWithMfa: 1,
      usersWithConsole: 1,
      activeAccessKeys: 1,
    });

    const patch = nodes.find((n) => n.id.endsWith('user/deploy-bot'));
    expect(patch?.properties).toMatchObject({
      password_enabled: false,
      mfa_enabled: true,
      password_last_used: undefined,
    });

    const consolePatch = nodes.find((n) => n.id.endsWith('user/console-user'));
    expect(consolePatch?.properties).toMatchObject({
      password_enabled: true,
      password_last_used: '2026-09-01T12:00:00.000Z',
      mfa_enabled: false,
    });

    const summary = nodes.find((n) => n.label === 'IamCredentialReport');
    expect(summary?.properties).toMatchObject({
      user_count: 2,
      users_with_mfa: 1,
      users_with_console: 1,
      active_access_keys: 1,
    });
    expect(edges).toContainEqual({
      from: `arn:aws:iam::${ACCOUNT}:root`,
      to: `arn:aws:iam::${ACCOUNT}:credential-report`,
      label: 'OWNS',
    });
  });

  const named = (name: string) => Object.assign(new Error(name), { name });
  const ready = () => ({
    Content: Buffer.from(reportCsv, 'utf-8'),
    GeneratedTime: new Date('2026-09-12T01:00:00.000Z'),
  });

  // A queue of GetCredentialReport outcomes: an Error is thrown, anything else returned.
  function reportClient(outcomes: unknown[], generateState = 'STARTED') {
    let i = 0;
    const generate = jest.fn(() => ({ State: generateState }));
    const client = createIamClient({
      GetCredentialReportCommand: () => {
        const next = outcomes[Math.min(i++, outcomes.length - 1)];
        if (next instanceof Error) throw next;
        return next;
      },
      GenerateCredentialReportCommand: generate,
    });
    return { client, generate };
  }
  const noWait = jest.fn(async () => {});

  it.each(['CredentialReportNotPresentException', 'CredentialReportExpiredException'])(
    'generates a report on %s and waits for it',
    async (error) => {
      const { client, generate } = reportClient([
        named(error),
        named('CredentialReportNotReadyException'),
        ready(),
      ]);

      const { report } = await collectIamCredentialReport(client, ACCOUNT, noWait);

      expect(generate).toHaveBeenCalledTimes(1);
      expect(report.userCount).toBe(2);
    }
  );

  it('reads straight away when generation completes immediately', async () => {
    const wait = jest.fn(async () => {});
    const { client } = reportClient(
      [named('CredentialReportNotPresentException'), ready()],
      'COMPLETE'
    );

    const { report } = await collectIamCredentialReport(client, ACCOUNT, wait);

    expect(report.userCount).toBe(2);
    expect(wait).not.toHaveBeenCalled();
  });

  // An empty result would be recorded as a complete collection, and 1.5, 1.10
  // and 1.12 would judge the account on rows that were never read.
  it('throws, rather than returning nothing, when no report is ready in time', async () => {
    const { client } = reportClient([named('CredentialReportNotReadyException')]);

    await expect(collectIamCredentialReport(client, ACCOUNT, noWait, 9_000)).rejects.toThrow(
      'not ready within 9s'
    );
  });

  it('propagates other errors', async () => {
    const { client, generate } = reportClient([named('AccessDenied')]);

    await expect(collectIamCredentialReport(client, ACCOUNT, noWait)).rejects.toThrow(
      'AccessDenied'
    );
    expect(generate).not.toHaveBeenCalled();
  });
});

describe('parseCredentialReport', () => {
  it('handles quoted fields and normalizes sentinel values', () => {
    const csv = [
      'user,arn,password_enabled,password_last_used,mfa_active',
      '"quoted,user","arn:aws:iam::111122223333:user/q",true,2026-01-05T00:00:00Z,false',
      'plain,arn:aws:iam::111122223333:user/plain,not_supported,not_supported,true',
    ].join('\n');

    const rows = parseCredentialReport(csv);

    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      user: 'quoted,user',
      arn: 'arn:aws:iam::111122223333:user/q',
      password_enabled: true,
      password_last_used: '2026-01-05T00:00:00.000Z',
      mfa_active: false,
    });
    expect(rows[1]).toMatchObject({
      password_enabled: false,
      password_last_used: undefined,
      mfa_active: true,
    });
  });

  // AWS reports a root password as not_supported normally, and as false only once
  // root credentials are removed (Organizations central root access).
  it.each([
    ['root credentials removed', 'false,false,false,false,false', false],
    ['normal root with a password', 'not_supported,false,false,false,false', true],
    ['no password but an active access key', 'false,true,false,false,false', true],
    ['no password but an active signing certificate', 'false,false,false,true,false', true],
  ])('records root credential presence: %s', (_case, cells, present) => {
    const csv = [
      'user,arn,password_enabled,access_key_1_active,access_key_2_active,cert_1_active,cert_2_active',
      `<root_account>,arn:aws:iam::111122223333:root,${cells}`,
      'alice,arn:aws:iam::111122223333:user/alice,true,false,false,false,false',
    ].join('\n');

    const [root, alice] = parseCredentialReport(csv);

    expect(root.root_credentials_present).toBe(present);
    expect(alice).not.toHaveProperty('root_credentials_present');
  });

  it('returns an empty list for a header-only report', () => {
    expect(parseCredentialReport('user,arn\n')).toEqual([]);
  });
});
