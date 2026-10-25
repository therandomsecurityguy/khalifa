import { clearReaderCountCache, secretReaderCounts } from '../services/secret-reader-counts';
import type { ReaderRow } from '../services/secret-readers';

const A = '111122223333';
const B = '444455556666';
const secret = (account: string, name: string) =>
  `arn:aws:secretsmanager:us-west-2:${account}:secret:${name}`;

function row(
  account: string,
  role: string,
  resources: string[],
  id = `${account}-${role}`
): ReaderRow {
  return {
    principal: {
      id: `arn:aws:iam::${account}:role/${role}`,
      label: 'IamRole',
      name: role,
      admin: false,
    },
    policy: { type: 'inline', arn: '', name: role },
    statement: {
      id,
      effect: 'Allow',
      actions: JSON.stringify(['secretsmanager:GetSecretValue']),
      notActions: null,
      resources: JSON.stringify(resources),
      notResources: null,
      conditional: false,
    },
  };
}

describe('secretReaderCounts', () => {
  beforeEach(() => clearReaderCountCache());

  it('counts readers per secret, broad ones separately, within each account', async () => {
    const load = jest.fn(async (account: string) => ({
      rows:
        account === A
          ? [row(A, 'app', [secret(A, 'prod/key')]), row(A, 'admin', ['*'])]
          : [row(B, 'other', ['*'])],
      truncated: false,
    }));
    const result = await secretReaderCounts(
      [
        { id: secret(A, 'prod/key'), accountId: A },
        { id: secret(A, 'dev/key'), accountId: A },
        { id: secret(B, 'x'), accountId: B },
      ],
      load,
      100
    );
    expect(result).toEqual({
      counts: {
        [secret(A, 'prod/key')]: { total: 2, broad: 1, partial: false },
        [secret(A, 'dev/key')]: { total: 1, broad: 1, partial: false },
        [secret(B, 'x')]: { total: 1, broad: 1, partial: false },
      },
      unavailableAccounts: 0,
      partialAccounts: 0,
    });
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('reads each account once within ten minutes, and again after', async () => {
    const load = jest.fn(async () => ({ rows: [row(A, 'app', ['*'])], truncated: true }));
    const secrets = [{ id: secret(A, 'k'), accountId: A }];
    await secretReaderCounts(secrets, load, 100, 0);
    const again = await secretReaderCounts(secrets, load, 100, 9 * 60_000);
    expect(load).toHaveBeenCalledTimes(1);
    expect(again.partialAccounts).toBe(1);
    expect(again.counts[secret(A, 'k')]).toEqual({ total: 1, broad: 1, partial: true });
    await secretReaderCounts(secrets, load, 100, 11 * 60_000);
    expect(load).toHaveBeenCalledTimes(2);
  });

  it('leaves out an account that fails, says so, and retries it next time', async () => {
    const load = jest
      .fn()
      .mockRejectedValueOnce(new Error('timeout'))
      .mockResolvedValue({ rows: [row(A, 'app', ['*'])], truncated: false });
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    const secrets = [{ id: secret(A, 'k'), accountId: A }];
    const failed = await secretReaderCounts(secrets, load, 100, 0);
    expect(failed).toEqual({ counts: {}, unavailableAccounts: 1, partialAccounts: 0 });
    const retried = await secretReaderCounts(secrets, load, 100, 1);
    expect(retried.counts[secret(A, 'k')]).toEqual({ total: 1, broad: 1, partial: false });
  });

  it('starts no account after the time budget and counts the rest as unavailable', async () => {
    let time = 0;
    const load = jest.fn(async () => {
      time += 15_000;
      return { rows: [row(A, 'app', ['*'])], truncated: false };
    });
    const accounts = ['1', '2', '3', '4', '5', '6'].map((n) => n.repeat(12));
    const result = await secretReaderCounts(
      accounts.map((accountId) => ({ id: secret(accountId, 'k'), accountId })),
      load,
      100,
      0,
      () => time
    );
    expect(load.mock.calls.length).toBeLessThan(accounts.length);
    expect(result.unavailableAccounts).toBe(accounts.length - load.mock.calls.length);
  });
});
