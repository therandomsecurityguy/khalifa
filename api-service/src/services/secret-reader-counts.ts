import {
  countReaders,
  prepareStatements,
  type PreparedStatements,
  type ReaderRow,
} from './secret-readers';

const CACHE_MS = 10 * 60_000;
const CONCURRENCY = 4;
// No account starts after this; with each read capped at 10s the request ends
// well inside the UI proxy's 35s timeout. Accounts left over count as unavailable.
const START_BUDGET_MS = 20_000;

export interface ReaderCount {
  total: number;
  broad: number;
  // The account had more policy rows than were read, so the real counts may
  // be higher: shown as "at least".
  partial: boolean;
}

interface AccountReaders {
  statements: PreparedStatements;
  truncated: boolean;
  // Counts already worked out from these statements, by secret ARN.
  counts: Map<string, ReaderCount>;
}

type LoadRows = (
  accountId: string,
  limit: number
) => Promise<{ rows: ReaderRow[]; truncated: boolean }>;

// Per account, held briefly: the graph changes only when a collection lands,
// and every list load would otherwise re-read and re-count each account. The
// promise is cached so concurrent loads share one read; a failure is not.
const cache = new Map<string, { at: number; value: Promise<AccountReaders> }>();

export function clearReaderCountCache(): void {
  cache.clear();
}

function readersIn(
  accountId: string,
  load: LoadRows,
  rowLimit: number,
  now: number
): Promise<AccountReaders> {
  const hit = cache.get(accountId);
  if (hit && now - hit.at < CACHE_MS) return hit.value;
  const value = load(accountId, rowLimit).then(({ rows, truncated }) => ({
    statements: prepareStatements(rows),
    truncated,
    counts: new Map<string, ReaderCount>(),
  }));
  cache.set(accountId, { at: now, value });
  value.catch(() => {
    if (cache.get(accountId)?.value === value) cache.delete(accountId);
  });
  return value;
}

function countFor(account: AccountReaders, arn: string): ReaderCount {
  let count = account.counts.get(arn);
  if (!count) {
    count = { ...countReaders(account.statements, arn), partial: account.truncated };
    account.counts.set(arn, count);
  }
  return count;
}

// How many principals can read each secret, and how many of them broadly.
// Accounts are read a few at a time; one that fails leaves its secrets out.
export async function secretReaderCounts(
  secrets: Array<{ id: string; accountId: string }>,
  load: LoadRows,
  rowLimit: number,
  now = Date.now(),
  clock: () => number = Date.now
): Promise<{
  counts: Record<string, ReaderCount>;
  unavailableAccounts: number;
  partialAccounts: number;
}> {
  const byAccount = new Map<string, string[]>();
  for (const secret of secrets) {
    if (!secret.accountId) continue;
    const ids = byAccount.get(secret.accountId) ?? [];
    ids.push(secret.id);
    byAccount.set(secret.accountId, ids);
  }
  const accounts = [...byAccount.keys()];
  const counts = new Map<string, ReaderCount>();
  let unavailableAccounts = 0;
  let partialAccounts = 0;
  let next = 0;
  const startedAt = clock();
  async function worker(): Promise<void> {
    while (next < accounts.length) {
      if (clock() - startedAt > START_BUDGET_MS) {
        unavailableAccounts += accounts.length - next;
        next = accounts.length;
        return;
      }
      const accountId = accounts[next++];
      try {
        const account = await readersIn(accountId, load, rowLimit, now);
        if (account.truncated) partialAccounts += 1;
        for (const arn of byAccount.get(accountId) ?? []) counts.set(arn, countFor(account, arn));
      } catch (error) {
        unavailableAccounts += 1;
        console.warn(
          'Secrets: reader count failed for an account',
          error instanceof Error ? error.name : 'error'
        );
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, accounts.length) }, worker));
  return { counts: Object.fromEntries(counts), unavailableAccounts, partialAccounts };
}
