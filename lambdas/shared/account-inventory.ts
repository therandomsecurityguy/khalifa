import {
  ListAccountsCommand,
  ListAccountsForParentCommand,
  ListOrganizationalUnitsForParentCommand,
  type Account,
  type ListAccountsCommandOutput,
  type ListAccountsForParentCommandOutput,
  type ListOrganizationalUnitsForParentCommandOutput,
} from '@aws-sdk/client-organizations';
import { collectPaginated } from './pagination';
import { Logger } from './types';

const logger = new Logger('account-inventory');

export interface CollectionConfig {
  accountIds: string[];
  parentIds: string[];
  regions: string[];
}

export interface InventoryAccount {
  accountId: string;
  name?: string;
  state: string;
  parentId?: string;
}

export interface WorkItem {
  accountId: string;
  region: string;
  collectGlobal: boolean;
}

export interface OrganizationsReader {
  send(command: ListAccountsCommand): Promise<ListAccountsCommandOutput>;
  send(command: ListAccountsForParentCommand): Promise<ListAccountsForParentCommandOutput>;
  send(
    command: ListOrganizationalUnitsForParentCommand
  ): Promise<ListOrganizationalUnitsForParentCommandOutput>;
}

const ACCOUNT_ID_PATTERN = /^\d{12}$/;
const PARENT_ID_PATTERN = /^(?:r-[a-z0-9]{4,32}|ou-[a-z0-9]{4,32}-[a-z0-9]{8,32})$/;
const REGION_PATTERN = /^[a-z]{2}(?:-[a-z]+)+-\d$/;

function parseList(value: string | undefined): string[] {
  return [
    ...new Set(
      (value || '')
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean)
    ),
  ];
}

function requireMatching(values: string[], pattern: RegExp, name: string): void {
  const invalid = values.filter((value) => !pattern.test(value));
  if (invalid.length > 0) throw new Error(`${name} contains invalid values: ${invalid.join(', ')}`);
}

export function parseCollectionConfig(environment: NodeJS.ProcessEnv): CollectionConfig {
  const accountIds = parseList(environment.COLLECTION_ACCOUNT_IDS);
  const parentIds = parseList(environment.COLLECTION_PARENT_IDS);
  const regions = parseList(environment.COLLECTION_REGIONS || environment.AWS_REGION);

  if (accountIds.length === 0 && parentIds.length === 0) {
    throw new Error('COLLECTION_ACCOUNT_IDS or COLLECTION_PARENT_IDS is required');
  }
  if (regions.length === 0) throw new Error('COLLECTION_REGIONS is required');

  requireMatching(accountIds, ACCOUNT_ID_PATTERN, 'COLLECTION_ACCOUNT_IDS');
  requireMatching(parentIds, PARENT_ID_PATTERN, 'COLLECTION_PARENT_IDS');
  requireMatching(regions, REGION_PATTERN, 'COLLECTION_REGIONS');

  return { accountIds, parentIds, regions };
}

export function toInventoryAccount(account: Account, parentId?: string): InventoryAccount {
  if (!account.Id) throw new Error('Organizations returned an account without an ID');
  return {
    accountId: account.Id,
    name: account.Name,
    state: account.State || 'UNKNOWN',
    parentId,
  };
}

export function buildWorkItems(accounts: InventoryAccount[], regions: string[]): WorkItem[] {
  return accounts
    .filter((account) => account.state === 'ACTIVE')
    .flatMap((account) =>
      regions.map((region, index) => ({
        accountId: account.accountId,
        region,
        collectGlobal: index === 0,
      }))
    );
}

async function listAccountsForParents(
  client: OrganizationsReader,
  parentIds: string[]
): Promise<InventoryAccount[]> {
  const accounts = new Map<string, InventoryAccount>();
  const pending = [...parentIds];
  const visited = new Set<string>();

  while (pending.length > 0) {
    const parentId = pending.shift()!;
    if (visited.has(parentId)) continue;
    visited.add(parentId);

    const parentAccounts = await collectPaginated(
      (token) =>
        client.send(new ListAccountsForParentCommand({ ParentId: parentId, NextToken: token })),
      (page) => page.Accounts,
      (page) => page.NextToken
    );
    for (const account of parentAccounts) {
      const item = toInventoryAccount(account, parentId);
      accounts.set(item.accountId, item);
    }

    const childOus = await collectPaginated(
      (token) =>
        client.send(
          new ListOrganizationalUnitsForParentCommand({ ParentId: parentId, NextToken: token })
        ),
      (page) => page.OrganizationalUnits,
      (page) => page.NextToken
    );
    for (const organizationalUnit of childOus) {
      if (organizationalUnit.Id) pending.push(organizationalUnit.Id);
    }
  }

  return [...accounts.values()];
}

// Listed accounts are approved and collected as given; Organizations only
// supplies their names. Listing accounts needs the management account or a
// delegated administrator; a hub that is neither keeps collecting without names.
async function nameListedAccounts(
  client: OrganizationsReader,
  accountIds: string[]
): Promise<Map<string, string>> {
  const names = new Map<string, string>();
  if (accountIds.length === 0) return names;
  const wanted = new Set(accountIds);
  try {
    const accounts = await collectPaginated(
      (token) => client.send(new ListAccountsCommand({ NextToken: token })),
      (page) => page.Accounts,
      (page) => page.NextToken
    );
    for (const account of accounts) {
      if (account.Id && account.Name && wanted.has(account.Id)) {
        names.set(account.Id, account.Name);
      }
    }
  } catch (error) {
    logger.warn('Could not read account names from Organizations; continuing without them', {
      error: error instanceof Error ? error.message : String(error),
    });
  }
  return names;
}

export interface DiscoverOptions {
  // Read listed accounts' names from Organizations. Off by default so callers
  // that only need the approved set, such as the incremental collector on
  // every batch, never call it.
  nameListed?: boolean;
}

export async function discoverAccounts(
  client: OrganizationsReader,
  config: CollectionConfig,
  { nameListed = false }: DiscoverOptions = {}
): Promise<InventoryAccount[]> {
  const selected = new Map<string, InventoryAccount>();

  if (config.parentIds.length > 0) {
    for (const account of await listAccountsForParents(client, config.parentIds)) {
      selected.set(account.accountId, account);
    }
  }

  const listed = config.accountIds.filter((accountId) => !selected.has(accountId));
  const names = nameListed ? await nameListedAccounts(client, listed) : new Map<string, string>();
  for (const accountId of listed) {
    const name = names.get(accountId);
    selected.set(
      accountId,
      name ? { accountId, name, state: 'ACTIVE' } : { accountId, state: 'ACTIVE' }
    );
  }

  return [...selected.values()].sort((left, right) =>
    left.accountId.localeCompare(right.accountId)
  );
}
