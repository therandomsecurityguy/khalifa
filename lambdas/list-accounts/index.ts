import { randomUUID } from 'crypto';
import { OrganizationsClient } from '@aws-sdk/client-organizations';
import {
  buildWorkItems,
  discoverAccounts,
  parseCollectionConfig,
  type InventoryAccount,
  type OrganizationsReader,
  type WorkItem,
} from '../shared/account-inventory';
import type { GraphWriter } from '../shared/graph-batch-writer';
import { invokeGraphWriter } from '../shared/graph-writer-client';
import type { GraphNode } from '../shared/types';
import { Logger } from '../shared/types';

const logger = new Logger('list-accounts');

function accountNodes(
  accounts: InventoryAccount[],
  observedAt: string,
  runId: string,
  prodAccountIds: string[]
): GraphNode[] {
  const prod = new Set(prodAccountIds);
  return accounts.map((account) => ({
    id: `arn:aws:iam::${account.accountId}:root`,
    label: 'AwsAccount',
    observedAt,
    properties: {
      id: account.accountId,
      arn: `arn:aws:iam::${account.accountId}:root`,
      account_id: account.accountId,
      name: account.name,
      state: account.state,
      parent_id: account.parentId,
      // Unset when no prod accounts are configured, so no account reads as non-prod.
      is_prod: prod.size > 0 ? prod.has(account.accountId) : undefined,
      inventory_observed_at: observedAt,
      collection_scope: 'organization-inventory',
      collection_run_id: runId,
      active: true,
    },
  }));
}

export function createHandler(
  client: OrganizationsReader,
  writeGraph: GraphWriter = invokeGraphWriter,
  environment: NodeJS.ProcessEnv = process.env
) {
  return async (): Promise<{
    workItems: WorkItem[];
    accountCount: number;
    activeAccountCount: number;
  }> => {
    const config = parseCollectionConfig(environment);
    const accounts = await discoverAccounts(client, config, { nameListed: true });
    const workItems = buildWorkItems(accounts, config.regions);
    const discovered = new Set(accounts.map((account) => account.accountId));
    const unknownProd = config.prodAccountIds.filter((id) => !discovered.has(id));
    if (unknownProd.length > 0) {
      logger.warn('PROD_ACCOUNT_IDS lists accounts that are not collected', {
        accountIds: unknownProd,
      });
    }
    const observedAt = new Date().toISOString();
    const runId = randomUUID();

    await writeGraph({
      nodes: accountNodes(accounts, observedAt, runId, config.prodAccountIds),
      edges: [],
      observedAt,
      reconcile: { scope: 'organization-inventory', runId, observedAt },
    });
    logger.info('Organization inventory complete', {
      accountCount: accounts.length,
      activeAccountCount: workItems.length / config.regions.length,
      workItemCount: workItems.length,
    });

    return {
      workItems,
      accountCount: accounts.length,
      activeAccountCount: workItems.length / config.regions.length,
    };
  };
}

export const handler = createHandler(new OrganizationsClient({ maxAttempts: 3 }));
