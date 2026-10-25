import {
  ListAccountsCommand,
  ListAccountsForParentCommand,
  ListOrganizationalUnitsForParentCommand,
  type Account,
} from '@aws-sdk/client-organizations';
import {
  buildWorkItems,
  discoverAccounts,
  parseCollectionConfig,
  toInventoryAccount,
  type OrganizationsReader,
} from '../../shared/account-inventory';
import { createHandler } from '../index';

const reader = (send: jest.Mock) => ({ send }) as unknown as OrganizationsReader;
const config = (accountIds: string[], parentIds: string[] = []) => ({
  accountIds,
  parentIds,
  regions: ['us-west-2'],
  prodAccountIds: [],
});

describe('organization inventory', () => {
  it('requires an explicit target and validates regions', () => {
    expect(() => parseCollectionConfig({ COLLECTION_REGIONS: 'us-west-2' })).toThrow(
      'COLLECTION_ACCOUNT_IDS or COLLECTION_PARENT_IDS is required'
    );
    expect(() =>
      parseCollectionConfig({ COLLECTION_ACCOUNT_IDS: '111122223333', COLLECTION_REGIONS: 'west' })
    ).toThrow('COLLECTION_REGIONS contains invalid values');
  });

  it('deduplicates configured accounts, parents, and regions', () => {
    expect(
      parseCollectionConfig({
        COLLECTION_ACCOUNT_IDS: '111122223333,111122223333',
        COLLECTION_PARENT_IDS: 'ou-abcd1234-12345678,ou-abcd1234-12345678',
        COLLECTION_REGIONS: 'us-west-2,us-east-1,us-west-2',
      })
    ).toEqual({
      accountIds: ['111122223333'],
      parentIds: ['ou-abcd1234-12345678'],
      regions: ['us-west-2', 'us-east-1'],
      prodAccountIds: [],
    });
  });

  it('validates prod account IDs', () => {
    expect(() =>
      parseCollectionConfig({
        COLLECTION_ACCOUNT_IDS: '111122223333',
        COLLECTION_REGIONS: 'us-west-2',
        PROD_ACCOUNT_IDS: '111122223333,prod',
      })
    ).toThrow('PROD_ACCOUNT_IDS contains invalid values: prod');
  });

  it.each([
    ['111122223333', { '111122223333': true, '444455556666': false }],
    ['', { '111122223333': undefined, '444455556666': undefined }],
  ])('marks prod accounts from PROD_ACCOUNT_IDS=%j', async (prodAccountIds, expected) => {
    const writeGraph = jest.fn().mockResolvedValue(undefined);
    const send = jest.fn().mockResolvedValue({ Accounts: [] });
    await createHandler(reader(send), writeGraph, {
      COLLECTION_ACCOUNT_IDS: '111122223333,444455556666',
      COLLECTION_REGIONS: 'us-west-2',
      PROD_ACCOUNT_IDS: prodAccountIds,
    })();

    const nodes = writeGraph.mock.calls[0][0].nodes;
    expect(
      Object.fromEntries(
        nodes.map((node: any) => [node.properties.account_id, node.properties.is_prod])
      )
    ).toEqual(expected);
  });

  it('uses the current Organizations account state', () => {
    expect(toInventoryAccount({ Id: '111122223333', State: 'SUSPENDED' } as Account)).toEqual({
      accountId: '111122223333',
      name: undefined,
      state: 'SUSPENDED',
      parentId: undefined,
    });
  });

  it('names listed accounts from Organizations and changes nothing else', async () => {
    const send = jest.fn().mockResolvedValue({
      Accounts: [
        { Id: '111122223333', Name: 'prod-data', State: 'ACTIVE' },
        { Id: '555566667777', Name: 'old-sandbox', State: 'SUSPENDED' },
        { Id: '999988887777', Name: 'not-approved', State: 'ACTIVE' },
      ],
    });

    await expect(
      discoverAccounts(reader(send), config(['444455556666', '111122223333', '555566667777']), {
        nameListed: true,
      })
    ).resolves.toEqual([
      { accountId: '111122223333', name: 'prod-data', state: 'ACTIVE' },
      { accountId: '444455556666', state: 'ACTIVE' },
      { accountId: '555566667777', name: 'old-sandbox', state: 'ACTIVE' },
    ]);
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0][0]).toBeInstanceOf(ListAccountsCommand);
  });

  it('keeps collecting without names when the hub cannot list accounts', async () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const send = jest.fn().mockRejectedValue(new Error('AccessDeniedException'));

    await expect(
      discoverAccounts(reader(send), config(['111122223333']), { nameListed: true })
    ).resolves.toEqual([{ accountId: '111122223333', state: 'ACTIVE' }]);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it('does not list accounts when parents already cover the listed ids', async () => {
    const send = jest.fn((command: unknown) => {
      if (command instanceof ListAccountsForParentCommand) {
        return Promise.resolve({
          Accounts: [{ Id: '111122223333', Name: 'prod-data', State: 'ACTIVE' }],
        });
      }
      if (command instanceof ListOrganizationalUnitsForParentCommand) {
        return Promise.resolve({ OrganizationalUnits: [] });
      }
      return Promise.reject(new Error(`unexpected ${String(command)}`));
    });

    await expect(
      discoverAccounts(reader(send), config(['111122223333'], ['ou-abcd1234-12345678']), {
        nameListed: true,
      })
    ).resolves.toEqual([
      {
        accountId: '111122223333',
        name: 'prod-data',
        state: 'ACTIVE',
        parentId: 'ou-abcd1234-12345678',
      },
    ]);
    expect(send.mock.calls.some(([command]) => command instanceof ListAccountsCommand)).toBe(false);
  });

  it('creates work only for active accounts in approved regions', () => {
    expect(
      buildWorkItems(
        [
          { accountId: '111122223333', state: 'ACTIVE' },
          { accountId: '444455556666', state: 'PENDING_CLOSURE' },
        ],
        ['us-west-2', 'us-east-1']
      )
    ).toEqual([
      { accountId: '111122223333', region: 'us-west-2', collectGlobal: true },
      { accountId: '111122223333', region: 'us-east-1', collectGlobal: false },
    ]);
  });
});
