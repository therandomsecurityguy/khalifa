import {
  ListAccountsForParentCommand,
  ListOrganizationalUnitsForParentCommand,
} from '@aws-sdk/client-organizations';
import { discoverAccounts, type OrganizationsReader } from '../../shared/account-inventory';

describe('discoverAccounts', () => {
  it('uses an explicit account list without calling Organizations', async () => {
    const send = jest.fn(async () => {
      throw new Error('Unexpected command');
    });

    await expect(
      discoverAccounts(sendClient(send), {
        accountIds: ['444455556666', '111122223333'],
        parentIds: [],
        regions: ['us-west-2'],
        prodAccountIds: [],
      })
    ).resolves.toEqual([
      { accountId: '111122223333', state: 'ACTIVE' },
      { accountId: '444455556666', state: 'ACTIVE' },
    ]);
    expect(send).not.toHaveBeenCalled();
  });

  it('recursively paginates approved organization parents', async () => {
    const send = jest.fn(async (command) => {
      if (command instanceof ListAccountsForParentCommand) {
        if (command.input.ParentId === 'r-root' && !command.input.NextToken) {
          return {
            Accounts: [{ Id: '111122223333', State: 'ACTIVE' }],
            NextToken: 'accounts-page-2',
          };
        }
        if (command.input.ParentId === 'r-root') {
          return { Accounts: [{ Id: '444455556666', State: 'SUSPENDED' }] };
        }
        return { Accounts: [{ Id: '777788889999', State: 'ACTIVE' }] };
      }
      if (command instanceof ListOrganizationalUnitsForParentCommand) {
        return command.input.ParentId === 'r-root'
          ? { OrganizationalUnits: [{ Id: 'ou-abcd-12345678' }] }
          : { OrganizationalUnits: [] };
      }
      throw new Error('Unexpected command');
    });

    await expect(
      discoverAccounts(sendClient(send), {
        accountIds: ['111122223333', '999900001111'],
        parentIds: ['r-root'],
        regions: ['us-west-2'],
        prodAccountIds: [],
      })
    ).resolves.toEqual([
      { accountId: '111122223333', name: undefined, state: 'ACTIVE', parentId: 'r-root' },
      { accountId: '444455556666', name: undefined, state: 'SUSPENDED', parentId: 'r-root' },
      {
        accountId: '777788889999',
        name: undefined,
        state: 'ACTIVE',
        parentId: 'ou-abcd-12345678',
      },
      { accountId: '999900001111', state: 'ACTIVE' },
    ]);
    expect(send).toHaveBeenCalledTimes(5);
  });
});

function sendClient(send: jest.Mock): OrganizationsReader {
  return { send } as unknown as OrganizationsReader;
}
