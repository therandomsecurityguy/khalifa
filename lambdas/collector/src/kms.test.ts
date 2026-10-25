import { collectKms } from '../index';

const account = '111122223333';
const arn = (id: string) => `arn:aws:kms:us-west-2:${account}:key/${id}`;

function denial(): Error {
  const error = new Error('not authorized by the key policy');
  error.name = 'AccessDeniedException';
  return error;
}

describe('collectKms', () => {
  it('records a key whose DescribeKey is denied as a restricted stub', async () => {
    const client = {
      send: jest.fn(async (command: { constructor: { name: string }; input: any }) => {
        const name = command.constructor.name;
        if (name === 'ListKeysCommand') {
          return {
            Keys: [
              { KeyId: 'open', KeyArn: arn('open') },
              { KeyId: 'locked', KeyArn: arn('locked') },
            ],
          };
        }
        if (command.input.KeyId === 'locked') throw denial();
        if (name === 'DescribeKeyCommand') {
          return {
            KeyMetadata: {
              KeyId: 'open',
              Arn: arn('open'),
              KeyManager: 'CUSTOMER',
              KeyState: 'Enabled',
            },
          };
        }
        return { KeyRotationEnabled: true };
      }),
    };

    const { nodes } = await collectKms(client as any, account);
    const props = (id: string) => nodes.find((n) => n.id === arn(id))?.properties;

    expect(props('locked')).toEqual({
      id: 'locked',
      arn: arn('locked'),
      account_id: account,
      collection_restricted: true,
    });
    expect(props('open')).toMatchObject({ rotation_enabled: true, collection_restricted: false });
  });
});
