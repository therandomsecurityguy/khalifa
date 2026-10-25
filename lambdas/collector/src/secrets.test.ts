import { collectSecrets } from '../index';

const account = '111122223333';
const open = `arn:aws:secretsmanager:us-west-2:${account}:secret:app/open-AbCdEf`;
const denied = `arn:aws:secretsmanager:us-west-2:${account}:secret:app/denied-GhIjKl`;

function denial(): Error {
  const error = new Error('explicit deny in a resource-based policy');
  error.name = 'AccessDeniedException';
  return error;
}

function clients(onCall: (command: string, secretId: string) => unknown) {
  const secrets = {
    send: jest.fn(async (command: { constructor: { name: string }; input: any }) => {
      if (command.constructor.name === 'ListSecretsCommand') {
        return {
          SecretList: [
            { ARN: open, Name: 'app/open' },
            { ARN: denied, Name: 'app/denied', RotationEnabled: true, KmsKeyId: 'key-1' },
          ],
        };
      }
      return onCall(command.constructor.name, command.input.SecretId);
    }),
  };
  const ssm = { send: jest.fn(async () => ({ Parameters: [] })) };
  return [secrets as any, ssm as any] as const;
}

const secretNode = (nodes: { id: string; properties: Record<string, unknown> }[], id: string) =>
  nodes.find((node) => node.id === id)?.properties;

describe('collectSecrets', () => {
  it('records a secret whose DescribeSecret is denied, from its list entry', async () => {
    const [secrets, ssm] = clients((command, id) => {
      if (id === denied) throw denial();
      return command === 'DescribeSecretCommand' ? { ARN: open } : {};
    });

    const { nodes } = await collectSecrets(secrets, ssm, account, 'us-west-2');

    expect(secretNode(nodes, denied)).toMatchObject({
      collection_restricted: true,
      rotation_enabled: true,
      kms_key_id: 'key-1',
    });
    expect(secretNode(nodes, open)).toMatchObject({ collection_restricted: false });
    // No resource-policy read is attempted for the denied secret.
    expect(
      secrets.send.mock.calls.filter(
        ([c]: any) =>
          c.constructor.name === 'GetResourcePolicyCommand' && c.input.SecretId === denied
      )
    ).toEqual([]);
  });

  it('records a secret whose resource policy read is denied', async () => {
    const [secrets, ssm] = clients((command, id) => {
      if (command === 'GetResourcePolicyCommand' && id === denied) throw denial();
      return command === 'DescribeSecretCommand' ? { ARN: id } : {};
    });

    const { nodes } = await collectSecrets(secrets, ssm, account, 'us-west-2');

    expect(secretNode(nodes, denied)).toMatchObject({ collection_restricted: true });
  });

  it('still fails the stage on any other error', async () => {
    const [secrets, ssm] = clients(() => {
      const error = new Error('Rate exceeded');
      error.name = 'ThrottlingException';
      throw error;
    });

    await expect(collectSecrets(secrets, ssm, account, 'us-west-2')).rejects.toThrow(
      'Secrets Manager collection'
    );
  });

  it('records rotation and access ages from DescribeSecret', async () => {
    const now = new Date('2026-10-22T12:00:00.000Z');
    const [secrets, ssm] = clients((command, id) =>
      command === 'DescribeSecretCommand'
        ? {
            ARN: id,
            CreatedDate: new Date('2026-01-01T00:00:00.000Z'),
            LastAccessedDate: new Date('2026-10-20T00:00:00.000Z'),
          }
        : {}
    );

    const { nodes } = await collectSecrets(secrets, ssm, account, 'us-west-2', now);

    expect(secretNode(nodes, open)).toMatchObject({
      created_at: '2026-01-01T00:00:00.000Z',
      last_accessed: '2026-10-20T00:00:00.000Z',
      days_since_rotation: 294,
      days_since_access: 2,
    });
  });

  it('builds parameter ARNs with one slash before the name, as AWS does', async () => {
    const [secrets] = clients(() => ({}));
    const ssm = {
      send: jest.fn(async () => ({
        Parameters: [
          { Name: '/db/password', Type: 'SecureString' },
          { Name: 'db-password', Type: 'String' },
          {
            Name: 'shared',
            Type: 'String',
            ARN: 'arn:aws:ssm:us-west-2:111122223333:parameter/shared',
          },
        ],
      })),
    };

    const { nodes } = await collectSecrets(secrets, ssm as any, account, 'us-west-2');

    expect(nodes.filter((node) => node.label === 'Parameter').map((node) => node.id)).toEqual([
      'arn:aws:ssm:us-west-2:111122223333:parameter/db/password',
      'arn:aws:ssm:us-west-2:111122223333:parameter/db-password',
      'arn:aws:ssm:us-west-2:111122223333:parameter/shared',
    ]);
  });
});
