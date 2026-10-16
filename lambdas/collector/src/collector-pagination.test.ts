import { collectContainerImages } from './containers';
import { collectCrossAccountTrust, extractTrustAccountIds } from './cross-account';

describe('collector pagination', () => {
  it('decodes role trust policies', () => {
    const policy = encodeURIComponent(
      JSON.stringify({
        Statement: {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::444455556666:root' },
        },
      })
    );

    expect(extractTrustAccountIds(policy)).toEqual(['444455556666']);
  });

  it('reads every IAM role page', async () => {
    const send = jest.fn(async (command: { constructor: { name: string }; input: any }) => {
      if (command.constructor.name === 'ListRolesCommand') {
        if (command.input.Marker) return { Roles: [] };
        return {
          Roles: [
            {
              RoleName: 'CrossAccountRole',
              Arn: 'arn:aws:iam::111122223333:role/CrossAccountRole',
              AssumeRolePolicyDocument: JSON.stringify({
                Statement: {
                  Effect: 'Allow',
                  Principal: { AWS: 'arn:aws:iam::444455556666:root' },
                },
              }),
            },
          ],
          IsTruncated: true,
          Marker: 'next-role',
        };
      }
      if (command.constructor.name === 'ListAttachedRolePoliciesCommand') {
        return { AttachedPolicies: [{ PolicyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' }] };
      }
      throw new Error(`Unexpected command: ${command.constructor.name}`);
    });

    const result = await collectCrossAccountTrust(sendClient(send), '111122223333', new Map());

    expect(result.nodes.map((node) => node.label)).toEqual(['ExternalAccount', 'IamRole']);
    expect(
      send.mock.calls.filter(([command]) => command.constructor.name === 'ListRolesCommand')
    ).toHaveLength(2);
  });

  it('reads every ECR repository and image page', async () => {
    const send = jest.fn(async (command: { constructor: { name: string }; input: any }) => {
      if (command.constructor.name === 'DescribeRepositoriesCommand') {
        if (command.input.nextToken) return { repositories: [] };
        return {
          repositories: [
            {
              repositoryName: 'app',
              repositoryArn: 'arn:aws:ecr:us-west-2:111122223333:repository/app',
            },
          ],
          nextToken: 'next-repository',
        };
      }
      if (command.constructor.name === 'ListImagesCommand') {
        if (command.input.nextToken) return { imageIds: [{ imageDigest: 'sha256:two' }] };
        return { imageIds: [{ imageDigest: 'sha256:one' }], nextToken: 'next-image' };
      }
      throw new Error(`Unexpected command: ${command.constructor.name}`);
    });

    const result = await collectContainerImages(
      sendClient(send),
      '111122223333',
      'us-west-2',
      new Map()
    );

    expect(result.nodes.map((node) => node.label)).toEqual([
      'EcrRepository',
      'ContainerImage',
      'ContainerImage',
    ]);
  });
});

function sendClient(send: jest.Mock): any {
  return { send };
}
