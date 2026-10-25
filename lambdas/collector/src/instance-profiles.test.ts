import type { IAMClient } from '@aws-sdk/client-iam';
import { instanceRoleEdges, listInstanceProfileRoles } from './instance-profiles';

const ACCOUNT = '111122223333';
const INSTANCE = `arn:aws:ec2:us-west-2:${ACCOUNT}:instance/i-0abc`;

function iamClient(send: jest.Mock): IAMClient {
  return { send } as unknown as IAMClient;
}

function named(name: string): Error {
  const error = new Error(name);
  error.name = name;
  return error;
}

describe('listInstanceProfileRoles', () => {
  it('maps every profile on every page to its role names', async () => {
    const send = jest.fn(async (command: { input: { Marker?: string } }) =>
      command.input.Marker
        ? {
            InstanceProfiles: [
              {
                Arn: `arn:aws:iam::${ACCOUNT}:instance-profile/eks/eks-node-1a2b`,
                Roles: [{ RoleName: 'eks-node-role' }],
              },
            ],
          }
        : {
            InstanceProfiles: [
              {
                Arn: `arn:aws:iam::${ACCOUNT}:instance-profile/gpu-worker`,
                Roles: [{ RoleName: 'gpu-worker' }],
              },
              { Arn: `arn:aws:iam::${ACCOUNT}:instance-profile/empty`, Roles: [] },
            ],
            IsTruncated: true,
            Marker: 'next',
          }
    );

    const roles = await listInstanceProfileRoles(iamClient(send));

    expect(roles).toEqual(
      new Map([
        [`arn:aws:iam::${ACCOUNT}:instance-profile/gpu-worker`, ['gpu-worker']],
        [`arn:aws:iam::${ACCOUNT}:instance-profile/empty`, []],
        [`arn:aws:iam::${ACCOUNT}:instance-profile/eks/eks-node-1a2b`, ['eks-node-role']],
      ])
    );
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('returns undefined when the permission is not deployed yet', async () => {
    const send = jest.fn().mockRejectedValue(named('AccessDenied'));

    await expect(listInstanceProfileRoles(iamClient(send))).resolves.toBeUndefined();
  });

  it.each(['Throttling', 'ServiceFailure'])('rethrows %s', async (name) => {
    const send = jest.fn().mockRejectedValue(named(name));

    await expect(listInstanceProfileRoles(iamClient(send))).rejects.toThrow(name);
  });
});

describe('instanceRoleEdges', () => {
  it('points at the role vertex id collectIam writes, not the profile', () => {
    const profile = `arn:aws:iam::${ACCOUNT}:instance-profile/eks/eks-node-1a2b`;

    const edges = instanceRoleEdges(
      INSTANCE,
      profile,
      new Map([[profile, ['eks-node-role']]]),
      ACCOUNT
    );

    expect(edges).toEqual([
      { from: INSTANCE, to: `arn:aws:iam::${ACCOUNT}:role/eks-node-role`, label: 'HAS_IAM_ROLE' },
    ]);
  });

  it('writes nothing for an unknown profile or one without a role', () => {
    const profile = `arn:aws:iam::${ACCOUNT}:instance-profile/empty`;
    const roles = new Map([[profile, []]]);

    expect(instanceRoleEdges(INSTANCE, profile, roles, ACCOUNT)).toEqual([]);
    expect(instanceRoleEdges(INSTANCE, `${profile}-gone`, roles, ACCOUNT)).toEqual([]);
  });
});
