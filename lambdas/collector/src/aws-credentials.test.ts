import { getTargetCredentials } from '../../shared/aws-credentials';

describe('getTargetCredentials', () => {
  it('uses ambient credentials in the home account', async () => {
    const send = jest.fn();

    await expect(
      getTargetCredentials({
        accountId: '111122223333',
        homeAccountId: '111122223333',
        region: 'us-west-2',
        client: { send },
      })
    ).resolves.toBeUndefined();
    expect(send).not.toHaveBeenCalled();
  });

  it('requires a controlled external ID for member accounts', async () => {
    await expect(
      getTargetCredentials({
        accountId: '444455556666',
        homeAccountId: '111122223333',
        externalId: '',
        region: 'us-west-2',
        client: { send: jest.fn() },
      })
    ).rejects.toThrow('COLLECTOR_EXTERNAL_ID must be at least 16 characters');
  });

  it('rejects weak external IDs', async () => {
    await expect(
      getTargetCredentials({
        accountId: '444455556666',
        homeAccountId: '111122223333',
        externalId: 'short',
        region: 'us-west-2',
        client: { send: jest.fn() },
      })
    ).rejects.toThrow('COLLECTOR_EXTERNAL_ID must be at least 16 characters');
  });

  it('requires the home account to prevent accidental self-assumption', async () => {
    await expect(
      getTargetCredentials({
        accountId: '111122223333',
        homeAccountId: '',
        externalId: 'controlled-external-id',
        region: 'us-west-2',
        client: { send: jest.fn() },
      })
    ).rejects.toThrow('HOME_ACCOUNT_ID is required');
  });

  it('assumes only the configured member role', async () => {
    const send = jest.fn().mockResolvedValue({
      Credentials: {
        AccessKeyId: 'access-key',
        SecretAccessKey: 'secret-key',
        SessionToken: 'session-token',
      },
    });

    await expect(
      getTargetCredentials({
        accountId: '444455556666',
        homeAccountId: '111122223333',
        externalId: 'controlled-external-id',
        roleName: 'KhalifaMemberRole',
        region: 'us-west-2',
        client: { send },
      })
    ).resolves.toEqual({
      accessKeyId: 'access-key',
      secretAccessKey: 'secret-key',
      sessionToken: 'session-token',
    });

    expect(send.mock.calls[0][0].input).toEqual({
      RoleArn: 'arn:aws:iam::444455556666:role/KhalifaMemberRole',
      RoleSessionName: expect.stringMatching(/^KhalifaCollector-/),
      DurationSeconds: 3600,
      ExternalId: 'controlled-external-id',
    });
  });
});
