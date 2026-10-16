import { ResourceGroupsTaggingAPIClient } from '@aws-sdk/client-resource-groups-tagging-api';
import { extractCommonProperties, fetchTagsForArns, isTaggableArn, type TagMap } from './tags';

describe('isTaggableArn', () => {
  it('accepts resource ARNs the Tagging API can look up', () => {
    for (const arn of [
      'arn:aws:ec2:us-west-2:111122223333:vpc/vpc-0123456789abcdef0',
      'arn:aws:s3:::my-bucket',
      'arn:aws:secretsmanager:us-west-2:111122223333:secret:name-AbCdEf',
      'arn:aws:apigateway:us-west-2::/restapis/abc123',
      'arn:aws:iam::111122223333:role/service-role/lambda-role',
    ]) {
      expect(isTaggableArn(arn)).toBe(true);
    }
  });

  it('rejects synthetic and untaggable ARNs that fail the whole GetResources call', () => {
    for (const arn of [
      'arn:aws:iam::111122223333:root',
      'arn:aws:iam::111122223333:password-policy',
      'arn:aws:iam::aws:policy/ReadOnlyAccess',
      'arn:aws:khalifa:global:internet',
      'arn:aws:khalifa:external-account:999988887777',
      'arn:aws:khalifa:us-west-2:111122223333:collection-coverage/iam',
      '',
    ]) {
      expect(isTaggableArn(arn)).toBe(false);
    }
  });
});

describe('extractCommonProperties', () => {
  it('returns empty object when no tags provided', () => {
    expect(extractCommonProperties(undefined)).toEqual({});
    expect(extractCommonProperties({})).toEqual({});
  });

  it('extracts env from environment tag', () => {
    const tags: TagMap = { environment: 'production' };
    expect(extractCommonProperties(tags)).toEqual({ env: 'prod' });
  });

  it('matches tag keys in any case and folds environment spellings', () => {
    expect(extractCommonProperties({ Env: 'Prod' })).toEqual({ env: 'prod' });
    expect(extractCommonProperties({ ENVIRONMENT: ' PRD ' })).toEqual({ env: 'prod' });
    expect(extractCommonProperties({ Environment: 'Stage' })).toEqual({ env: 'staging' });
    expect(extractCommonProperties({ env: 'stg' })).toEqual({ env: 'staging' });
    expect(extractCommonProperties({ env: 'Development' })).toEqual({ env: 'dev' });
    expect(extractCommonProperties({ env: 'sandbox' })).toEqual({ env: 'sandbox' });
    expect(extractCommonProperties({ Owner: 'Platform', CrownJewel: 'yes' })).toEqual({
      owner: 'platform',
      crown_jewel: true,
    });
  });

  it('normalizes data_classification values', () => {
    const tags: TagMap = { 'data-classification': 'Restricted' };
    expect(extractCommonProperties(tags)).toEqual({ data_classification: 'restricted' });
  });

  it('converts crown_jewel string to boolean', () => {
    expect(extractCommonProperties({ crown_jewel: 'true' })).toEqual({ crown_jewel: true });
    expect(extractCommonProperties({ crown_jewel: 'yes' })).toEqual({ crown_jewel: true });
    expect(extractCommonProperties({ crown_jewel: 'false' })).toEqual({ crown_jewel: false });
    expect(extractCommonProperties({ crown_jewel: 'Production' })).toEqual({
      crown_jewel: false,
    });
  });

  it('extracts owner', () => {
    expect(extractCommonProperties({ owner: 'team-security' })).toEqual({
      owner: 'team-security',
    });
  });

  it('extracts business_unit', () => {
    expect(extractCommonProperties({ 'business-unit': 'retail' })).toEqual({
      business_unit: 'retail',
    });
  });

  it('converts canary tag to boolean', () => {
    expect(extractCommonProperties({ canary: 'true' })).toEqual({ canary: true });
    expect(extractCommonProperties({ canary: 'yes' })).toEqual({ canary: true });
    expect(extractCommonProperties({ canary: 'false' })).toEqual({ canary: false });
  });

  it('combines multiple props from one tag set', () => {
    const tags: TagMap = {
      environment: 'prod',
      owner: 'platform',
      'data-classification': 'internal',
    };
    expect(extractCommonProperties(tags)).toEqual({
      env: 'prod',
      data_classification: 'internal',
      owner: 'platform',
    });
  });

  it('splits ARN lookups into the API maximum without pagination parameters', async () => {
    const send = jest.fn().mockResolvedValue({ ResourceTagMappingList: [] });
    const client = { send } as unknown as ResourceGroupsTaggingAPIClient;

    await fetchTagsForArns(
      client,
      Array.from({ length: 101 }, (_, index) => `arn:aws:service:::resource/${index}`)
    );

    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0][0].input.ResourceARNList).toHaveLength(100);
    expect(send.mock.calls[0][0].input).not.toHaveProperty('PaginationToken');
    expect(send.mock.calls[1][0].input.ResourceARNList).toHaveLength(1);
  });

  it('drains every GetResources page for a chunk', async () => {
    // A resource with more tags than TagsPerPage pages the response; ignoring
    // PaginationToken silently dropped those tags, which changes
    // data_classification / crown_jewel and therefore risk scoring.
    const send = jest
      .fn()
      .mockResolvedValueOnce({
        ResourceTagMappingList: [
          { ResourceARN: 'arn:aws:s3:::paged', Tags: [{ Key: 'owner', Value: 'team-a' }] },
        ],
        PaginationToken: 'page-2',
      })
      .mockResolvedValueOnce({
        ResourceTagMappingList: [
          {
            ResourceARN: 'arn:aws:s3:::paged',
            Tags: [{ Key: 'data_classification', Value: 'secret' }],
          },
        ],
      });
    const client = { send } as unknown as ResourceGroupsTaggingAPIClient;

    const tags = await fetchTagsForArns(client, ['arn:aws:s3:::paged'], { concurrency: 1 });

    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1][0].input.PaginationToken).toBe('page-2');
    expect(tags.get('arn:aws:s3:::paged')).toEqual({
      owner: 'team-a',
      data_classification: 'secret',
    });
  });

  it('fetches every chunk when several are needed', async () => {
    const send = jest
      .fn()
      .mockImplementation(async (command: { input: { ResourceARNList: string[] } }) => ({
        ResourceTagMappingList: command.input.ResourceARNList.map((arn) => ({
          ResourceARN: arn,
          Tags: [{ Key: 'env', Value: 'prod' }],
        })),
      }));
    const client = { send } as unknown as ResourceGroupsTaggingAPIClient;

    const arns = Array.from({ length: 250 }, (_, index) => `arn:aws:s3:::bucket-${index}`);
    const tags = await fetchTagsForArns(client, arns, { concurrency: 3 });

    expect(send).toHaveBeenCalledTimes(3);
    expect(tags.size).toBe(250);
    expect(tags.get('arn:aws:s3:::bucket-249')).toEqual({ env: 'prod' });
  });
});
