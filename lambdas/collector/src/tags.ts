import { ResourceGroupsTaggingAPIClient, GetResourcesCommand } from '@aws-sdk/client-resource-groups-tagging-api';

const TAGGING_PAGE_SIZE = 100;

export type TagMap = Record<string, string>;

const SUPPORTED_KEYS = ['env', 'environment', 'data_classification', 'crown_jewel', 'owner', 'business_unit'];

export const PROP_ALIASES: Record<string, string[]> = {
  env: ['env', 'environment'],
  data_classification: ['data_classification', 'data-classification'],
  crown_jewel: ['crown_jewel', 'crown-jewel', 'crownJewel'],
  owner: ['owner', 'team', 'owning-team', 'owning_team'],
  business_unit: ['business_unit', 'business-unit', 'businessUnit'],
};

export async function fetchTagsForArns(
  client: ResourceGroupsTaggingAPIClient,
  arns: string[]
): Promise<Map<string, TagMap>> {
  const tagMap = new Map<string, TagMap>();
  if (arns.length === 0) return tagMap;

  let paginationToken: string | undefined;
  do {
    const response = await client.send(
      new GetResourcesCommand({
        ResourceARNList: arns,
        PaginationToken: paginationToken,
      })
    );

    for (const rm of response.ResourceTagMappingList || []) {
      const tags: TagMap = {};
      for (const t of rm.Tags || []) {
        if (t.Key && t.Value !== undefined) {
          tags[t.Key] = t.Value;
        }
      }
      if (rm.ResourceARN) {
        tagMap.set(rm.ResourceARN, tags);
      }
    }

    paginationToken = response.PaginationToken;
  } while (paginationToken);

  return tagMap;
}

export async function fetchAllTags(
  client: ResourceGroupsTaggingAPIClient,
  arnProvider: () => AsyncIterable<string[]>
): Promise<Map<string, TagMap>> {
  const result = new Map<string, TagMap>();
  for await (const batch of arnProvider()) {
    const partial = await fetchTagsForArns(client, batch);
    partial.forEach((v, k) => result.set(k, v));
  }
  return result;
}

export function extractCommonProperties(tags: TagMap | undefined): Record<string, string | boolean> {
  const props: Record<string, string | boolean> = {};
  if (!tags) return props;

  for (const [prop, aliases] of Object.entries(PROP_ALIASES)) {
    for (const alias of aliases) {
      const value = tags[alias];
      if (value !== undefined) {
        props[prop] = value.toLowerCase();
        break;
      }
    }
  }

  const crown = props.crown_jewel;
  if (typeof crown === 'string') {
    props.crown_jewel = crown === 'true' || crown === 'yes' || crown === '1';
  }

  return props;
}

export function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

export const TAG_BATCH_SIZE = TAGGING_PAGE_SIZE;