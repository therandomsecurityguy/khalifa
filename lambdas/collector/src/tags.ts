import {
  ResourceGroupsTaggingAPIClient,
  GetResourcesCommand,
} from '@aws-sdk/client-resource-groups-tagging-api';
import { mapBounded } from '../../shared/concurrency';

const TAGGING_PAGE_SIZE = 100;
// Tag lookups are independent per ARN chunk; a few in flight keeps a large
// account from serializing hundreds of GetResources calls.
const TAGGING_CHUNK_CONCURRENCY = 4;

export type TagMap = Record<string, string>;

// The Resource Groups Tagging API rejects a whole GetResources call when any
// ARN is not a taggable resource: a resource segment without a type delimiter
// (IAM `:root`, `:password-policy`), an account that is not 12 digits (AWS-managed
// policies), or a service it does not know (Khalifa synthetic vertices). S3 bucket
// ARNs are the one delimiter-less form it accepts.
const TAGGABLE_ARN = /^arn:[^:]+:([^:]+):[^:]*:(?:\d{12})?:(.+)$/;

export function isTaggableArn(arn: string): boolean {
  const match = TAGGABLE_ARN.exec(arn);
  if (!match) return false;
  const [, service, resource] = match;
  if (service === 'khalifa') return false;
  // Image digests (repository/name@sha256:...) carry no tags of their own, and
  // with 400k of them the lookups throttled and failed the whole tags stage.
  if (service === 'ecr' && resource.includes('@')) return false;
  return service === 's3' || /[/:]/.test(resource);
}

export const PROP_ALIASES: Record<string, string[]> = {
  env: ['env', 'environment'],
  data_classification: ['data_classification', 'data-classification'],
  crown_jewel: ['crown_jewel', 'crown-jewel', 'crownJewel'],
  owner: ['owner', 'team', 'owning-team', 'owning_team'],
  business_unit: ['business_unit', 'business-unit', 'businessUnit'],
  canary: ['canary'],
};

// Tag keys are matched without regard to case (Env, ENVIRONMENT), and the
// usual spellings of an environment fold into the three that scoring knows.
const ENV_VALUES: Record<string, string> = {
  prod: 'prod',
  prd: 'prod',
  production: 'prod',
  staging: 'staging',
  stage: 'staging',
  stg: 'staging',
  dev: 'dev',
  development: 'dev',
};

export async function fetchTagsForArns(
  client: ResourceGroupsTaggingAPIClient,
  arns: string[],
  options: { concurrency?: number } = {}
): Promise<Map<string, TagMap>> {
  const tagMap = new Map<string, TagMap>();
  if (arns.length === 0) return tagMap;

  await mapBounded(
    chunk(arns, TAGGING_PAGE_SIZE),
    options.concurrency ?? TAGGING_CHUNK_CONCURRENCY,
    async (arnBatch) => {
      // GetResources pages when a resource carries more tags than TagsPerPage
      // (default 50). Ignoring PaginationToken silently dropped those tags,
      // which changes data_classification / crown_jewel and therefore risk
      // scoring, so always drain the pages for a chunk.
      let paginationToken: string | undefined;
      do {
        const response = await client.send(
          new GetResourcesCommand({
            ResourceARNList: arnBatch,
            ...(paginationToken ? { PaginationToken: paginationToken } : {}),
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
            // A resource's tags can span several pages, so merge rather than
            // overwrite: page two carries a different slice of the same tag set.
            const existing = tagMap.get(rm.ResourceARN);
            tagMap.set(rm.ResourceARN, existing ? { ...existing, ...tags } : tags);
          }
        }

        paginationToken = response.PaginationToken;
      } while (paginationToken);
    }
  );

  return tagMap;
}

export function extractCommonProperties(
  tags: TagMap | undefined
): Record<string, string | boolean> {
  const props: Record<string, string | boolean> = {};
  if (!tags) return props;

  const byKey = new Map(
    Object.entries(tags).map(([key, value]) => [key.trim().toLowerCase(), value])
  );
  for (const [prop, aliases] of Object.entries(PROP_ALIASES)) {
    for (const alias of aliases) {
      const value = byKey.get(alias.toLowerCase());
      if (value !== undefined) {
        props[prop] = value.trim().toLowerCase();
        break;
      }
    }
  }

  const env = props.env;
  if (typeof env === 'string') props.env = ENV_VALUES[env] ?? env;

  const crown = props.crown_jewel;
  if (typeof crown === 'string') {
    props.crown_jewel = crown === 'true' || crown === 'yes' || crown === '1';
  }

  const canary = props.canary;
  if (typeof canary === 'string') {
    props.canary = canary === 'true' || canary === 'yes' || canary === '1';
  }

  return props;
}

// Tag-derived keys a resource no longer carries, to clear from its vertex. Only
// after a complete tag lookup: a failed one would otherwise wipe every
// resource's env and crown_jewel. Keys the resource's own collector sets (an S3
// bucket's data_classification) stay.
export function staleTagProperties(
  arn: string,
  tagProps: Record<string, unknown>,
  nodeProps: Record<string, unknown>,
  tagsCollected: boolean
): string[] {
  if (!tagsCollected || !isTaggableArn(arn)) return [];
  return Object.keys(PROP_ALIASES).filter(
    (key) =>
      tagProps[key] === undefined && (nodeProps[key] === undefined || nodeProps[key] === null)
  );
}

export function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}
