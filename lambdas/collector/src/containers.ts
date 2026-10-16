import { ECRClient, DescribeRepositoriesCommand, ListImagesCommand } from '@aws-sdk/client-ecr';
import { collectPaginated } from '../../shared/pagination';
import type { GraphNode, GraphEdge } from '../../shared/types';
import type { TagMap } from './tags';
import { extractCommonProperties } from './tags';

export async function collectContainerImages(
  client: ECRClient,
  accountId: string,
  region: string,
  tagsByArn: Map<string, TagMap>
): Promise<{ nodes: GraphNode[]; edges: GraphEdge[] }> {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seenImages = new Set<string>();

  const repositories = await collectPaginated(
    (token) => client.send(new DescribeRepositoriesCommand({ nextToken: token, maxResults: 100 })),
    (page) => page.repositories,
    (page) => page.nextToken
  );
  for (const repo of repositories) {
    if (!repo.repositoryArn) continue;

    const tags = tagsByArn.get(repo.repositoryArn);
    const tagProps = extractCommonProperties(tags);

    nodes.push({
      id: repo.repositoryArn,
      label: 'EcrRepository',
      properties: {
        id: repo.repositoryName,
        arn: repo.repositoryArn,
        account_id: accountId,
        name: repo.repositoryName,
        uri: repo.repositoryUri,
        created_at: repo.createdAt?.toISOString(),
        ...tagProps,
      },
    });

    const images = await collectPaginated(
      (token) =>
        client.send(
          new ListImagesCommand({
            repositoryName: repo.repositoryName,
            maxResults: 100,
            nextToken: token,
          })
        ),
      (page) => page.imageIds,
      (page) => page.nextToken
    );
    for (const image of images) {
      if (!image.imageDigest) continue;
      const imageArn = `${repo.repositoryArn}@${image.imageDigest}`;

      if (seenImages.has(imageArn)) continue;
      seenImages.add(imageArn);

      nodes.push({
        id: imageArn,
        label: 'ContainerImage',
        properties: {
          id: image.imageDigest,
          arn: imageArn,
          account_id: accountId,
          repository: repo.repositoryName,
          digest: image.imageDigest,
          tag: image.imageTag,
        },
      });

      edges.push({
        from: imageArn,
        to: repo.repositoryArn,
        label: 'BELONGS_TO',
      });
    }
  }

  return { nodes, edges };
}
