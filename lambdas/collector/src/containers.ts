import { ECRClient, DescribeRepositoriesCommand, ListImagesCommand } from '@aws-sdk/client-ecr';
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

  const reposResponse = await client.send(new DescribeRepositoriesCommand({}));
  for (const repo of reposResponse.repositories || []) {
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

    try {
      const imagesResponse = await client.send(
        new ListImagesCommand({ repositoryName: repo.repositoryName, maxResults: 50 })
      );
      for (const image of imagesResponse.imageIds || []) {
        if (!image.imageDigest) continue;
        const imageArn = `${repo.repositoryArn}@${image.imageDigest}`;

        const seen = new Set(nodes.map((n) => n.id));
        if (seen.has(imageArn)) continue;

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
    } catch (e) {}
  }

  return { nodes, edges };
}
