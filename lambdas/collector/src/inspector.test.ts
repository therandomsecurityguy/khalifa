import type { Finding } from '@aws-sdk/client-inspector2';
import { collectInspectorFindings, findingResourceId, maxCvssBaseScore } from './inspector';

const account = '111122223333';
const region = 'us-west-2';

const ec2Arn = `arn:aws:ec2:${region}:${account}:instance/i-abc`;
const imageArn = `arn:aws:ecr:${region}:${account}:repository/app@sha256:deadbeef`;
const fnArn = `arn:aws:lambda:${region}:${account}:function:leaky`;

function finding(overrides: Partial<Finding>): Finding {
  return {
    findingArn: `arn:aws:inspector2:${region}:${account}:finding/1`,
    severity: 'CRITICAL',
    title: 'CVE-2026-1234 - openssl',
    exploitAvailable: 'NO',
    ...overrides,
  } as Finding;
}

function clientFor(pages: { findings?: Finding[]; nextToken?: string }[]): any {
  const send = jest.fn();
  for (const page of pages) send.mockResolvedValueOnce(page);
  return { send };
}

describe('findingResourceId', () => {
  it('reassembles the graph ids for instances, images and functions', () => {
    expect(
      findingResourceId(
        finding({
          resources: [
            { type: 'AWS_EC2_INSTANCE', id: 'i-abc', details: { awsEc2Instance: {} } } as any,
          ],
        }),
        account,
        region
      )
    ).toBe(ec2Arn);

    expect(
      findingResourceId(
        finding({
          resources: [
            {
              type: 'AWS_ECR_CONTAINER_IMAGE',
              id: 'registry/app',
              details: {
                awsEcrContainerImage: { repositoryName: 'app', imageHash: 'sha256:deadbeef' },
              },
            } as any,
          ],
        }),
        account,
        region
      )
    ).toBe(imageArn);

    expect(
      findingResourceId(
        finding({
          resources: [
            {
              type: 'AWS_LAMBDA_FUNCTION',
              id: 'leaky',
              details: { awsLambdaFunction: { functionName: 'leaky' } },
            } as any,
          ],
        }),
        account,
        region
      )
    ).toBe(fnArn);
  });

  it('is undefined without a resource or for an unmodelled type', () => {
    expect(findingResourceId(finding({}), account, region)).toBeUndefined();
    expect(
      findingResourceId(
        finding({ resources: [{ type: 'AWS_ECS_CONTAINER', id: 'task' } as any] }),
        account,
        region
      )
    ).toBeUndefined();
  });
});

describe('maxCvssBaseScore', () => {
  it('takes the highest CVSS base score and falls back to the inspector score', () => {
    expect(
      maxCvssBaseScore(
        finding({
          packageVulnerabilityDetails: {
            vulnerabilityId: 'CVE-2026-1234',
            cvss: [{ baseScore: 7.5 }, { baseScore: 9.8 }],
          } as any,
        })
      )
    ).toBe(9.8);
    expect(maxCvssBaseScore(finding({ inspectorScore: 8.1 }))).toBe(8.1);
    expect(maxCvssBaseScore(finding({}))).toBeUndefined();
  });
});

describe('collectInspectorFindings', () => {
  it('writes one Vulnerability vertex per finding and HAS_CVE from the resource', async () => {
    const client = clientFor([
      {
        findings: [
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/ec2',
            packageVulnerabilityDetails: {
              vulnerabilityId: 'CVE-2026-1234',
              cvss: [{ baseScore: 9.8 }],
              vulnerablePackages: [{ fixedInVersion: '3.0.1' }, { fixedInVersion: '3.0.1' }],
            } as any,
            exploitAvailable: 'YES',
            resources: [
              { type: 'AWS_EC2_INSTANCE', id: 'i-abc', details: { awsEc2Instance: {} } } as any,
            ],
          }),
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/image',
            severity: 'HIGH',
            resources: [
              {
                type: 'AWS_ECR_CONTAINER_IMAGE',
                id: 'app',
                details: {
                  awsEcrContainerImage: { repositoryName: 'app', imageHash: 'sha256:deadbeef' },
                },
              } as any,
            ],
          }),
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/lambda',
            resources: [
              {
                type: 'AWS_LAMBDA_FUNCTION',
                id: 'leaky',
                details: { awsLambdaFunction: { functionName: 'leaky' } },
              } as any,
            ],
          }),
        ],
      },
    ]);

    const result = await collectInspectorFindings(
      client,
      account,
      region,
      new Set([ec2Arn, imageArn, fnArn])
    );

    expect(result.notEnabled).toBe(false);
    expect(result.findings).toBe(3);
    expect(result.nodes).toHaveLength(3);
    expect(result.nodes.every((node) => node.label === 'Vulnerability')).toBe(true);
    expect(result.edges).toEqual([
      {
        from: ec2Arn,
        to: 'arn:aws:inspector2:us-west-2:111122223333:finding/ec2',
        label: 'HAS_CVE',
      },
      {
        from: imageArn,
        to: 'arn:aws:inspector2:us-west-2:111122223333:finding/image',
        label: 'HAS_CVE',
      },
      {
        from: fnArn,
        to: 'arn:aws:inspector2:us-west-2:111122223333:finding/lambda',
        label: 'HAS_CVE',
      },
    ]);

    const ec2 = result.nodes.find((node) => node.id.endsWith('/ec2'))!;
    expect(ec2.properties).toMatchObject({
      cve_id: 'CVE-2026-1234',
      severity: 'CRITICAL',
      cvss_base_score: 9.8,
      exploit_available: true,
      fixed_versions: '3.0.1',
      source: 'inspector',
    });
  });

  it('skips findings for resources the graph does not hold', async () => {
    const client = clientFor([
      {
        findings: [
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/unknown',
            resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-gone' } as any],
          }),
        ],
      },
    ]);
    const result = await collectInspectorFindings(client, account, region, new Set([ec2Arn]));
    expect(result.nodes).toEqual([]);
    expect(result.edges).toEqual([]);
    expect(result.findings).toBe(1);
  });

  it('follows the NextToken across pages', async () => {
    const client = clientFor([
      {
        findings: [
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/1',
            resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-abc' } as any],
          }),
        ],
        nextToken: 'page-2',
      },
      {
        findings: [
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/2',
            resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-abc' } as any],
          }),
        ],
      },
    ]);
    const result = await collectInspectorFindings(client, account, region, new Set([ec2Arn]));
    expect(result.nodes).toHaveLength(2);
    expect(client.send).toHaveBeenCalledTimes(2);
    expect(client.send.mock.calls[1][0].input.nextToken).toBe('page-2');
  });

  it('caps the findings and reports the truncation', async () => {
    const client = clientFor([
      {
        findings: [
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/1',
            resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-abc' } as any],
          }),
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/2',
            resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-abc' } as any],
          }),
          finding({
            findingArn: 'arn:aws:inspector2:us-west-2:111122223333:finding/3',
            resources: [{ type: 'AWS_EC2_INSTANCE', id: 'i-abc' } as any],
          }),
        ],
        nextToken: 'more',
      },
    ]);
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const result = await collectInspectorFindings(client, account, region, new Set([ec2Arn]), 2);
    warn.mockRestore();
    expect(result.findings).toBe(2);
    expect(result.truncated).toBe(true);
    expect(client.send).toHaveBeenCalledTimes(1);
  });

  it('reports Inspector as not enabled instead of failing the stage', async () => {
    const error = new Error('Inspector is not enabled');
    error.name = 'AccessDeniedException';
    const client = { send: jest.fn().mockRejectedValue(error) } as any;
    const result = await collectInspectorFindings(client, account, region, new Set([ec2Arn]));
    expect(result).toEqual({
      nodes: [],
      edges: [],
      findings: 0,
      truncated: false,
      notEnabled: true,
    });
  });

  it('rethrows other errors so the stage records them as failed', async () => {
    const client = {
      send: jest.fn().mockRejectedValue(new Error('InternalServerException')),
    } as any;
    await expect(
      collectInspectorFindings(client, account, region, new Set([ec2Arn]))
    ).rejects.toThrow('InternalServerException');
  });
});
