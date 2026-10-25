import type { GraphVertex } from '@/types';
import { groupFindings } from './finding-groups';

const INSPECTOR = 'arn:aws:securityhub:us-west-2::product/aws/inspector';

function finding(id: string, properties: Record<string, unknown>): GraphVertex {
  return { id, label: 'SecurityHubFinding', properties };
}

function group(vertices: GraphVertex[], extraIds: string[] = []) {
  const ids = [...vertices.map((v) => v.id), ...extraIds];
  return groupFindings(
    ids.map((resourceId) => ({ resourceId, resourceType: 'SecurityHubFinding' })),
    new Map(vertices.map((v) => [v.id, v]))
  );
}

describe('groupFindings', () => {
  it('groups Inspector findings by package and names each by its CVE', () => {
    const groups = group([
      finding('f1', {
        title: 'CVE-2026-1 - linux-image-aws, linux-image-aws',
        severity: 'HIGH',
        product_arn: INSPECTOR,
      }),
      finding('f2', {
        title: 'CVE-2026-2 - linux-image-aws',
        severity: 'CRITICAL',
        product_arn: INSPECTOR,
      }),
      finding('f3', { title: 'CVE-2026-3 - openssl', severity: 'HIGH', product_arn: INSPECTOR }),
    ]);
    expect(groups.map((g) => g.fix)).toEqual(['linux-image-aws', 'openssl']);
    expect(groups[0].items.map((i) => i.name)).toEqual(['CVE-2026-2', 'CVE-2026-1']);
    expect(groups[0].severities).toEqual([
      ['CRITICAL', 1],
      ['HIGH', 1],
    ]);
  });

  it('keeps the whole title for findings from other products', () => {
    const [only] = group([
      finding('f1', { title: 'EC2.8 - instances should use IMDSv2', severity: 'HIGH' }),
    ]);
    expect(only.fix).toBe('EC2.8 - instances should use IMDSv2');
    expect(only.items[0].name).toBe('EC2.8 - instances should use IMDSv2');
  });

  it('puts findings it could not load last, named by their id', () => {
    const groups = group(
      [finding('f1', { title: 'CVE-2026-1 - zlib', severity: 'LOW', product_arn: INSPECTOR })],
      ['arn:aws:securityhub:us-west-2:111122223333:finding/abc']
    );
    expect(groups.map((g) => g.fix)).toEqual(['zlib', 'Details unavailable']);
    expect(groups[1].items[0].name).toBe('abc');
  });
});
