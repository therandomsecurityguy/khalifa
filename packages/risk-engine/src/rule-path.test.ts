import { extractRulePath } from './rule-path';

const T_ID = { elementName: 'id' };
const T_LABEL = { elementName: 'label' };

// One element as the gremlin driver deserializes `valueMap(true, …)`: T.id and
// T.label enums as keys, and every property wrapped in a one-element list.
function element(
  id: string,
  label: string,
  props: Record<string, unknown> = {}
): Map<unknown, unknown> {
  const entry = new Map<unknown, unknown>([
    [T_ID, id],
    [T_LABEL, label],
  ]);
  for (const [key, value] of Object.entries(props)) entry.set(key, [value]);
  return entry;
}

describe('extractRulePath', () => {
  it('splits an alternating vertex-edge-vertex result', () => {
    const path = extractRulePath([
      element('ec2', 'Ec2Instance', { is_internet_exposed: true }),
      element('edge-1', 'HAS_IAM_ROLE'),
      element('role', 'IamRole', { is_admin: true }),
    ]);
    expect(path.vertices.map((v) => v.id)).toEqual(['ec2', 'role']);
    expect(path.edges.map((e) => e.label)).toEqual(['HAS_IAM_ROLE']);
    expect(path.vertices[0].properties.is_internet_exposed).toBe(true);
  });

  it('treats an even element count as vertices only', () => {
    const path = extractRulePath([element('a', 'Ec2Instance'), element('b', 'IamRole')]);
    expect(path.vertices.map((v) => v.id)).toEqual(['a', 'b']);
    expect(path.edges).toEqual([]);
  });

  it('accepts a single vertex and the {objects} wrapper', () => {
    const single = extractRulePath([element('a', 'Secret')]);
    expect(single.vertices.map((v) => v.id)).toEqual(['a']);

    const wrapped = extractRulePath({
      objects: [element('a', 'Secret'), element('e', 'GRANTS'), element('b', 'S3Bucket')],
    });
    expect(wrapped.vertices.map((v) => v.id)).toEqual(['a', 'b']);
    expect(wrapped.edges.map((e) => e.id)).toEqual(['e']);
  });

  it('accepts flat plain objects and empty results', () => {
    // Plain-object elements carry properties as top-level keys, like the Map.
    const path = extractRulePath([
      { id: 'x', label: 'Ec2Instance', name: ['front'] },
      { id: 'e', label: 'HAS_CVE' },
      { id: 'cve', label: 'Vulnerability', cvss_base_score: [9.8] },
    ]);
    expect(path.vertices.map((v) => v.id)).toEqual(['x', 'cve']);
    expect(path.vertices[0].properties.name).toBe('front');
    expect(path.vertices[1].properties.cvss_base_score).toBe(9.8);
    expect(extractRulePath(undefined)).toEqual({ vertices: [], edges: [] });
    expect(extractRulePath(null)).toEqual({ vertices: [], edges: [] });
  });
});
