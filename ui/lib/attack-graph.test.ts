import type { GraphEdge, GraphVertex } from '@/types';
import {
  AWS_MANAGED_ACCOUNT,
  INTERNET_ID,
  buildAttackGraph,
  chokePoints,
  edgeLabel,
  walkedBackwards,
  groupSiblings,
  layoutAttackGraph,
  describePaths,
  riskFlags,
} from './attack-graph';

const v = (id: string, label: string, properties: Record<string, unknown> = {}): GraphVertex => ({
  id,
  label,
  properties,
});
const e = (from: GraphVertex, to: GraphVertex, label: string): GraphEdge => ({
  id: `${from.id}>${to.id}`,
  label,
  from: from.id,
  to: to.id,
});

const ec2 = v('arn:aws:ec2:us-west-2:111122223333:instance/i-1', 'Ec2Instance', {
  account_id: '111122223333',
  is_internet_exposed: true,
});
const role = v('arn:aws:iam::111122223333:role/app', 'IamRole', { account_id: '111122223333' });
const policy = v('arn:aws:iam::111122223333:policy/s3', 'IamPolicyDocument', {
  account_id: '111122223333',
  name: 'app-s3-access',
});
const statement = v('arn:aws:iam::111122223333:policy/s3/0', 'IamPolicyStatement', {
  account_id: '111122223333',
  name: 'AllowS3',
  actions: '["s3:GetObject","s3:PutObject"]',
  has_wildcard_resource: true,
});
const bucket = v('arn:aws:s3:::data', 'S3Bucket', {
  account_id: '444455556666',
  data_classification: 'restricted',
});

describe('riskFlags', () => {
  it('flags only properties the collector records', () => {
    expect(riskFlags(ec2)).toEqual([{ level: 'risk', text: 'Internet exposed' }]);
    expect(riskFlags(v('b', 'S3Bucket', { data_classification: 'public' }))).toEqual([]);
    expect(riskFlags(v('u', 'IamUser', { password_enabled: false, mfa_enabled: false }))).toEqual(
      []
    );
  });
});

describe('buildAttackGraph', () => {
  const fullPath = {
    nodes: [ec2, role, policy, statement, bucket],
    edges: [
      e(ec2, role, 'HAS_IAM_ROLE'),
      e(role, policy, 'ATTACHED_TO'),
      e(policy, statement, 'CONTAINS'),
      e(statement, bucket, 'GRANTS'),
    ],
  };

  it('collapses role → policy → statement → resource into one Allows hop', () => {
    const graph = buildAttackGraph([fullPath]);
    expect(graph.nodes.map((n) => n.vertex.id)).toEqual([ec2.id, role.id, bucket.id]);
    expect(graph.links[1]).toEqual({
      from: role.id,
      to: bucket.id,
      label: 'Allows s3:GetObject +1',
      crossAccount: true,
      kind: 'access',
      via: 'app-s3-access',
    });
    const roleNode = graph.nodes[1];
    expect(roleNode.permissions).toEqual([
      {
        policy: 'app-s3-access',
        statement: 'AllowS3',
        effect: 'Allow',
        actions: 's3:GetObject, s3:PutObject',
        notActions: undefined,
        resources: undefined,
        conditions: undefined,
      },
    ]);
    expect(roleNode.risks).toContainEqual({ level: 'risk', text: 'Wildcard resource' });
  });

  it('folds a path that ends at a statement into its principal', () => {
    const graph = buildAttackGraph([
      {
        nodes: [role, policy, statement],
        edges: [e(role, policy, 'ATTACHED_TO'), e(policy, statement, 'CONTAINS')],
      },
    ]);
    expect(graph.nodes.map((n) => n.vertex.id)).toEqual([role.id]);
    expect(graph.links).toEqual([]);
    expect(graph.nodes[0].permissions).toHaveLength(1);
  });

  it('prepends the internet only for an internet entry', () => {
    const graph = buildAttackGraph([fullPath], { [ec2.id]: { kind: 'internet' } });
    expect(graph.nodes.find((n) => n.vertex.id === INTERNET_ID)?.account).toBeNull();
    expect(graph.links).toContainEqual({
      from: INTERNET_ID,
      to: ec2.id,
      label: 'Exposes',
      crossAccount: false,
      kind: 'access',
      via: undefined,
    });
    expect(buildAttackGraph([fullPath]).nodes.some((n) => n.vertex.id === INTERNET_ID)).toBe(false);
  });

  it('starts a trust path at the outside account across accounts', () => {
    const external = v('arn:aws:khalifa:external-account:999988887777', 'ExternalAccount', {
      account_id: '999988887777',
    });
    const graph = buildAttackGraph([{ nodes: [role], edges: [] }], {
      [role.id]: { kind: 'trust', principals: [external] },
    });
    expect(graph.nodes.find((n) => n.vertex.id === external.id)?.external).toBe(true);
    expect(graph.links).toContainEqual({
      from: external.id,
      to: role.id,
      label: 'Can assume',
      crossAccount: true,
      kind: 'access',
      via: undefined,
    });
  });

  it('merges shared hops across paths once', () => {
    const other = v('arn:aws:s3:::other', 'S3Bucket', { account_id: '444455556666' });
    const second = {
      nodes: [ec2, role, policy, statement, other],
      edges: [...fullPath.edges.slice(0, 3), e(statement, other, 'GRANTS')],
    };
    const graph = buildAttackGraph([fullPath, second]);
    expect(graph.pathCount).toBe(2);
    expect(graph.nodes).toHaveLength(4);
    expect(graph.links.filter((l) => l.from === ec2.id)).toHaveLength(1);
  });

  it('reads the account from the ARN when the vertex has no account_id', () => {
    const graph = buildAttackGraph([
      { nodes: [v('arn:aws:iam::222233334444:role/x', 'IamRole')], edges: [] },
    ]);
    expect(graph.nodes[0].account).toBe('222233334444');
  });

  it('formats edge labels as plain phrases', () => {
    expect(edgeLabel('HAS_IAM_ROLE')).toBe('Has IAM role');
    expect(edgeLabel('ATTACHED_TO')).toBe('Attached to');
  });
});

describe('edge direction', () => {
  const user = v('arn:aws:iam::111122223333:user/svc', 'IamUser', { account_id: '111122223333' });
  const key = v('arn:aws:iam::111122223333:user/svc/access-key/AKIA1', 'AccessKey', {
    account_id: '111122223333',
  });

  it('reads a step against the edge with its inverse phrase', () => {
    // RULE-013 walks key -> user; the issue path keeps that order.
    const backwards = buildAttackGraph([
      { nodes: [key, user], edges: [e(key, user, 'HAS_ACCESS_KEY')] },
    ]);
    expect(backwards.links[0].label).toBe('Access key of');
    const forwards = buildAttackGraph([
      { nodes: [user, key], edges: [e(user, key, 'HAS_ACCESS_KEY')] },
    ]);
    expect(forwards.links[0].label).toBe('Has access key');
  });

  it('orders CONTAINS by what holds what', () => {
    expect(walkedBackwards('CONTAINS', statement, policy)).toBe(true);
    expect(walkedBackwards('CONTAINS', policy, statement)).toBe(false);
    expect(walkedBackwards('CONNECTED', key, user)).toBe(false);
  });
});

describe('layoutAttackGraph', () => {
  it('orders bands internet, outside accounts, then collected accounts, and columns by hop', () => {
    const external = v('arn:aws:khalifa:external-account:999988887777', 'ExternalAccount', {
      account_id: '999988887777',
    });
    const graph = buildAttackGraph(
      [
        { nodes: [ec2, role], edges: [e(ec2, role, 'HAS_IAM_ROLE')] },
        { nodes: [role], edges: [] },
      ],
      { [ec2.id]: { kind: 'internet' }, [role.id]: { kind: 'trust', principals: [external] } }
    );
    const layout = layoutAttackGraph(graph);
    expect(layout.bands.map((b) => b.account)).toEqual([null, '999988887777', '111122223333']);
    const x = (id: string) => layout.positions.get(id)!.x;
    expect(x(INTERNET_ID)).toBeLessThan(x(ec2.id));
    expect(x(ec2.id)).toBeLessThan(x(role.id));

    // Given a wider canvas, lanes reach its edge and columns spread, up to a cap.
    const wide = layoutAttackGraph(graph, 2000);
    expect(wide.width).toBe(2000);
    expect(wide.positions.get(role.id)!.x).toBeGreaterThan(x(role.id));
    const huge = layoutAttackGraph(graph, 10000);
    expect(huge.width).toBe(10000);
    expect(huge.positions.get(role.id)!.x - huge.positions.get(ec2.id)!.x).toBe(520);
  });
});

describe('AWS-managed policies', () => {
  // RULE-016's path order: statement, document, policy, then the principal.
  it('sit in no account and never make a hop cross-account', () => {
    const configRole = v('arn:aws:iam::111122223333:role/AWSServiceRoleForConfig', 'IamRole', {
      account_id: '111122223333',
    });
    // Shared across accounts; account_id is whichever account wrote it last.
    const stale = { account_id: '522814703025' };
    const awsPolicy = v('arn:aws:iam::aws:policy/AWSConfigServiceRolePolicy', 'IamPolicy', stale);
    const awsDoc = v(`${awsPolicy.id}/version/v96`, 'IamPolicyDocument', stale);
    const awsStatement = v(`${awsDoc.id}/statement/2`, 'IamPolicyStatement', stale);
    const graph = buildAttackGraph([
      {
        nodes: [awsStatement, awsDoc, awsPolicy, configRole],
        edges: [
          e(awsDoc, awsStatement, 'CONTAINS'),
          e(awsPolicy, awsDoc, 'CONTAINS'),
          e(configRole, awsPolicy, 'ATTACHED_TO'),
        ],
      },
    ]);
    const managed = graph.nodes.filter((n) => n.vertex.id.includes(':iam::aws:'));
    expect(managed.length).toBeGreaterThan(0);
    expect(managed.every((n) => n.account === AWS_MANAGED_ACCOUNT)).toBe(true);
    expect(graph.links.length).toBeGreaterThan(0);
    expect(graph.links.some((link) => link.crossAccount)).toBe(false);
  });
});

describe('groupSiblings', () => {
  const r = (name: string) =>
    v(`arn:aws:iam::111122223333:role/${name}`, 'IamRole', { account_id: '111122223333' });
  const a = r('a');
  const b = r('b');
  const c = r('c');
  const other = v('arn:aws:s3:::other', 'S3Bucket', { account_id: '111122223333' });
  const graph = buildAttackGraph([
    { nodes: [a, bucket], edges: [e(a, bucket, 'GRANTS')] },
    { nodes: [b, bucket], edges: [e(b, bucket, 'GRANTS')] },
    { nodes: [c, other], edges: [e(c, other, 'GRANTS')] },
  ]);

  it('draws nodes with identical links as one, and keeps every path', () => {
    const grouped = groupSiblings(graph);
    expect(grouped.members.get(a.id)?.map((n) => n.vertex.id)).toEqual([a.id, b.id]);
    expect(grouped.groupOf.get(b.id)).toBe(a.id);
    expect(grouped.groupOf.has(c.id)).toBe(false);
    expect(grouped.model.nodes.map((n) => n.vertex.id)).not.toContain(b.id);
    expect(grouped.model.links.filter((l) => l.to === bucket.id)).toHaveLength(1);
    expect(grouped.model.pathCount).toBe(3);
    expect(grouped.model.paths[1].nodeIds).toEqual([a.id, bucket.id]);
    expect(grouped.linkOf.get(`${b.id}>${bucket.id}`)).toBe(`${a.id}>${bucket.id}`);
  });

  it('never merges nodes whose links differ, and leaves expanded groups apart', () => {
    expect(groupSiblings(graph).members.size).toBe(1);
    const expanded = groupSiblings(graph, new Set([a.id]));
    expect(expanded.members.size).toBe(0);
    expect(expanded.model.nodes).toHaveLength(graph.nodes.length);
  });
});

describe('review fixes', () => {
  const stmt = (id: string, props: Record<string, unknown>) =>
    v(`arn:aws:iam::111122223333:policy/s3/${id}`, 'IamPolicyStatement', {
      account_id: '111122223333',
      name: id,
      actions: ['s3:GetObject'],
      ...props,
    });
  const through = (s: GraphVertex, target = bucket) => ({
    nodes: [role, policy, s, target],
    edges: [e(role, policy, 'ATTACHED_TO'), e(policy, s, 'CONTAINS'), e(s, target, 'GRANTS')],
  });

  it('labels a Deny statement as Denies and a conditional grant as conditional', () => {
    const deny = buildAttackGraph([through(stmt('d', { effect: 'Deny' }))]);
    expect(deny.links[0].label).toBe('Denies s3:GetObject');
    expect(deny.links[0].kind).toBe('deny');
    expect(deny.nodes[0].permissions[0].effect).toBe('Deny');

    const conditional = buildAttackGraph([
      through(
        stmt('c', { effect: 'Allow', conditions_json: '{"Bool":{"aws:SecureTransport":"true"}}' })
      ),
    ]);
    expect(conditional.links[0].label).toBe('Allows s3:GetObject (conditional)');
    expect(conditional.links[0].kind).toBe('conditional');
    expect(conditional.nodes[0].permissions[0].conditions).toContain('SecureTransport');
  });

  it('says how many statements lead to the same resource', () => {
    const graph = buildAttackGraph([through(stmt('a', {})), through(stmt('b', {}))]);
    expect(graph.links).toHaveLength(1);
    expect(graph.links[0].label).toBe('Allows 2 statements');
    expect(graph.nodes[0].permissions).toHaveLength(2);
  });

  it('never marks a hop to an unknown account as cross-account', () => {
    const noAccount = v('not-an-arn', 'S3Bucket');
    const graph = buildAttackGraph([
      { nodes: [role, noAccount], edges: [e(role, noAccount, 'X')] },
    ]);
    expect(graph.links[0].crossAccount).toBe(false);
  });

  it('draws an unresolved outside account when the trust lookup found nobody', () => {
    const graph = buildAttackGraph([{ nodes: [role], edges: [] }], {
      [role.id]: { kind: 'trust', principals: [] },
    });
    const entry = graph.nodes.find((n) => n.vertex.id.startsWith('khalifa:unresolved-trust:'));
    expect(entry?.account).toBe('unresolved');
    expect(entry?.external).toBe(true);
    expect(graph.links).toContainEqual(
      expect.objectContaining({ to: role.id, label: 'Can assume', crossAccount: false })
    );
  });

  it('draws a merged hop by its strongest grant', () => {
    const graph = buildAttackGraph([
      through(stmt('x', { effect: 'Deny' })),
      through(stmt('y', { effect: 'Allow' })),
    ]);
    expect(graph.links[0]).toEqual(
      expect.objectContaining({ kind: 'access', label: 'Allows 2 statements' })
    );
  });

  it('orders nodes in a column by where their links come from', () => {
    const a = v('arn:aws:iam::111122223333:role/a', 'IamRole', { account_id: '111122223333' });
    const b = v('arn:aws:iam::111122223333:role/b', 'IamRole', { account_id: '111122223333' });
    const ta = v('arn:aws:s3:::ta', 'S3Bucket', { account_id: '111122223333' });
    const tb = v('arn:aws:s3:::tb', 'S3Bucket', { account_id: '111122223333' });
    // tb is listed first, but its source b sits below a, so tb belongs below ta.
    const graph = buildAttackGraph([
      { nodes: [a], edges: [] },
      { nodes: [b, tb], edges: [e(b, tb, 'X')] },
      { nodes: [a, ta], edges: [e(a, ta, 'X')] },
    ]);
    const y = (id: string) => layoutAttackGraph(graph).positions.get(id)!.y;
    expect(y(a.id)).toBeLessThan(y(b.id));
    expect(y(ta.id)).toBeLessThan(y(tb.id));
  });

  it('collapses the collector managed-policy shape onto the role', () => {
    const managed = v('arn:aws:iam::111122223333:policy/ReadExports', 'IamPolicy', {
      account_id: '111122223333',
      name: 'ReadExports',
    });
    const doc = v('arn:aws:iam::111122223333:policy/ReadExports/doc', 'IamPolicyDocument', {
      account_id: '111122223333',
    });
    const s1 = stmt('m', { effect: 'Allow' });
    const graph = buildAttackGraph([
      {
        nodes: [role, managed, doc, s1, bucket],
        edges: [
          e(role, managed, 'ATTACHED_TO'),
          e(managed, doc, 'CONTAINS'),
          e(doc, s1, 'CONTAINS'),
          e(s1, bucket, 'GRANTS'),
        ],
      },
    ]);
    expect(graph.nodes.map((n) => n.vertex.id)).toEqual([role.id, bucket.id]);
    expect(graph.links[0]).toEqual(
      expect.objectContaining({ label: 'Allows s3:GetObject', via: 'ReadExports' })
    );
    expect(graph.nodes[0].permissions[0].policy).toBe('ReadExports');
  });
});

describe('triage helpers', () => {
  const roleA = v('arn:aws:iam::111122223333:role/a', 'IamRole', { account_id: '111122223333' });
  const roleB = v('arn:aws:iam::111122223333:role/b', 'IamRole', { account_id: '111122223333' });
  const ec2 = v('arn:aws:ec2:us-west-2:111122223333:instance/i-1', 'Ec2Instance', {
    account_id: '111122223333',
    is_internet_exposed: true,
  });
  const b1 = v('arn:aws:s3:::one', 'S3Bucket', { account_id: '111122223333' });
  const b2 = v('arn:aws:s3:::two', 'S3Bucket', { account_id: '111122223333' });
  const path = (nodes: GraphVertex[], severity: 'critical' | 'high' | 'low') => ({
    nodes,
    edges: nodes.slice(1).map((n, i) => e(nodes[i], n, 'X')),
    score: severity === 'critical' ? 90 : severity === 'high' ? 70 : 20,
    severity,
  });
  const model = buildAttackGraph(
    [
      path([ec2, roleA, b1], 'critical'),
      path([ec2, roleA, b2], 'high'),
      path([ec2, roleB, b2], 'low'),
    ],
    { [ec2.id]: { kind: 'internet' } }
  );

  it("records each path's nodes and links after collapse, entry included", () => {
    expect(model.paths).toHaveLength(3);
    expect(model.paths[0].nodeIds).toEqual([INTERNET_ID, ec2.id, roleA.id, b1.id]);
    expect(model.paths[0].linkKeys).toHaveLength(3);
    expect(model.paths[0].severity).toBe('critical');
  });

  it('ranks intermediate nodes by the paths that run through them', () => {
    const chokes = chokePoints(model);
    expect(chokes.map((c) => [c.node.vertex.id, c.paths])).toEqual([
      [ec2.id, 3],
      [roleA.id, 2],
      [roleB.id, 1],
    ]);
    // Entries and targets are not choke points.
    expect(chokes.some((c) => c.node.vertex.id === INTERNET_ID || c.node.vertex.id === b2.id)).toBe(
      false
    );
  });

  it('describes each path with its entry, ends, hops and risks, in the given order', () => {
    const described = describePaths(model);
    expect(described.map((d) => d.path.severity)).toEqual(['critical', 'high', 'low']);
    expect(described[0]).toMatchObject({ index: 0, entry: 'internet', hops: 3 });
    expect(described[0].start.vertex.id).toBe(INTERNET_ID);
    expect(described[0].target.vertex.id).toBe(b1.id);
    expect(described[0].risks).toEqual([{ level: 'risk', text: 'Internet exposed' }]);
    expect(
      describePaths(buildAttackGraph([{ nodes: [roleA, b1], edges: [e(roleA, b1, 'X')] }]))[0].entry
    ).toBe('internal');
  });

  it('calls a path from an unresolved trust an outside entry', () => {
    const trust = buildAttackGraph([{ nodes: [roleA, b1], edges: [e(roleA, b1, 'X')] }], {
      [roleA.id]: { kind: 'trust', principals: [] },
    });
    expect(describePaths(trust)[0].entry).toBe('outside');
  });
});
