import Gremlin from 'gremlin';
import {
  fetchPoliciesForPrincipal,
  fetchPrincipals,
  fetchRolesWithPermissions,
  fetchTrustEdges,
  dropStaleEscalations,
  writeEffectivePermission,
  writeEscalationEdge,
  writeEscalationPath,
} from './index';
import { effectivePermissionId } from '@khalifa/risk-engine';

function recordingClient(rows: unknown[] = []): {
  client: Gremlin.driver.Client;
  queries: unknown[];
} {
  const queries: unknown[] = [];
  const client = {
    submit: jest.fn(async (query: unknown) => {
      queries.push(query);
      return { toArray: () => rows };
    }),
  };
  return { client: client as unknown as Gremlin.driver.Client, queries };
}

// Neptune rejects script bindings, so the CIEM writes submit Bytecode; the
// assertions inspect the serialized traversal rather than a query string.
function encoded(query: unknown): string {
  return JSON.stringify(query);
}

describe('CIEM query shapes', () => {
  const arn = 'arn:aws:iam::111122223333:role/Admin';

  it('enumerates principals in bounded pages instead of one unbounded submit', async () => {
    const { client, queries } = recordingClient();
    await fetchPrincipals(client);

    expect(queries).toHaveLength(1);
    expect(queries[0]).toContain('range(0, 1000)');
    expect(queries[0]).toContain("hasLabel(within('IamUser', 'IamRole'))");
  });

  it('resolves a principal by id, not by a property filter', async () => {
    const { client, queries } = recordingClient();
    await fetchPoliciesForPrincipal(client, arn);

    const q = encoded(queries[0]);
    expect(q).toContain(JSON.stringify(['V', arn]));
    expect(q).not.toContain('"has","arn"');
    expect(q).toContain(JSON.stringify(['project', 'policyArn', 'documentJson']));
    expect(q).toContain('"optional"');
    expect(q).toContain(JSON.stringify(['out', 'CONTAINS']));
  });

  it("follows a user's groups and counts a shared policy once", async () => {
    const { client, queries } = recordingClient();
    await fetchPoliciesForPrincipal(client, arn);

    const q = encoded(queries[0]);
    expect(q).toContain('"union"');
    expect(q).toContain(JSON.stringify(['out', 'MEMBER_OF']));
    expect(q).toContain(JSON.stringify(['dedup']));
  });

  it('projects trust-edge endpoints from the edge, not unset label properties', async () => {
    const { client, queries } = recordingClient();
    await fetchTrustEdges(client);

    expect(queries[0]).toContain('outV().id()');
    expect(queries[0]).toContain('inV().id()');
    expect(queries[0]).not.toContain('from_label');
    expect(queries[0]).not.toContain('to_label');
    expect(queries[0]).toContain('range(0, 1000)');
  });

  it('enumerates effective permissions in bounded pages', async () => {
    const { client, queries } = recordingClient();
    await fetchRolesWithPermissions(client);

    expect(queries[0]).toContain("hasLabel('EffectivePermission')");
    expect(queries[0]).toContain('range(0, 1000)');
  });

  it('fails loudly when a trust-edge read errors instead of reporting no paths', async () => {
    const client = {
      submit: jest.fn().mockRejectedValue(new Error('Neptune timeout')),
    } as unknown as Gremlin.driver.Client;

    await expect(fetchTrustEdges(client)).rejects.toThrow('Neptune timeout');
  });

  it('fails loudly when the effective-permission read errors', async () => {
    const client = {
      submit: jest.fn().mockRejectedValue(new Error('MemoryLimitExceededException')),
    } as unknown as Gremlin.driver.Client;

    await expect(fetchRolesWithPermissions(client)).rejects.toThrow('MemoryLimitExceededException');
  });

  it('upserts the effective permission by its deterministic id', async () => {
    const { client, queries } = recordingClient();
    await writeEffectivePermission(client, {
      id: effectivePermissionId(arn),
      principalArn: arn,
      allowedActions: ['s3:GetObject'],
      deniedActions: [],
      conditionalGrants: [],
      policiesEvaluated: ['arn:aws:iam::111122223333:policy/ReadOnly'],
      evaluatedAt: '2026-09-20T00:00:00.000Z',
      isAdmin: false,
      blastRadius: 1,
    });

    const q = encoded(queries[0]);
    expect(q).toContain(JSON.stringify(['V', effectivePermissionId(arn)]));
    expect(q).not.toContain('hasLabel');
    expect(q).toContain('"coalesce"');
  });

  it('writes is_admin onto the principal itself', async () => {
    const { client, queries } = recordingClient();
    await writeEffectivePermission(client, {
      id: effectivePermissionId(arn),
      principalArn: arn,
      allowedActions: ['*'],
      deniedActions: [],
      conditionalGrants: [],
      policiesEvaluated: [],
      evaluatedAt: '2026-09-20T00:00:00.000Z',
      isAdmin: true,
      blastRadius: 1,
    });

    const { stepInstructions } = JSON.parse(encoded(queries[0]));
    expect(stepInstructions.slice(-2)).toEqual([
      ['V', arn],
      ['property', { typeName: 'Cardinality', elementName: 'single' }, 'is_admin', true],
    ]);
  });

  it('parses the serialized allowed_actions list before escalation detection uses it', async () => {
    const row = {
      get: (key: string) =>
        ({
          arn,
          allowedActions: '["iam:CreatePolicyVersion","s3:GetObject"]',
          isAdmin: false,
        })[key],
    };
    const { client } = recordingClient([row]);

    const [role] = await fetchRolesWithPermissions(client);

    expect(role.allowedActions).toEqual(['iam:CreatePolicyVersion', 's3:GetObject']);
    // Prove the parsed value survives the `.some`/`.filter` calls that a raw
    // JSON string would throw on.
    expect(role.allowedActions.some((action) => action === 's3:GetObject')).toBe(true);
  });

  it('pins the element id and writes single-cardinality properties on effective permissions', async () => {
    const { client, queries } = recordingClient();
    await writeEffectivePermission(client, {
      id: effectivePermissionId(arn),
      principalArn: arn,
      allowedActions: ['s3:GetObject'],
      deniedActions: [],
      conditionalGrants: [],
      policiesEvaluated: ['arn:aws:iam::111122223333:policy/ReadOnly'],
      evaluatedAt: '2026-09-20T00:00:00.000Z',
      isAdmin: false,
      blastRadius: 1,
    });

    const q = encoded(queries[0]);
    // T.id, not the plain `id` property: the create branch must be an id step
    // on the next run, or the same principal is added again.
    expect(q).toContain('"typeName":"T","elementName":"id"');
    // single, not the default set: `evaluated_at` would otherwise gain a value
    // on every run.
    expect(q).toContain('"typeName":"Cardinality","elementName":"single"');
    expect(q).toContain('"evaluated_at"');
    // The API reads `conditional_grants`; it was never written.
    expect(q).toContain('"conditional_grants"');
  });

  it('upserts escalation paths by id with single-cardinality properties', async () => {
    const { client, queries } = recordingClient();
    await writeEscalationPath(client, {
      id: 'esc-path:admin',
      sourceArn: arn,
      targetArn: 'arn:aws:iam::111122223333:role/Admin',
      path: [],
      pathLength: 2,
      riskLevel: 'high',
      escalationType: 'privilege_escalation',
      conditions: {},
      detectedAt: '2026-09-20T00:00:00.000Z',
    });

    const q = encoded(queries[0]);
    expect(q).toContain(JSON.stringify(['V', 'esc-path:admin']));
    expect(q).toContain('"typeName":"T","elementName":"id"');
    expect(q).toContain('"typeName":"Cardinality","elementName":"single"');
    expect(q).toContain('"detected_at"');
    expect(q).not.toContain('hasLabel');
  });

  it('upserts the escalation link by id between the two principals', async () => {
    const { client, queries } = recordingClient();
    const target = 'arn:aws:iam::111122223333:role/Target';
    await writeEscalationEdge(client, {
      id: 'esc-path:x',
      sourceArn: arn,
      targetArn: target,
      path: [],
      pathLength: 1,
      riskLevel: 'critical',
      escalationType: 'admin',
      conditions: {},
      detectedAt: '2026-09-20T00:00:00.000Z',
    });

    const q = encoded(queries[0]);
    expect(q).toContain(JSON.stringify(['E', `can-escalate:${arn}:${target}`]));
    expect(q).toContain(JSON.stringify(['addE', 'CAN_ESCALATE_TO']));
    expect(q).toContain('"typeName":"T","elementName":"id"');
    // Neptune rejects a cardinality token on edge properties.
    expect(q).not.toContain('"Cardinality"');
  });

  it('drops only escalation paths and links the run did not refresh', async () => {
    const { client, queries } = recordingClient();
    await dropStaleEscalations(client, '2026-09-20T00:00:00.000Z');

    expect(queries).toHaveLength(2);
    expect(encoded(queries[0])).toContain(JSON.stringify(['hasLabel', 'EscalationPath']));
    expect(encoded(queries[1])).toContain(JSON.stringify(['hasLabel', 'CAN_ESCALATE_TO']));
    for (const query of queries) {
      expect(encoded(query)).toContain('"not"');
      expect(encoded(query)).toContain('"gte"');
    }
  });
});
