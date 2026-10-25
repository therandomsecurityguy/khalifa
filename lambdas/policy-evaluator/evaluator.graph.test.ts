import Gremlin from 'gremlin';
import { NeptuneRuntimeClient, effectivePermissionId } from '@khalifa/risk-engine';
import {
  dropStaleEscalations,
  fetchPassableAdminRoles,
  fetchPoliciesForPrincipal,
  writeEffectivePermission,
  writeEscalationEdge,
  writeEscalationPath,
} from './index';
import type { EscalationPath } from './types';

// The evaluator's writes against a throwaway local Gremlin Server (CI only).
const endpoint = process.env.GREMLIN_TEST_ENDPOINT ?? '';
if (!/^ws:\/\/(127\.0\.0\.1|localhost):\d+\/gremlin$/.test(endpoint)) {
  throw new Error('GREMLIN_TEST_ENDPOINT must be a local ws://127.0.0.1:<port>/gremlin');
}

const neptune = new NeptuneRuntimeClient(
  { endpoint: 'wss://localhost/gremlin', maxAttempts: 1, timeoutMs: 15_000 },
  {
    createHeaders: async () => ({}),
    createClient: () => new Gremlin.driver.Client(endpoint, { traversalSource: 'g' }),
  }
);

const admin = 'arn:aws:iam::111122223333:role/Admin';
const reader = 'arn:aws:iam::111122223333:role/Reader';
const account = 'arn:aws:iam::111122223333:root';

async function values(query: string): Promise<unknown[]> {
  return neptune.submit(query);
}

function permission(principalArn: string, isAdmin: boolean) {
  return {
    id: effectivePermissionId(principalArn),
    principalArn,
    allowedActions: isAdmin ? ['*'] : ['s3:GetObject'],
    deniedActions: [],
    conditionalGrants: [],
    policiesEvaluated: [],
    evaluatedAt: '2026-10-13T00:00:00.000Z',
    isAdmin,
    blastRadius: 1,
  };
}

function path(sourceArn: string, targetArn: string, detectedAt: string): EscalationPath {
  return {
    id: `esc-path:${sourceArn}:${targetArn}`,
    sourceArn,
    targetArn,
    path: [],
    pathLength: 1,
    riskLevel: 'critical',
    escalationType: 'admin',
    conditions: {},
    detectedAt,
  };
}

beforeEach(async () => {
  await neptune.submit('g.V().drop().iterate()');
  await neptune.submit(
    `g.addV('AwsAccount').property(T.id, '${account}')` +
      `.addV('IamRole').property(T.id, '${admin}')` +
      `.addV('IamRole').property(T.id, '${reader}').iterate()`
  );
});
afterAll(() => neptune.close());

describe('policy evaluator writes against a Gremlin Server', () => {
  it('writes is_admin onto the principal, true and false', async () => {
    await writeEffectivePermission(neptune, permission(admin, true));
    await writeEffectivePermission(neptune, permission(reader, false));

    expect(await values(`g.V('${admin}').values('is_admin')`)).toEqual([true]);
    expect(await values(`g.V('${reader}').values('is_admin')`)).toEqual([false]);
  });

  it('flips is_admin when a principal loses admin', async () => {
    await writeEffectivePermission(neptune, permission(admin, true));
    await writeEffectivePermission(neptune, permission(admin, false));

    expect(await values(`g.V('${admin}').values('is_admin')`)).toEqual([false]);
  });

  it('creates no principal that is not in the graph', async () => {
    await writeEffectivePermission(
      neptune,
      permission('arn:aws:iam::111122223333:role/Gone', true)
    );

    expect(await values(`g.V().hasLabel('IamRole').count()`)).toEqual([2]);
  });

  it("reads a user's own and group policies, each once", async () => {
    const user = 'arn:aws:iam::111122223333:user/dev';
    const group = 'arn:aws:iam::111122223333:group/Admins';
    const shared = 'arn:aws:iam::aws:policy/AdministratorAccess';
    await neptune.submit(
      `g.addV('IamUser').property(T.id, '${user}')` +
        `.addV('IamGroup').property(T.id, '${group}')` +
        `.addV('IamPolicyDocument').property(T.id, '${user}/inline').property('policy_arn', 'own')` +
        `.addV('IamPolicyDocument').property(T.id, '${group}/inline').property('policy_arn', 'group')` +
        `.addV('IamPolicy').property(T.id, '${shared}')` +
        `.addV('IamPolicyDocument').property(T.id, '${shared}/v1').property('policy_arn', 'managed')` +
        // Another group the user is not in.
        `.addV('IamGroup').property(T.id, 'other-group')` +
        `.addV('IamPolicyDocument').property(T.id, 'other/inline').property('policy_arn', 'other')` +
        `.iterate()`
    );
    for (const [from, label, to] of [
      [user, 'MEMBER_OF', group],
      [user, 'ATTACHED_TO', `${user}/inline`],
      [group, 'ATTACHED_TO', `${group}/inline`],
      [user, 'ATTACHED_TO', shared],
      [group, 'ATTACHED_TO', shared],
      [shared, 'CONTAINS', `${shared}/v1`],
      ['other-group', 'ATTACHED_TO', 'other/inline'],
    ]) {
      await neptune.submit(`g.V('${from}').addE('${label}').to(__.V('${to}')).iterate()`);
    }

    const policies = await fetchPoliciesForPrincipal(neptune, user);

    expect(policies.map((policy) => policy.policyArn).sort()).toEqual(['group', 'managed', 'own']);
  });

  it('links source to target once, refreshing on re-run', async () => {
    await writeEscalationEdge(neptune, path(account, admin, '2026-10-13T00:00:00.000Z'));
    await writeEscalationEdge(neptune, path(account, admin, '2026-10-14T00:00:00.000Z'));

    expect(await values(`g.V('${account}').outE('CAN_ESCALATE_TO').inV().id()`)).toEqual([admin]);
    expect(await values(`g.E().hasLabel('CAN_ESCALATE_TO').values('detected_at')`)).toEqual([
      '2026-10-14T00:00:00.000Z',
    ]);
  });

  it('skips a link whose source is not in the graph', async () => {
    await writeEscalationEdge(
      neptune,
      path('arn:aws:iam::999999999999:root', admin, '2026-10-13T00:00:00.000Z')
    );

    expect(await values(`g.E().hasLabel('CAN_ESCALATE_TO').count()`)).toEqual([0]);
  });

  it('drops only escalation paths and links the run did not refresh', async () => {
    const runStartedAt = '2026-10-13T05:00:00.000Z';
    await writeEscalationPath(neptune, path(account, admin, '2026-10-13T05:01:00.000Z'));
    await writeEscalationEdge(neptune, path(account, admin, '2026-10-13T05:01:00.000Z'));
    await writeEscalationPath(neptune, path(reader, admin, '2026-10-12T05:01:00.000Z'));
    await writeEscalationEdge(neptune, path(reader, admin, '2026-10-12T05:01:00.000Z'));
    // Written before detected_at existed.
    await neptune.submit(`g.addV('EscalationPath').property(T.id, 'legacy').iterate()`);
    // Other elements the cleanup must never touch.
    await neptune.submit(`g.V('${reader}').addE('TRUSTS').to(__.V('${admin}')).iterate()`);

    await dropStaleEscalations(neptune, runStartedAt);

    expect(await values(`g.V().hasLabel('EscalationPath').id()`)).toEqual([
      `esc-path:${account}:${admin}`,
    ]);
    expect(await values(`g.E().hasLabel('CAN_ESCALATE_TO').outV().id()`)).toEqual([account]);
    expect(await values(`g.E().hasLabel('TRUSTS').count()`)).toEqual([1]);
    expect(await values(`g.V().hasLabel('IamRole').count()`)).toEqual([2]);
  });

  it('reads admin roles a compute service can assume, with their path', async () => {
    const trust = JSON.stringify({
      Statement: [{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' } }],
    }).replace(/'/g, "\\'");
    await neptune.submit(
      `g.V('${admin}').property(single, 'is_admin', true).property(single, 'path', '/service-role/')` +
        `.property(single, 'assume_role_policy_document', '${trust}')` +
        `.V('${reader}').property(single, 'is_admin', false)` +
        `.property(single, 'assume_role_policy_document', '${trust}').iterate()`
    );

    expect(await fetchPassableAdminRoles(neptune)).toEqual([
      {
        arn: admin,
        accountId: '111122223333',
        passArn: 'arn:aws:iam::111122223333:role/service-role/Admin',
        trustedServices: ['lambda.amazonaws.com'],
      },
    ]);
  });

  it('keeps a pass_role link apart from a trust link between the same pair', async () => {
    const at = '2026-10-13T00:00:00.000Z';
    await writeEscalationEdge(neptune, path(reader, admin, at));
    await writeEscalationEdge(neptune, {
      ...path(reader, admin, at),
      escalationType: 'pass_role',
      via: ['lambda.amazonaws.com'],
    });

    expect(
      await values(`g.E().hasLabel('CAN_ESCALATE_TO').values('escalation_type').order()`)
    ).toEqual(['admin', 'pass_role']);
  });
});
