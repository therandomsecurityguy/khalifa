import Gremlin from 'gremlin';
import { effectivePermissionId } from '@khalifa/risk-engine';
import {
  configure,
  fetchEffectivePermission,
  fetchPoliciesForPrincipal,
  fetchPrincipals,
  fetchUsedActions,
} from './index';

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

// Neptune rejects script bindings, so the sweep reads submit Bytecode.
function encoded(query: unknown): string {
  return JSON.stringify(query);
}

describe('sweep query shapes', () => {
  const arn = 'arn:aws:iam::111122223333:role/Data';

  it('enumerates principals in bounded pages', async () => {
    const { client, queries } = recordingClient();
    await fetchPrincipals(client);

    expect(queries[0]).toContain("hasLabel(within('IamUser', 'IamRole'))");
    expect(queries[0]).toContain('range(0, 1000)');
  });

  it('resolves a principal by id, not by a property filter', async () => {
    const { client, queries } = recordingClient();
    await fetchPoliciesForPrincipal(client, arn);

    const q = encoded(queries[0]);
    expect(q).toContain(JSON.stringify(['V', arn]));
    expect(q).not.toContain('"has","arn"');
    expect(q).toContain(JSON.stringify(['project', 'policyArn', 'documentJson', 'policyType']));
  });

  it('propagates usage-read failures so the principal is skipped, not emptied', async () => {
    const sender = {
      send: jest.fn().mockRejectedValue(new Error('DynamoDB throttled')),
    };

    await expect(fetchUsedActions(arn, sender)).rejects.toThrow('DynamoDB throttled');
  });

  it('configure() rebinds the table names so the runtime injects its environment', async () => {
    const sender = { send: jest.fn().mockResolvedValue({ Items: [] }) };
    configure({ ACCESS_ANALYZER_TABLE: 'InjectedCache' });
    try {
      await fetchUsedActions(arn, sender);
      expect(
        (sender.send.mock.calls[0][0] as { input: { TableName: string } }).input.TableName
      ).toBe('InjectedCache');
    } finally {
      configure(); // restore the module-load defaults for the other cases
    }
  });

  it('returns an empty list when a principal simply has no recorded usage', async () => {
    const sender = { send: jest.fn().mockResolvedValue({ Items: [] }) };
    await expect(fetchUsedActions(arn, sender)).resolves.toEqual([]);
  });

  it('reads the effective permission by its deterministic id', async () => {
    const { client, queries } = recordingClient([
      new Map<string, unknown>([
        ['allowedActions', '["s3:GetObject"]'],
        ['isAdmin', false],
        ['blastRadius', 3],
      ]),
    ]);

    const permission = await fetchEffectivePermission(client, arn);

    const q = encoded(queries[0]);
    expect(q).toContain(JSON.stringify(['V', effectivePermissionId(arn)]));
    expect(q).not.toContain('"has","principal_arn"');
    expect(permission).toEqual({
      allowedActions: ['s3:GetObject'],
      isAdmin: false,
      blastRadius: 3,
    });
  });
});
