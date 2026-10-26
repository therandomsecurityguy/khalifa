import { PlanParseError, parsePlan } from './plan';

function plan(changes: unknown[]): string {
  return JSON.stringify({ format_version: '1.2', resource_changes: changes });
}

function change(overrides: Record<string, unknown> = {}) {
  return {
    address: 'aws_security_group.app',
    mode: 'managed',
    type: 'aws_security_group',
    name: 'app',
    change: { actions: ['create'], before: null, after: { name: 'app' } },
    ...overrides,
  };
}

describe('parsePlan', () => {
  it('keeps create and update changes, treating a replacement as a create', () => {
    const resources = parsePlan(
      plan([
        change(),
        change({ address: 'b', change: { actions: ['update'], after: { name: 'b' } } }),
        change({ address: 'c', change: { actions: ['delete', 'create'], after: { name: 'c' } } }),
      ])
    );
    expect(resources.map((resource) => [resource.address, resource.actions[0]])).toEqual([
      ['aws_security_group.app', 'create'],
      ['b', 'update'],
      ['c', 'create'],
    ]);
  });

  it('drops no-ops, deletes, and data sources', () => {
    const resources = parsePlan(
      plan([
        change({ address: 'noop', change: { actions: ['no-op'], after: {} } }),
        change({ address: 'gone', change: { actions: ['delete'], after: null } }),
        change({
          address: 'data.aws_ami.x',
          mode: 'data',
          change: { actions: ['read'], after: {} },
        }),
      ])
    );
    expect(resources).toEqual([]);
  });

  it('drops unknown values so checks only read what the plan knows', () => {
    const [resource] = parsePlan(
      plan([
        change({
          change: { actions: ['create'], after: { name: 'app', vpc_id: null, tags: null } },
        }),
      ])
    );
    expect(resource.after).toEqual({ name: 'app' });
  });

  it.each([
    ['not JSON', 'not json at all', 'not valid JSON'],
    ['no resource_changes', JSON.stringify({ format_version: '1.2' }), 'no resource_changes'],
    ['missing address', plan([change({ address: undefined })]), 'missing address or type'],
    [
      'bad actions',
      plan([change({ change: { actions: 'create', after: {} } })]),
      'actions must be a string array',
    ],
  ])('rejects %s', (_label, text, message) => {
    expect(() => parsePlan(text)).toThrow(PlanParseError);
    expect(() => parsePlan(text)).toThrow(message);
  });
});
