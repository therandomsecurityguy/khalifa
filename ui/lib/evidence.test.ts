import { evidenceFor } from './evidence';

const vertex = (label: string, properties: Record<string, unknown>) => ({
  id: `arn:${label}`,
  label,
  properties,
});

describe('evidenceFor', () => {
  it('describes an access key and marks what RULE-013 matched on', () => {
    const facts = evidenceFor(
      vertex('AccessKey', {
        status: 'Active',
        key_age_days: 131,
        created_date: '2026-05-28T10:00:00.000Z',
        last_used_date: '2026-09-30T08:00:00.000Z',
        last_used_days_ago: 6,
      }),
      'RULE-013'
    );
    expect(facts).toEqual([
      { id: 'status', label: 'Status', value: 'Active', decisive: true },
      {
        id: 'key_age_days',
        label: 'Age',
        value: '131 days',
        decisive: true,
      },
      { id: 'created_date', label: 'Created', value: 'May 28, 2026', decisive: false },
      {
        id: 'last_used_days_ago',
        label: 'Last used',
        value: 'Sep 30, 2026 · 6 days ago',
        decisive: false,
      },
    ]);
  });

  it('shows a port range, a single port, or all ports for a security group rule', () => {
    const rule = (extra: Record<string, unknown>) =>
      evidenceFor(
        vertex('SecurityGroupRule', { direction: 'ingress', cidr_block: '0.0.0.0/0', ...extra }),
        'RULE-002'
      );
    expect(rule({ protocol: 'tcp', port_from: 22, port_to: 22 }).map((f) => f.value)).toEqual([
      'ingress',
      'tcp',
      '22',
      '0.0.0.0/0',
    ]);
    expect(rule({ protocol: 'tcp', port_from: 20, port_to: 25 })[2].value).toBe('20–25');
    expect(rule({ protocol: '-1' })[2].value).toBe('all');
    expect(rule({ protocol: 'tcp', port_from: 22, port_to: 22 })[3]).toEqual(
      expect.objectContaining({ decisive: true })
    );
  });

  it('parses list properties stored as JSON or comma-separated text', () => {
    const facts = evidenceFor(
      vertex('IamPolicyStatement', {
        effect: 'Allow',
        actions: '["s3:*","iam:PassRole"]',
        resources: 'arn:aws:s3:::a, arn:aws:s3:::b',
        has_wildcard_resource: false,
      }),
      'RULE-006'
    );
    expect(facts.map((f) => [f.label, f.value])).toEqual([
      ['Effect', 'Allow'],
      ['Actions', 's3:*, iam:PassRole'],
      ['Resources', 'arn:aws:s3:::a, arn:aws:s3:::b'],
      ['Wildcard resource', 'no'],
    ]);
  });

  it('falls back to a vertex’s own scalar properties, skipping identifiers and bookkeeping', () => {
    const facts = evidenceFor(
      vertex('NewThing', {
        id: 'x',
        arn: 'arn:x',
        account_id: '111122223333',
        collection_run_id: 'run',
        is_encrypted: true,
        retention_days: 7,
        owner: 'team-a',
        nested: { a: 1 },
      }),
      'RULE-099'
    );
    expect(facts).toEqual([
      { id: 'is_encrypted', label: 'Encrypted', value: 'yes', decisive: false },
      { id: 'retention_days', label: 'Retention days', value: '7', decisive: false },
      { id: 'owner', label: 'Owner', value: 'team-a', decisive: false },
    ]);
  });

  it('leaves out facts whose property is missing', () => {
    expect(evidenceFor(vertex('Vpc', {}), 'RULE-027')).toEqual([]);
    expect(evidenceFor(vertex('Vpc', { flow_logs_enabled: false }), 'RULE-027')).toEqual([
      {
        id: 'flow_logs_enabled',
        label: 'Flow logs',
        value: 'no',
        decisive: true,
      },
    ]);
  });
});
