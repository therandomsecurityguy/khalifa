import {
  complianceCutoffIso,
  complianceRuleEvaluators,
  getEvaluatorForControl,
} from './compliance-rules';
import {
  LEGACY_CONTROL_IDS,
  REGIONAL_CONTROL_IDS,
  getAllControls,
  getControlById,
  getControlsByFramework,
} from './compliance-types';

const ACCOUNT = '111111111111';

/**
 * A graph stub for the per-account helpers . Coverage reads return one
 * assessed account (or account/region); "which accounts violate" reads return it
 * only when `failing`; every count returns `count`. `routes` answers any query
 * containing its key first, so guards are matched by text, not by call order.
 */
function graphStub(
  opts: { count?: number; failing?: boolean; routes?: Record<string, unknown[]> } = {}
) {
  const count = opts.count ?? 0;
  const failing = opts.failing ?? count > 0;
  const routes = opts.routes ?? {};
  const pair = { a: ACCOUNT, r: 'us-west-2' };
  return {
    executeQuery: jest.fn(async (q: string) => {
      for (const [key, value] of Object.entries(routes)) if (q.includes(key)) return value;
      const regional = q.includes("project('a', 'r')");
      if (q.includes("hasLabel('CollectionCoverage')")) return regional ? [pair] : [ACCOUNT];
      if (regional) return failing ? [pair] : [];
      if (q.includes("values('account_id')")) return failing ? [ACCOUNT] : [];
      return [count];
    }),
  };
}

const squash = (q: string) => q.replace(/\s+/g, ' ').trim();
/** The first query an evaluator ran that contains `text`. */
const queryWith = (g: { executeQuery: jest.Mock }, text: string) =>
  (g.executeQuery.mock.calls as [string][]).map(([q]) => squash(q)).find((q) => q.includes(text));

describe('compliance Gremlin queries', () => {
  it('creates a bounded ISO cutoff client-side', () => {
    const now = Date.parse('2026-09-10T00:00:00.000Z');

    expect(complianceCutoffIso(90, now)).toBe('2026-06-12T00:00:00.000Z');
    expect(() => complianceCutoffIso(0, now)).toThrow('between 1 and 3650');
    expect(() => complianceCutoffIso(90, Number.POSITIVE_INFINITY)).toThrow('must be finite');
  });

  // These controls must test the same collected properties as RULE-013/014.
  // They previously compared last_used_date, so key rotation never caught a
  // long-lived actively-used key and both controls measured the same thing.
  // Ids follow CIS v3.0.0: rotation is 1.14, unused credentials is 1.12.
  it.each([
    ['1.14', "has('key_age_days', gt(90))"],
    ['1.12', "has('last_used_days_ago', gte(45))"],
  ])('%s emits the matching risk-rule predicate', async (controlId, predicate) => {
    const graphClient = graphStub();

    await getEvaluatorForControl(controlId)?.evaluate(graphClient);

    const query = queryWith(graphClient, predicate)!;
    expect(query).toContain(predicate);
    expect(query).toContain('.hasLabel(');
    expect(query).not.toContain('last_used_date');
  });

  it('all evaluators use graph labels instead of a non-existent label property', async () => {
    // Counts get [0]; account and account/region reads get none, since [0] is neither.
    const graphClient = {
      executeQuery: jest.fn(async (q: string) =>
        q.includes("values('account_id')") || q.includes("project('a', 'r')") ? [] : [0]
      ),
    };

    for (const evaluator of complianceRuleEvaluators) await evaluator.evaluate(graphClient);

    expect(graphClient.executeQuery).toHaveBeenCalled();
    for (const [query] of graphClient.executeQuery.mock.calls) {
      expect(query).toContain('.hasLabel(');
      expect(query).not.toContain(".has('label'");
    }
  });

  it('rejects a missing count instead of treating it as a passing zero', async () => {
    const evaluator = getEvaluatorForControl('1.4')!;
    await expect(evaluator.evaluate({ executeQuery: async () => [] })).rejects.toThrow(
      'invalid count'
    );
  });
});

// list-accounts writes arn:aws:iam::<account>:root as an AwsAccount before the IAM
// stage writes root posture to the same id, and an upsert never relabels, so the
// root user is an AwsAccount vertex in production. Matching IamUser alone failed
// 1.5 for every account and left 1.4 blind to root keys.
describe('root user controls', () => {
  it.each([
    ['1.4', ".out('HAS_ACCESS_KEY')"],
    ['1.5', "has('root_credentials_present', false)"],
  ])('%s reads root posture from either label', async (controlId, step) => {
    const graphClient = {
      executeQuery: jest.fn(async (q: string) =>
        q.includes("values('account_id')") ? ['111111111111'] : [0]
      ),
    };

    await getEvaluatorForControl(controlId)!.evaluate(graphClient);

    const query = (graphClient.executeQuery.mock.calls as [string][])
      .map(([q]) => q.replace(/\s+/g, ' '))
      .find((q) => q.includes(step))!;
    expect(query).toContain(
      "g.V().hasLabel('IamUser', 'AwsAccount').has('arn', endingWith(':root'))"
    );
  });
});

// IAM.9 passes "if root user credentials aren't present in the account"
// (AWS Security Hub iam-controls, IAM.9). Accounts under Organizations central
// root access have no root password, key or certificate.
describe('1.5 root MFA', () => {
  it('passes an account whose root has MFA or has no credentials at all', async () => {
    const graphClient = {
      executeQuery: jest.fn(async (q: string) =>
        q.includes('CollectionCoverage')
          ? ['111111111111', '222222222222', '333333333333']
          : ['111111111111', '222222222222']
      ),
    };

    const result = await getEvaluatorForControl('1.5')!.evaluate(graphClient);

    const query = (graphClient.executeQuery.mock.calls as [string][])
      .map(([q]) => q.replace(/\s+/g, ' '))
      .find((q) => q.includes('root_credentials_present'))!;
    expect(query).toContain(
      ".or(has('mfa_enabled', true), has('root_credentials_present', false))"
    );
    expect(result.status).toBe('FAIL');
    expect(result.evidence[0].details.failingAccounts).toEqual(['333333333333']);
  });
});

// The security-group controls had no query-level tests, so nothing checked that
// they matched what EC2.53/EC2.54 evaluate, or would survive an edit.
describe('security group controls', () => {
  const SG_CONTROLS = ['5.2', '5.3'] as const;

  // Gremlin is formatted for reading, so assertions must not depend on where the
  // line breaks fall. Squashing runs of whitespace lets a reflow of the query
  // pass while a real change to it still fails.
  const flat = (query: string) => query.replace(/\s+/g, ' ').trim();

  async function queryFor(controlId: string) {
    const graphClient = graphStub();
    await getEvaluatorForControl(controlId)!.evaluate(graphClient);
    return flat(graphClient.executeQuery.mock.calls.at(-1)![0] as string);
  }

  const startsAt = (query: string, label: string) => query.startsWith(`g.V().hasLabel('${label}')`);

  // Both of these assert a rule rather than one spelling, so a rewrite that
  // starts at SecurityGroup and filters -- which needs no dedup -- satisfies
  // them too.
  it.each(SG_CONTROLS)('%s does not double-count a group with several rules', async (controlId) => {
    const query = await queryFor(controlId);

    // Walking up from rules is many-to-one: a group with an open port-22 rule
    // and an open port-3389 rule is reached twice, and counted twice.
    if (startsAt(query, 'SecurityGroupRule')) {
      expect(query).toMatch(/dedup\(\)[\s\S]*count\(\)/);
    }
  });

  it.each(SG_CONTROLS)('%s walks PART_OF in the direction its start implies', async (controlId) => {
    const query = await queryFor(controlId);

    // PART_OF points from a rule to its group. Traversed the wrong way the query
    // matches nothing, the count is zero and the control reports PASS forever.
    if (startsAt(query, 'SecurityGroupRule')) {
      expect(query).toContain("out('PART_OF')");
      expect(query).not.toContain("in('PART_OF')");
    } else {
      expect(query).toContain("in('PART_OF')");
      expect(query).not.toContain("out('PART_OF')");
    }
  });

  it.each(SG_CONTROLS)('%s counts only ingress rules', async (controlId) => {
    expect(await queryFor(controlId)).toContain("has('direction', 'ingress')");
  });

  // port_from 0 alone also matches a rule for ports 0-10, which does not reach
  // 22 or 3389 at all. Pairing it with port_to 0 keeps the clause to its real
  // meaning: a rule carrying no port range, so every port.
  it.each(SG_CONTROLS)(
    '%s treats an absent port range as all ports, not any',
    async (controlId) => {
      const query = await queryFor(controlId);

      expect(query).toContain("has('port_from', 0).has('port_to', 0)");
      expect(query).not.toMatch(/has\('port_from', 0\)(?!\.has\('port_to', 0\))/);
    }
  );

  it.each([
    // EC2.53 and EC2.54 are worded identically apart from the address family,
    // so both cover 22 and 3389. 5.2 checked only SSH until RDP was folded in.
    ['5.2', "has('cidr_block', '0.0.0.0/0')", [22, 3389]],
    ['5.3', "has('cidr_block', '::/0')", [22, 3389]],
  ] as const)('%s targets its own address family and ports', async (controlId, cidr, ports) => {
    const query = await queryFor(controlId);

    expect(query).toContain(cidr);
    for (const port of ports) {
      expect(query).toContain(`has('port_from', lte(${port})).has('port_to', gte(${port}))`);
    }
  });

  // 5.3 is the IPv6 half of the split: EC2.53 is 0.0.0.0/0, EC2.54 is ::/0.
  // Widening 5.2 instead would report a benchmark result v3.0.0 does not define.
  it('5.2 and 5.3 do not overlap on address family', async () => {
    expect(await queryFor('5.2')).not.toContain('::/0');
    expect(await queryFor('5.3')).not.toContain('0.0.0.0/0');
  });
});

// The NACL controls were shipped with no query-level tests, so nothing checked
// that they would catch an exposed NACL or that they matched what EC2.21
// actually evaluates. These pin the three decisions that were wrong or missing.
describe('network ACL controls', () => {
  const NACL_CONTROLS = ['5.1', 'KH-5.1'] as const;

  // [NACL count, entry count]: the data-presence guard's two counts, by text.
  function client([acls, entries = acls]: number[]) {
    return graphStub({
      routes: {
        "g.V().hasLabel('NetworkAcl').count()": [acls],
        "g.V().hasLabel('NetworkAclEntry').count()": [entries],
      },
    });
  }

  // Gremlin is formatted for reading, so assertions must not depend on where
  // the line breaks fall. Squashing runs of whitespace lets a reflow of the
  // query pass while a real change to it still fails.
  const flat = (query: string) => query.replace(/\s+/g, ' ').trim();

  const lastQuery = (graphClient: { executeQuery: jest.Mock }) =>
    flat(graphClient.executeQuery.mock.calls.at(-1)![0] as string);

  const startsAt = (query: string, label: string) => query.startsWith(`g.V().hasLabel('${label}')`);

  // The data-presence guard sees NACLs with entries, so it passes through to the
  // control's own query, which finds `findingCount` violations.
  function ready(findingCount: number) {
    return graphStub({
      count: findingCount,
      routes: {
        "g.V().hasLabel('NetworkAcl').count()": [4],
        "g.V().hasLabel('NetworkAclEntry').count()": [12],
      },
    });
  }

  it.each(NACL_CONTROLS)(
    '%s reports NOT_EVALUATED when NACLs exist but their entries do not',
    async (controlId) => {
      const graphClient = client([4, 0]);

      const result = await getEvaluatorForControl(controlId)!.evaluate(graphClient);

      expect(result.status).toBe('NOT_EVALUATED');
      expect(result.issues).toEqual([]);
      // It must not have run its own query on absent data.
      expect(graphClient.executeQuery).toHaveBeenCalledTimes(2);
    }
  );

  it.each(NACL_CONTROLS)('%s passes when no NACLs are collected at all', async (controlId) => {
    const graphClient = client([0]);

    const result = await getEvaluatorForControl(controlId)!.evaluate(graphClient);

    expect(result.status).toBe('PASS');
  });

  it.each(NACL_CONTROLS)('%s fails on a non-zero count once entries exist', async (controlId) => {
    const result = await getEvaluatorForControl(controlId)!.evaluate(ready(3));

    expect(result.status).toBe('FAIL');
    expect(result.issues).toHaveLength(1);
    expect(result.evidence[0].controlId).toBe(controlId);
  });

  // The Khalifa controls filter to NACLs a subnet actually uses: without it a
  // default NACL, which cannot be deleted and allows all traffic, would flag
  // every VPC forever with no remediation that could clear it.
  it.each(['KH-5.1'])('%s only counts NACLs a subnet actually uses', async (controlId) => {
    const graphClient = ready(0);

    await getEvaluatorForControl(controlId)!.evaluate(graphClient);

    const query = lastQuery(graphClient);
    expect(query).toContain("where(outE('ASSOCIATED_WITH'))");
  });

  // 5.1 deliberately does not. EC2.21 evaluates every NACL as a standalone
  // resource, and a CIS-numbered control has to reconcile against Security Hub
  // -- filtering here would let it PASS where Security Hub FAILs.
  it('5.1 counts every NACL, associated or not, to stay level with EC2.21', async () => {
    const graphClient = ready(0);

    await getEvaluatorForControl('5.1')!.evaluate(graphClient);

    const query = lastQuery(graphClient);
    expect(query).not.toContain('ASSOCIATED_WITH');
  });

  // EC2.21 "doesn't generate findings for a default network ACL", which allows
  // all traffic out of the box (benchmarks/cis-aws-foundations-3.0.0, ec2-controls).
  it('5.1 excludes default NACLs, as EC2.21 does', async () => {
    const graphClient = ready(0);

    await getEvaluatorForControl('5.1')!.evaluate(graphClient);

    expect(lastQuery(graphClient)).toContain(
      "hasLabel('NetworkAcl') .not(has('is_default', true))"
    );
  });

  // Both of these assert a rule rather than one spelling of the query, so the
  // cleaner rewrite -- start at NetworkAcl and filter, which needs no dedup --
  // satisfies them too. A test that demanded the current shape would reject
  // that refactor, which is why neither hardcodes the traversal.

  it.each(NACL_CONTROLS)(
    '%s does not double-count a NACL with several matching rules',
    async (controlId) => {
      const graphClient = ready(0);

      await getEvaluatorForControl(controlId)!.evaluate(graphClient);

      const query = lastQuery(graphClient);
      // Walking up from entries is many-to-one: one NACL with an open port-22
      // rule and an open port-3389 rule is reached twice, and counted twice.
      if (startsAt(query, 'NetworkAclEntry')) {
        expect(query).toMatch(/dedup\(\)[\s\S]*count\(\)/);
      }
    }
  );

  it.each(NACL_CONTROLS)(
    '%s walks PART_OF in the direction its start implies',
    async (controlId) => {
      const graphClient = ready(0);

      await getEvaluatorForControl(controlId)!.evaluate(graphClient);

      const query = lastQuery(graphClient);
      // PART_OF points from a rule to its NACL. Traversed the wrong way the
      // query matches nothing, the count is zero and the control reports PASS
      // forever -- the silent green that NOT_EVALUATED cannot catch, because the
      // entries do exist and only the traversal is wrong.
      if (startsAt(query, 'NetworkAclEntry')) {
        expect(query).toContain("out('PART_OF')");
        expect(query).not.toContain("in('PART_OF')");
      } else {
        expect(query).toContain("in('PART_OF')");
        expect(query).not.toContain("out('PART_OF')");
      }
    }
  );

  it.each(NACL_CONTROLS)('%s counts only allow-ingress entries', async (controlId) => {
    const graphClient = ready(0);

    await getEvaluatorForControl(controlId)!.evaluate(graphClient);

    const query = lastQuery(graphClient);
    expect(query).toContain("has('direction', 'ingress')");
    expect(query).toContain("has('rule_action', 'allow')");
  });

  // EC2.21's page says TCP, but the Config rule it runs on
  // (nacl-no-unrestricted-ssh-rdp) flags "TCP or UDP"; RDP really does run over
  // UDP 3389, so tcp-only would pass a NACL that Security Hub fails.
  it.each(['5.1'])('%s matches UDP as well as TCP', async (controlId) => {
    const graphClient = ready(0);

    await getEvaluatorForControl(controlId)!.evaluate(graphClient);

    const query = lastQuery(graphClient);
    expect(query).toContain("within('tcp', 'udp', '-1')");
  });

  it('KH-5.1 stays TCP-only, since these database ports are not UDP services', async () => {
    const graphClient = ready(0);

    await getEvaluatorForControl('KH-5.1')!.evaluate(graphClient);

    const query = lastQuery(graphClient);
    // Positive first: a bare not.toContain would also pass on an empty or
    // broken query, which is the wrong reason to be green.
    expect(query).toContain("has('protocol', within(");
    expect(query).not.toContain("'udp'");
  });

  it.each([
    // EC2.21: '0.0.0.0/0' or '::/0'. The ::/0 half used to be KH-5.3.
    ['5.1', "has('cidr_block', within('0.0.0.0/0', '::/0'))", [22, 3389]],
    ['KH-5.1', "has('cidr_block', within('0.0.0.0/0', '::/0'))", [1433, 3306, 5432]],
  ] as const)('%s targets its own address family and ports', async (controlId, cidr, ports) => {
    const graphClient = ready(0);

    await getEvaluatorForControl(controlId)!.evaluate(graphClient);

    const query = lastQuery(graphClient);
    expect(query).toContain(cidr);
    for (const port of ports) {
      expect(query).toContain(`has('port_from', lte(${port})).has('port_to', gte(${port}))`);
    }
    // Protocol -1 carries no PortRange, which the collector records as 0-0.
    expect(query).toContain("has('port_from', 0).has('port_to', 0)");
  });
});

// Four controls that already had a risk rule reading the same property, but no
// evaluator -- so Khalifa raised the finding while the compliance page said
// "Not evaluated".
describe('controls backfilled from existing rules', () => {
  const flat = (q: string) => q.replace(/\s+/g, ' ').trim();

  async function queryFor(controlId: string) {
    const graphClient = graphStub();
    const result = await getEvaluatorForControl(controlId)!.evaluate(graphClient);
    return { query: flat(graphClient.executeQuery.mock.calls.at(-1)![0] as string), result };
  }

  it.each([
    // Per account/region: the compliant set is the ACTIVE analyzers.
    ['1.20', "hasLabel('AccessAnalyzer')", "has('status', 'ACTIVE')"],
    ['3.6', "hasLabel('KmsKey')", "has('rotation_enabled', false)"],
    ['5.6', "hasLabel('Ec2Instance')", "has('metadata_http_tokens', 'optional')"],
    ['KH-5.7', "hasLabel('Vpc')", "out('HAS_ENDPOINT')"],
  ])('%s targets the right label and predicate', async (controlId, label, predicate) => {
    const { query } = await queryFor(controlId);

    expect(query).toContain(label);
    expect(query).toContain(predicate);
  });

  // AWS-managed keys rotate on their own schedule and a pending-deletion key
  // cannot be remediated; counting either would produce findings nobody can act
  // on. RULE-026 scopes the same way.
  it('3.6 counts only customer-managed, enabled keys', async () => {
    const { query } = await queryFor('3.6');

    expect(query).toContain("has('key_manager', 'CUSTOMER')");
    expect(query).toContain("has('key_state', 'Enabled')");
  });

  // RULE-024 fires only when an IMDSv1 instance also holds an IAM role, because
  // that is what makes SSRF profitable. The control asks whether IMDSv2 is
  // enforced at all, so it must not inherit that narrowing.
  it('5.6 counts every IMDSv1 instance, not just role-holding ones', async () => {
    const { query } = await queryFor('5.6');

    expect(query).not.toContain('HAS_IAM_ROLE');
  });

  it.each(['3.6', '5.6', 'KH-5.7'])('%s passes on a zero count', async (controlId) => {
    const { result } = await queryFor(controlId);

    expect(result.status).toBe('PASS');
    expect(result.issues).toEqual([]);
    expect(result.evidence[0].controlId).toBe(controlId);
  });

  // The collector emits no synthetic MISSING vertex for Access Analyzer the way
  // it does for GuardDuty, so an account with none at all yields zero vertices.
  // Counting only non-ACTIVE analyzers would report PASS for exactly the state
  // 1.20 forbids. RULE-025 has that gap.
  it('1.20 fails an account/region with no ACTIVE analyzer', async () => {
    // Collected (coverage) but no ACTIVE analyzer there.
    const graphClient = graphStub({ failing: false });

    const result = await getEvaluatorForControl('1.20')!.evaluate(graphClient);

    expect(result.status).toBe('FAIL');
    expect(result.issues[0]).toContain('no ACTIVE IAM Access Analyzer');
    expect(result.evidence[0].details.failingAccountRegions).toEqual([`${ACCOUNT} us-west-2`]);
  });

  it('1.20 passes an account/region with an ACTIVE analyzer', async () => {
    // The regional read returns the pair: here, the ACTIVE analyzer's.
    const graphClient = graphStub({ failing: true });

    const result = await getEvaluatorForControl('1.20')!.evaluate(graphClient);

    expect(result.status).toBe('PASS');
    expect(result.evidence[0].details).toMatchObject({
      accountRegionsAssessed: 1,
      accountRegionsFailing: 0,
    });
  });

  // A key whose rotation status could not be read has no rotation_enabled
  // property at all -- normalizeProperties drops undefined. Matching only
  // false would count it as compliant.
  it('3.6 counts keys whose rotation status is unreadable, not just false', async () => {
    const { query } = await queryFor('3.6');

    expect(query).toContain("hasNot('rotation_enabled')");
  });

  // DescribeInstances is called unfiltered, so terminated instances linger in
  // the graph. Counting them reports a violation nobody can remediate.
  it('5.6 excludes terminated instances', async () => {
    const { query } = await queryFor('5.6');

    expect(query).toContain("not(has('state', within('terminated', 'shutting-down')))");
  });
});

// Section 2 storage controls. Every property here is a plain boolean lifted from
// an optional field in the AWS response, so each can be absent rather than
// false -- normalizeProperties drops undefined. Matching false alone would count
// a resource we could not assess as compliant, which is how 3.6 was wrong.
describe('storage encryption controls (KHALIFA_BASELINE)', () => {
  const flat = (q: string) => q.replace(/\s+/g, ' ').trim();

  async function queryFor(controlId: string) {
    const graphClient = graphStub();
    const result = await getEvaluatorForControl(controlId)!.evaluate(graphClient);
    return { query: flat(graphClient.executeQuery.mock.calls.at(-1)![0] as string), result };
  }

  it.each([
    ['KH-2.11', 'RedshiftCluster', 'encrypted'],
    ['KH-2.12', 'RedshiftCluster', 'publicly_accessible'],
    ['KH-2.14', 'OpenSearchDomain', 'encryption_at_rest'],
    ['KH-2.15', 'OpenSearchDomain', 'enforce_https'],
    ['KH-2.16', 'OpenSearchDomain', 'node_to_node_encryption'],
  ])('%s reads %s.%s', async (controlId, label, prop) => {
    const { query } = await queryFor(controlId);

    expect(query).toContain(`hasLabel('${label}')`);
    expect(query).toContain(`'${prop}'`);
  });

  it.each(['KH-2.11', 'KH-2.12', 'KH-2.13', 'KH-2.14', 'KH-2.15', 'KH-2.16'])(
    '%s treats an absent property as a failure, not a pass',
    async (controlId) => {
      const { query } = await queryFor(controlId);

      expect(query).toContain('hasNot(');
    }
  );

  // 2.12 is the odd one: every other control here fails on false, but a cluster
  // is exposed when publicly_accessible is TRUE.
  it('KH-2.12 counts publicly accessible clusters, not private ones', async () => {
    const { query } = await queryFor('KH-2.12');

    expect(query).toContain("has('publicly_accessible', true)");
    expect(query).not.toContain("has('publicly_accessible', false)");
  });

  it('KH-2.13 checks transit and at-rest encryption', async () => {
    const { query } = await queryFor('KH-2.13');

    expect(query).toContain("has('transit_encryption', false)");
    expect(query).toContain("has('at_rest_encryption', false)");
  });

  // Memcached cannot do at-rest encryption at all, so hasNot would flag every
  // memcached cluster permanently with no remediation available -- the same
  // error as counting terminated EC2 instances in 5.6.
  it('KH-2.13 only assesses engines that can be encrypted', async () => {
    const { query } = await queryFor('KH-2.13');

    expect(query).toContain("has('engine', within('redis', 'valkey'))");
  });

  it.each(['KH-2.11', 'KH-2.12', 'KH-2.13'])(
    '%s excludes clusters mid-create or mid-delete',
    async (controlId) => {
      const { query } = await queryFor(controlId);

      expect(query).toContain("not(has('status', within('deleting', 'creating')))");
    }
  );

  // v3.0.0 section 2 ends at 2.9 and names none of these services, so these
  // controls carry KH- ids. A CIS-numbered control the benchmark does not
  // define is worse for an audit than no control at all.
  it('these controls are not claimed as CIS', () => {
    for (const id of ['KH-2.10', 'KH-2.11', 'KH-2.13', 'KH-2.16']) {
      expect(getControlById(id, 'KHALIFA_BASELINE')).toBeDefined();
    }
    // The bare ids must not reappear under CIS: v3.0.0 section 2 ends at 2.9.
    for (const id of ['2.10', '2.11', '2.13', '2.16']) {
      expect(getControlById(id, 'CIS_AWS_FOUNDATIONS')).toBeUndefined();
    }
  });

  it.each(['KH-2.11', 'KH-2.12', 'KH-2.13', 'KH-2.14', 'KH-2.15', 'KH-2.16'])(
    '%s passes on a zero count',
    async (controlId) => {
      const { result } = await queryFor(controlId);

      expect(result.status).toBe('PASS');
      expect(result.evidence[0].controlId).toBe(controlId);
    }
  );
});

// Every id in CIS_AWS_FOUNDATIONS must be a real v3.0.0 requirement. The
// catalogue previously carried 19 that were not: fabricated section 2 ids for
// services the benchmark never mentions, GuardDuty and Security Hub findings,
// and a section 4 shifted two places so every alarm control sat at the wrong
// number. Showing an auditor a CIS id the benchmark does not define, or defines
// as something else, is worse than having no control at all.
describe('CIS catalogue matches v3.0.0', () => {
  // CIS AWS Foundations Benchmark v3.0.0, all 62 requirements.
  const V3 = new Set([
    '1.1',
    '1.2',
    '1.3',
    '1.4',
    '1.5',
    '1.6',
    '1.7',
    '1.8',
    '1.9',
    '1.10',
    '1.11',
    '1.12',
    '1.13',
    '1.14',
    '1.15',
    '1.16',
    '1.17',
    '1.18',
    '1.19',
    '1.20',
    '1.21',
    '1.22',
    '2.1.1',
    '2.1.2',
    '2.1.3',
    '2.1.4',
    '2.2.1',
    '2.3.1',
    '2.3.2',
    '2.3.3',
    '2.4.1',
    '3.1',
    '3.2',
    '3.3',
    '3.4',
    '3.5',
    '3.6',
    '3.7',
    '3.8',
    '3.9',
    '4.1',
    '4.2',
    '4.3',
    '4.4',
    '4.5',
    '4.6',
    '4.7',
    '4.8',
    '4.9',
    '4.10',
    '4.11',
    '4.12',
    '4.13',
    '4.14',
    '4.15',
    '4.16',
    '5.1',
    '5.2',
    '5.3',
    '5.4',
    '5.5',
    '5.6',
  ]);

  it('every CIS control id is a v3.0.0 requirement', () => {
    const strays = getControlsByFramework('CIS_AWS_FOUNDATIONS')
      .map((c) => c.id)
      .filter((id) => !V3.has(id));

    expect(strays).toEqual([]);
  });

  it('section 4 alarm controls sit at their real numbers', () => {
    const byId = (id: string) => getControlById(id, 'CIS_AWS_FOUNDATIONS')?.title ?? '';

    // These four were at 4.3, 4.5, 4.6 and 4.8 before the shift was corrected.
    expect(byId('4.1')).toMatch(/unauthorized API/i);
    expect(byId('4.3')).toMatch(/root account/i);
    expect(byId('4.4')).toMatch(/IAM policy/i);
    expect(byId('4.14')).toMatch(/VPC changes/i);
    // Security Hub enablement is requirement 4.16, not a Khalifa invention.
    expect(byId('4.16')).toMatch(/Security Hub/i);
  });
});

// Both of these join across labels on a bucket name, because a trail and a
// Config delivery channel record their bucket as a string rather than an edge.
describe('bucket-name join controls', () => {
  const flat = (q: string) => q.replace(/\s+/g, ' ').trim();
  async function queryFor(controlId: string) {
    const graphClient = graphStub();
    const result = await getEvaluatorForControl(controlId)!.evaluate(graphClient);
    return { query: flat(graphClient.executeQuery.mock.calls.at(-1)![0] as string), result };
  }

  it.each([
    ['3.4', 'CloudTrail', 'logging_enabled'],
    ['KH-3.11', 'ConfigDeliveryChannel', 'default_encryption'],
  ])('%s joins %s.s3_bucket_name to S3Bucket.name', async (controlId, label, prop) => {
    const { query } = await queryFor(controlId);

    expect(query).toContain(`hasLabel('${label}')`);
    expect(query).toContain("values('s3_bucket_name')");
    // The join is what stops this counting every bucket in the account.
    expect(query).toContain("by('name')");
    expect(query).toContain(`has('${prop}', false)`);
    expect(query).toContain(`hasNot('${prop}')`);
  });
});

// Controls whose rule already fires on the same condition, so the page said
// "Not evaluated" for something Khalifa was reporting in the issues list.
describe('Khalifa Baseline controls backfilled from rules', () => {
  const flat = (q: string) => q.replace(/\s+/g, ' ').trim();
  async function queryFor(controlId: string) {
    const graphClient = { executeQuery: jest.fn(async (_q: string) => [0]) };
    await getEvaluatorForControl(controlId)!.evaluate(graphClient);
    return flat(graphClient.executeQuery.mock.calls.at(-1)![0] as string);
  }

  it.each([
    ['KH-EKS-1', "hasLabel('EksCluster')", "has('endpoint_world_open', true)"],
    ['KH-SEC-1', "hasLabel('IamPolicyStatement')", "has('secret_grant_scope', 'wildcard')"],
    ['KH-SEC-2', "hasLabel('DataClassificationFinding')", "has('secret_count', gt(0))"],
    ['KH-PATH-1', "hasLabel('Internet')", "has('crown_jewel', true)"],
  ])('%s targets the right label and predicate', async (controlId, label, predicate) => {
    const query = await queryFor(controlId);

    expect(query).toContain(label);
    expect(query).toContain(predicate);
  });

  // 22 and 3389 belong to CIS 5.2 and 5.3. Repeating them here would report the
  // same security group twice across two frameworks.
  it('KH-5.6 covers the database and search ports, not the admin ports', async () => {
    const query = await queryFor('KH-5.6');

    for (const port of [1433, 3306, 5432, 6379, 9200, 27017]) {
      expect(query).toContain(`has('port_from', lte(${port}))`);
    }
    expect(query).not.toContain('lte(22)');
    expect(query).not.toContain('lte(3389)');
  });

  // simplePath is what stops a cyclic graph looping forever.
  it('KH-PATH-1 bounds its traversal', async () => {
    const query = await queryFor('KH-PATH-1');

    expect(query).toContain('simplePath()');
    expect(query).toContain('loops().is(4)');
  });
});

// Tier 1: controls unlocked by keeping data the collector already fetched and
// discarded, plus AWS-managed policy vertices so their attachments land.
describe('Tier 1 collector-backed controls', () => {
  const flat = (q: string) => q.replace(/\s+/g, ' ').trim();
  // Each call returns the next queued result, then repeats the last one.
  function queued(results: unknown[][]) {
    let i = 0;
    return {
      executeQuery: jest.fn(async (_q: string) => results[Math.min(i++, results.length - 1)]),
    };
  }
  const lastQuery = (g: { executeQuery: jest.Mock }) =>
    flat(g.executeQuery.mock.calls.at(-1)![0] as string);

  // Vertices from a collector that predates the property carry no value for it.
  // Reading that as false would FAIL every control the moment this deploys.
  it.each([
    ['2.1.2', [[5], [0]]],
    ['2.3.2', [[5], [0]]],
    ['3.8', [[5], [0]]],
    ['3.9', [[5], [0]]],
    ['KH-3.10', [[5], [0]]],
  ])('%s reports NOT_EVALUATED until the property has been collected', async (id, results) => {
    const result = await getEvaluatorForControl(id)!.evaluate(queued(results));

    expect(result.status).toBe('NOT_EVALUATED');
  });

  it.each(['1.17', '1.22'])(
    '%s reports NOT_EVALUATED until AWS-managed policy vertices exist',
    async (id) => {
      const result = await getEvaluatorForControl(id)!.evaluate(queued([[0]]));

      expect(result.status).toBe('NOT_EVALUATED');
    }
  );

  // MFA Delete only exists on versioned buckets; S3.20 scopes the same way.
  it('2.1.2 assesses versioned buckets only', async () => {
    const g = graphStub();
    await getEvaluatorForControl('2.1.2')!.evaluate(g);

    expect(queryWith(g, "has('versioning_enabled', true)")).toContain(
      "hasNot('mfa_delete_enabled')"
    );
  });

  // S3.22 and S3.23 want a multi-Region trail. A single-Region trail logging
  // every bucket still leaves other Regions unlogged.
  it.each([
    ['3.8', 'logs_all_s3_object_writes'],
    ['3.9', 'logs_all_s3_object_reads'],
  ])('%s is per account: fails the account its trails do not cover', async (id, prop) => {
    // guard total, guard with property, assessed accounts, org trails, covered accounts
    const g = queued([[2], [2], ['111111111111', '222222222222'], [0], ['111111111111']]);
    const result = await getEvaluatorForControl(id)!.evaluate(g);

    expect(lastQuery(g)).toContain("has('is_multi_region_trail', true)");
    expect(lastQuery(g)).toContain(`has('${prop}', true)`);
    expect(result.status).toBe('FAIL');
    expect(result.evidence[0].details.failingAccounts).toEqual(['222222222222']);
  });

  // An organization trail is one vertex for every member, so a qualifying one
  // covers all accounts rather than whichever account wrote it last.
  it.each(['3.8', '3.9'])(
    '%s passes every account off a qualifying organization trail',
    async (id) => {
      const g = queued([[2], [2], ['111111111111', '222222222222'], [1]]);
      const result = await getEvaluatorForControl(id)!.evaluate(g);

      expect(result.status).toBe('PASS');
      expect(g.executeQuery).toHaveBeenCalledTimes(4);
    }
  );

  // IAM.18 is per account: one account's support role says nothing about
  // another's, so a graph-wide "any role anywhere" check would pass every
  // account off one.
  it('1.17 fails each account without a support role, not the graph as a whole', async () => {
    const g = graphStub({
      routes: {
        "has('policy_type', 'aws-managed').count()": [3],
        "hasLabel('CollectionCoverage')": ['111111111111', '222222222222'],
        AWSSupportAccess: ['111111111111'],
      },
    });

    const result = await getEvaluatorForControl('1.17')!.evaluate(g);

    expect(result.status).toBe('FAIL');
    expect(result.evidence[0].details).toMatchObject({
      accountsAssessed: 2,
      failingAccounts: ['222222222222'],
    });
    // IAM.18's policyUsageType is ANY: the policy attached to a user, group or
    // role satisfies it (benchmarks/cis-aws-foundations-3.0.0, iam-controls IAM.18).
    expect(queryWith(g, 'AWSSupportAccess')).toContain(
      "hasLabel(within('IamRole', 'IamUser', 'IamGroup'))"
    );
  });

  it('1.17 rejects a malformed account id rather than treating it as absent', async () => {
    const g = queued([[3], ['not-an-account']]);

    await expect(getEvaluatorForControl('1.17')!.evaluate(g)).rejects.toThrow('invalid account id');
  });

  it('1.22 checks users, roles and groups', async () => {
    const g = graphStub({ routes: { "has('policy_type', 'aws-managed').count()": [3] } });
    await getEvaluatorForControl('1.22')!.evaluate(g);

    expect(queryWith(g, 'AWSCloudShellFullAccess')).toContain(
      "within('IamUser', 'IamRole', 'IamGroup')"
    );
  });
});

// Two controls that reported PASS off data that could never match.
describe('false PASS fixes', () => {
  const flat = (q: string) => q.replace(/\s+/g, ' ').trim();
  function queued(results: unknown[][]) {
    let i = 0;
    return {
      executeQuery: jest.fn(async (_q: string) => results[Math.min(i++, results.length - 1)]),
    };
  }

  // DescribeTrails omits the log group ARN when there is none, and
  // normalizeProperties drops undefined, so it is absent -- never ''.
  it('KH-3.4 counts a trail with no log group property at all', async () => {
    const g = queued([[0]]);
    await getEvaluatorForControl('KH-3.4')!.evaluate(g);

    expect(flat(g.executeQuery.mock.calls[0][0] as string)).toContain(
      "hasNot('cloudwatch_logs_log_group_arn')"
    );
  });

  // The collector links every user policy with ATTACHED_TO; HAS_INLINE_POLICY
  // was never written, so the old query could only ever count zero.
  it('1.15 walks the edge the collector actually writes', async () => {
    const g = graphStub({ routes: { "has('policy_type', 'aws-managed').count()": [3] } });
    await getEvaluatorForControl('1.15')!.evaluate(g);
    const query = queryWith(g, "hasLabel('IamUser')");

    expect(query).toContain("where(out('ATTACHED_TO'))");
    expect(query).not.toContain('HAS_INLINE_POLICY');
  });

  it('1.15 fails each account with a directly attached policy', async () => {
    const g = graphStub({ count: 2, routes: { "has('policy_type', 'aws-managed').count()": [3] } });
    const result = await getEvaluatorForControl('1.15')!.evaluate(g);

    expect(result.status).toBe('FAIL');
    expect(result.evidence[0].details).toMatchObject({
      failingAccounts: [ACCOUNT],
      violations: 2,
    });
  });

  // Per account, the guard comes first: an account with no edge found may
  // still have a direct AWS-managed attachment, so even a violation elsewhere
  // does not make the other accounts' zeros trustworthy.
  it('1.15 reports NOT_EVALUATED before AWS-managed vertices exist, even with violations', async () => {
    const g = graphStub({ count: 2, routes: { "has('policy_type', 'aws-managed').count()": [0] } });
    const result = await getEvaluatorForControl('1.15')!.evaluate(g);

    expect(result.status).toBe('NOT_EVALUATED');
  });

  // A zero is only trustworthy once AWS-managed attachments can land.
  it('1.15 reports NOT_EVALUATED for zero until AWS-managed vertices exist', async () => {
    const result = await getEvaluatorForControl('1.15')!.evaluate(queued([[0], [0]]));

    expect(result.status).toBe('NOT_EVALUATED');
  });

  it('1.15 carries the v3.0.0 title, and the duplicate KH-3.6 is gone', () => {
    expect(getControlById('1.15', 'CIS_AWS_FOUNDATIONS')?.title).toBe(
      'Ensure IAM Users Receive Permissions Only Through Groups'
    );
    expect(getControlById('KH-3.6', 'KHALIFA_BASELINE')).toBeUndefined();
  });

  // Exact duplicates of a CIS control report every failure twice.
  it.each([
    ['KH-5.4', '3.7'],
    ['KH-1.20', '1.15'],
  ])('%s is removed as a duplicate of %s', (removed, kept) => {
    expect(getControlById(removed, 'KHALIFA_BASELINE')).toBeUndefined();
    expect(getControlById(kept, 'CIS_AWS_FOUNDATIONS')).toBeDefined();
    expect(LEGACY_CONTROL_IDS.REMOVED[removed]).toBe(kept);
  });
});

// The old->new table used to be a comment, and it went stale unnoticed when 19
// controls moved. As data, every target must resolve, so a later removal that
// would orphan an old evidence id fails here instead.
describe('LEGACY_CONTROL_IDS', () => {
  const current = new Set(getAllControls().map((c) => c.id));

  it.each([
    ...Object.entries(LEGACY_CONTROL_IDS.V1_49),
    ...Object.entries(LEGACY_CONTROL_IDS.REMOVED),
  ])('%s maps to %s, which exists', (_old, target) => {
    expect(current.has(target)).toBe(true);
  });

  it('no removed id is still a current control', () => {
    for (const removed of Object.keys(LEGACY_CONTROL_IDS.REMOVED)) {
      expect(current.has(removed)).toBe(false);
    }
  });
});

// CIS 2.1.4 is the Block Public Access settings, met at bucket or account level.
// It previously counted public buckets, so a bucket with BPA off passed.
describe('2.1.4 Block Public Access', () => {
  function queued(results: unknown[][]) {
    let i = 0;
    return {
      executeQuery: jest.fn(async (_q: string) => results[Math.min(i++, results.length - 1)]),
    };
  }
  const evaluate = (results: unknown[][]) =>
    getEvaluatorForControl('2.1.4')!.evaluate(queued(results));

  // Order: guard total, guard with-property, total, fully blocked.
  it('passes when every bucket has all four bucket-level settings on', async () => {
    const result = await evaluate([[4], [4], [4], [4]]);

    expect(result.status).toBe('PASS');
    expect(result.evidence[0].details).toEqual({ buckets: 4, bucketsWithFullBlockPublicAccess: 4 });
  });

  // Account-level BPA is not collected, so the bucket may be covered by it.
  it('reports NOT_EVALUATED, not FAIL, for a bucket without full bucket-level BPA', async () => {
    const result = await evaluate([[4], [4], [4], [3]]);

    expect(result.status).toBe('NOT_EVALUATED');
    expect(result.evidence[0].details.reason).toMatch(/^1 of 4 S3 buckets/);
  });

  it('reports NOT_EVALUATED before the settings have been collected', async () => {
    const g = queued([[4], [0]]);
    const result = await getEvaluatorForControl('2.1.4')!.evaluate(g);

    expect(result.status).toBe('NOT_EVALUATED');
    expect(g.executeQuery).toHaveBeenCalledTimes(2);
  });

  it('no longer reads is_publicly_accessible', async () => {
    const g = queued([[4], [4], [4], [4]]);
    await getEvaluatorForControl('2.1.4')!.evaluate(g);

    for (const [q] of g.executeQuery.mock.calls) expect(q).not.toContain('is_publicly_accessible');
  });

  it('carries the v3.0.0 title', () => {
    expect(getControlById('2.1.4', 'CIS_AWS_FOUNDATIONS')?.title).toBe(
      "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'"
    );
  });
});

describe('REGIONAL_CONTROL_IDS', () => {
  it('names only controls that exist', () => {
    const ids = new Set(getAllControls().map((c) => c.id));
    expect([...REGIONAL_CONTROL_IDS].filter((id) => !ids.has(id))).toEqual([]);
  });

  // Per Region or per VPC in the Security Hub source of truth: IAM.28, EC2.7,
  // Config.1, EC2.6, EC2.2.
  it.each(['1.20', '2.2.1', '3.3', '3.7', '5.4'])('includes %s', (id) => {
    expect(REGIONAL_CONTROL_IDS.has(id)).toBe(true);
  });

  // A multi-region trail is visible from any one region; IAM and S3 are global.
  it.each(['3.1', '3.2', '1.12', '1.19', '2.1.4'])('excludes %s', (id) => {
    expect(REGIONAL_CONTROL_IDS.has(id)).toBe(false);
  });
});

// KH-5.3 existed because EC2.21 was believed to be IPv4-only. It is not, so
// 5.1 covers ::/0 and stored KH-5.3 rows resolve to it.
describe('KH-5.3 removal', () => {
  it('is gone, and its stored results resolve to 5.1', () => {
    expect(getControlById('KH-5.3', 'KHALIFA_BASELINE')).toBeUndefined();
    expect(getEvaluatorForControl('KH-5.3')).toBeUndefined();
    expect(LEGACY_CONTROL_IDS.REMOVED['KH-5.3']).toBe('5.1');
  });
});

// EC2.2: a default security group fails if it allows inbound or outbound
// traffic, including the rules every default group is created with.
describe('5.4 default security group', () => {
  function queued(results: unknown[][]) {
    let i = 0;
    return {
      executeQuery: jest.fn(async (_q: string) => results[Math.min(i++, results.length - 1)]),
    };
  }

  it('reports NOT_EVALUATED until rule counts are collected', async () => {
    const result = await getEvaluatorForControl('5.4')!.evaluate(queued([[5], [0]]));
    expect(result.status).toBe('NOT_EVALUATED');
  });

  it('fails default groups with inbound or outbound rules', async () => {
    const g = graphStub({ count: 2 });
    const result = await getEvaluatorForControl('5.4')!.evaluate(g);

    expect(result.status).toBe('FAIL');
    expect(queryWith(g, "has('is_default', true)")).toContain("has('egress_rule_count', gt(0))");
  });
});

// KMS.4 and EC2.6, per the source of truth's control pages.
describe('3.6 and 3.7 scope', () => {
  function queued(results: unknown[][]) {
    let i = 0;
    return {
      executeQuery: jest.fn(async (_q: string) => results[Math.min(i++, results.length - 1)]),
    };
  }

  it('3.6 counts only keys that can rotate', async () => {
    const g = graphStub();
    await getEvaluatorForControl('3.6')!.evaluate(g);
    const q = queryWith(g, "has('key_spec', 'SYMMETRIC_DEFAULT')");
    expect(q).toContain("has('origin', 'AWS_KMS')");
    expect(q).toContain("hasNot('custom_key_store_id')");
  });

  it('3.7 needs a flow log capturing rejected traffic', async () => {
    const g = graphStub({ count: 1 });
    const result = await getEvaluatorForControl('3.7')!.evaluate(g);
    expect(result.status).toBe('FAIL');
    expect(queryWith(g, "not(has('flow_logs_capture_rejects', true))")).toBeDefined();
  });

  it.each(['3.6', '3.7'])(
    '%s reports NOT_EVALUATED before the new properties are collected',
    async (id) => {
      const result = await getEvaluatorForControl(id)!.evaluate(queued([[3], [0]]));
      expect(result.status).toBe('NOT_EVALUATED');
    }
  );
});

// CIS v3.0.0 1.12: credentials unused for 45 days or greater are disabled,
// covering console passwords as well as access keys.
describe('1.12 unused credentials', () => {
  // Keys and passwords are one union, so an account fails on either.
  const run = async (count: number) => {
    const g = graphStub({ count });
    const result = await getEvaluatorForControl('1.12')!.evaluate(g);
    return { result, query: queryWith(g, "hasLabel('AccessKey')")! };
  };

  it('counts only active keys: a disabled key is what 1.12 asks for', async () => {
    const { query } = await run(0);
    expect(query).toContain("__.hasLabel('AccessKey').has('status', 'Active')");
  });

  it('checks console passwords, excluding the root row', async () => {
    const { query } = await run(0);
    expect(query).toContain("has('password_enabled', true)");
    expect(query).toContain("not(has('id', '<root_account>'))");
    expect(query).toContain("hasNot('password_last_used')");
  });

  it.each([
    [0, 'PASS'],
    [3, 'FAIL'],
  ])('%s unused credentials -> %s', async (count, status) => {
    const { result } = await run(count);
    expect(result.status).toBe(status);
    expect(result.evidence[0].details).toMatchObject({ violations: count });
  });

  it('names the 45-day threshold in the issue', async () => {
    const { result } = await run(3);
    expect(result.issues[0]).toContain('45+ days');
  });

  it('carries the v3.0.0 title', () => {
    expect(getControlById('1.12', 'CIS_AWS_FOUNDATIONS')?.title).toBe(
      'Ensure credentials unused for 45 days or greater are disabled'
    );
  });
});
