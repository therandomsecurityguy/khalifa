import {
  AGREEMENT_EPOCH,
  readSecurityHubCisFindings,
  reconcile,
  reconciliationSettingsFromEnv,
  runReconciliation,
  type ReconciliationRecord,
  type ShControlFinding,
} from './cis-reconciliation';
import type {
  ComplianceControlResult,
  ComplianceControlStatus,
  ComplianceReport,
} from './compliance-types';

const A = '111111111111';
const B = '222222222222';
const C = '333333333333';
const NOW = new Date('2026-11-20T00:00:00.000Z');
const config = { minAgreementDays: 5, allowlist: new Set(['1.5', '1.8', '3.3']) };

function result(
  id: string,
  status: ComplianceControlStatus,
  details: Record<string, unknown> = {}
): ComplianceControlResult {
  return {
    control: { id } as ComplianceControlResult['control'],
    status,
    evidence: [
      {
        controlId: id,
        resourceId: 'x',
        resourceType: 'x',
        status,
        details,
        collectedAt: NOW.toISOString(),
        collectedBy: 'compliance-engine',
      },
    ],
    issues: [],
    lastEvaluated: NOW.toISOString(),
  };
}

function report(...controls: ComplianceControlResult[]): ComplianceReport {
  return {
    framework: 'CIS_AWS_FOUNDATIONS',
    generatedAt: NOW.toISOString(),
    summary: {} as ComplianceReport['summary'],
    controls,
  };
}

const f = (controlId: string, accountId: string, status: string, region = 'us-west-2') => ({
  controlId,
  accountId,
  region,
  status,
});

const req = (record: ReconciliationRecord, id: string) =>
  record.requirements.find((r) => r.requirement === id)!;

describe('reconcile', () => {
  it('compares a per-account requirement account by account', () => {
    // 1.5 <- IAM.9. Khalifa assessed A, B, C and failed B.
    const r = report(result('1.5', 'FAIL', { assessedAccounts: [A, B, C], failingAccounts: [B] }));
    const findings = [
      f('IAM.9', A, 'PASSED'),
      f('IAM.9', B, 'PASSED'),
      f('IAM.9', C, 'NOT_AVAILABLE'),
    ];

    const out = req(reconcile(r, findings, null, config, NOW), '1.5');

    expect(out.khalifaScope).toBe('account');
    expect(out.counts).toMatchObject({ AGREE_PASS: 1, DISAGREE: 1, SH_NO_RESULT: 1 });
    expect(out.disagreements).toEqual([{ accountId: B, khalifa: 'FAIL', securityHub: 'PASSED' }]);
  });

  it('counts an account Security Hub checks but Khalifa did not assess', () => {
    const r = report(result('1.5', 'PASS', { assessedAccounts: [A], failingAccounts: [] }));

    const out = req(
      reconcile(r, [f('IAM.9', A, 'PASSED'), f('IAM.9', B, 'FAILED')], null, config, NOW),
      '1.5'
    );

    expect(out.counts).toMatchObject({ AGREE_PASS: 1, KHALIFA_NO_RESULT: 1, DISAGREE: 0 });
  });

  it('compares a per-account-region requirement per region', () => {
    // 3.3 <- Config.1.
    const r = report(
      result('3.3', 'FAIL', {
        assessedAccountRegions: [`${A} us-west-2`, `${A} us-east-1`],
        failingAccountRegions: [`${A} us-east-1`],
      })
    );
    const findings = [
      f('Config.1', A, 'PASSED', 'us-west-2'),
      f('Config.1', A, 'PASSED', 'us-east-1'),
    ];

    const out = req(reconcile(r, findings, null, config, NOW), '3.3');

    expect(out.khalifaScope).toBe('account-region');
    expect(out.counts).toMatchObject({ AGREE_PASS: 1, DISAGREE: 1 });
    expect(out.disagreements).toEqual([
      { accountId: A, region: 'us-east-1', khalifa: 'FAIL', securityHub: 'PASSED' },
    ]);
  });

  it('flags an org-wide PASS that Security Hub fails, but cannot check an org-wide FAIL', () => {
    const r = report(result('5.2', 'PASS', { groupsWithOpenAdminPorts: 0 }), result('5.3', 'FAIL'));
    const findings = [f('EC2.53', A, 'FAILED'), f('EC2.53', B, 'PASSED'), f('EC2.54', A, 'PASSED')];

    const out = reconcile(r, findings, null, config, NOW);

    expect(req(out, '5.2').khalifaScope).toBe('aggregate');
    expect(req(out, '5.2').counts).toMatchObject({ DISAGREE: 1, KHALIFA_AGGREGATE_ONLY: 1 });
    expect(req(out, '5.3').counts).toMatchObject({ KHALIFA_AGGREGATE_ONLY: 1, DISAGREE: 0 });
  });

  it('records no result when Khalifa did not evaluate the requirement', () => {
    const r = report(result('2.2.1', 'NOT_EVALUATED'));

    const out = req(reconcile(r, [f('EC2.7', A, 'FAILED')], null, config, NOW), '2.2.1');

    expect(out.khalifaScope).toBe('none');
    expect(out.counts.KHALIFA_NO_RESULT).toBe(1);
    expect(out.agreeingSince).toBeNull();
  });

  it('fails a requirement if any of its controls fails (2.1.4 <- S3.1, S3.8)', () => {
    const r = report(result('2.1.4', 'PASS', { assessedAccounts: [A], failingAccounts: [] }));

    const out = req(
      reconcile(r, [f('S3.1', A, 'PASSED'), f('S3.8', A, 'FAILED')], null, config, NOW),
      '2.1.4'
    );

    expect(out.securityHubControls).toEqual(['S3.1', 'S3.8']);
    expect(out.counts.DISAGREE).toBe(1);
  });

  it('ignores findings for controls outside CIS v3.0.0', () => {
    const r = report(result('1.5', 'PASS', { assessedAccounts: [A], failingAccounts: [] }));

    const out = reconcile(
      r,
      [f('Lambda.1', A, 'FAILED'), f('IAM.9', A, 'PASSED')],
      null,
      config,
      NOW
    );

    expect(req(out, '1.5').counts.AGREE_PASS).toBe(1);
  });
});

describe('agreement streak and publication gate', () => {
  const agreeing = report(result('1.5', 'PASS', { assessedAccounts: [A], failingAccounts: [] }));
  const findings = [f('IAM.9', A, 'PASSED')];

  function previous(
    since: string | null,
    status: 'OK' | 'STALE' = 'OK',
    generatedAt = '2026-11-19T20:00:00.000Z'
  ): ReconciliationRecord {
    return {
      framework: 'CIS_RECONCILIATION',
      generatedAt,
      status,
      khalifaReportGeneratedAt: null,
      minAgreementDays: 5,
      securityHubFindingsRead: 1,
      requirements: [
        // Security Hub passed 1.5, with no missing data, for as long as it agreed.
        {
          requirement: '1.5',
          agreeingSince: since,
          securityHubStatus: 'PASSED',
          stableSince: since,
        } as ReconciliationRecord['requirements'][0],
      ],
    };
  }

  it('starts a new agreement now', () => {
    const out = req(reconcile(agreeing, findings, null, config, NOW), '1.5');

    expect(out.agreeingSince).toBe(NOW.toISOString());
    expect(out.agreementDays).toBe(0);
    expect(out.publishable).toBe(false);
  });

  it('carries the start forward and publishes after minAgreementDays', () => {
    const out = req(
      reconcile(agreeing, findings, previous('2026-11-15T00:00:00.000Z'), config, NOW),
      '1.5'
    );

    expect(out.agreeingSince).toBe('2026-11-15T00:00:00.000Z');
    expect(out.agreementDays).toBe(5);
    expect(out.publishable).toBe(true);
  });

  it('is not publishable one day short', () => {
    const out = req(
      reconcile(agreeing, findings, previous('2026-11-16T00:00:00.000Z'), config, NOW),
      '1.5'
    );

    expect(out.agreementDays).toBe(4);
    expect(out.publishable).toBe(false);
  });

  it('never publishes a requirement off the allowlist', () => {
    const out = req(
      reconcile(
        agreeing,
        findings,
        previous('2026-11-01T00:00:00.000Z'),
        { ...config, allowlist: new Set() },
        NOW
      ),
      '1.5'
    );

    expect(out.agreementDays).toBe(19);
    expect(out.publishable).toBe(false);
  });

  it('resets agreement on a disagreement, and a Security Hub status change restarts stability', () => {
    const out = req(
      reconcile(
        agreeing,
        [f('IAM.9', A, 'FAILED')],
        previous('2026-11-01T00:00:00.000Z'),
        config,
        NOW
      ),
      '1.5'
    );

    expect(out.agreeingSince).toBeNull();
    expect(out.stableSince).toBe(NOW.toISOString());
    expect(out.publishable).toBe(false);
  });

  it('restarts after a STALE run rather than bridging the gap', () => {
    const out = req(
      reconcile(agreeing, findings, previous('2026-11-01T00:00:00.000Z', 'STALE'), config, NOW),
      '1.5'
    );

    expect(out.agreeingSince).toBe(NOW.toISOString());
  });

  it('restarts when the previous record is more than 6 hours old', () => {
    // Runs failed from 2026-11-14 to 2026-11-19 and left no records; nothing
    // was compared in between, so those days must not count as agreement.
    const out = req(
      reconcile(
        agreeing,
        findings,
        previous('2026-11-01T00:00:00.000Z', 'OK', '2026-11-19T17:59:59.999Z'),
        config,
        NOW
      ),
      '1.5'
    );

    expect(out.agreeingSince).toBe(NOW.toISOString());
    expect(out.agreementDays).toBe(0);
  });

  it('carries the start across a gap of exactly 6 hours', () => {
    const out = req(
      reconcile(
        agreeing,
        findings,
        previous('2026-11-15T00:00:00.000Z', 'OK', '2026-11-19T18:00:00.000Z'),
        config,
        NOW
      ),
      '1.5'
    );

    expect(out.agreeingSince).toBe('2026-11-15T00:00:00.000Z');
  });
});

describe('agreement epoch', () => {
  it('starts no agreement before the first record after the 2026-10-14 to 19 gap', () => {
    const r = report(result('1.8', 'FAIL', { assessedAccounts: [A], failingAccounts: [A] }));
    const previous: ReconciliationRecord = {
      framework: 'CIS_RECONCILIATION',
      generatedAt: '2026-10-21T13:15:00.000Z',
      status: 'OK',
      khalifaReportGeneratedAt: null,
      minAgreementDays: 5,
      securityHubFindingsRead: 1,
      requirements: [
        {
          requirement: '1.8',
          agreeingSince: '2026-10-09T23:30:49.946Z',
        } as ReconciliationRecord['requirements'][0],
      ],
    };

    const out = req(
      reconcile(
        r,
        [f('IAM.15', A, 'FAILED')],
        previous,
        config,
        new Date('2026-10-21T17:15:00.000Z')
      ),
      '1.8'
    );

    expect(out.agreeingSince).toBe(AGREEMENT_EPOCH);
    expect(out.agreementDays).toBe(1);
  });
});

describe("publication follows Security Hub's result", () => {
  const since = '2026-11-01T00:00:00.000Z';
  const previous = (securityHubStatus: 'PASSED' | 'FAILED'): ReconciliationRecord => ({
    framework: 'CIS_RECONCILIATION',
    generatedAt: '2026-11-19T20:00:00.000Z',
    status: 'OK',
    khalifaReportGeneratedAt: null,
    minAgreementDays: 5,
    securityHubFindingsRead: 1,
    requirements: [
      {
        requirement: '1.5',
        agreeingSince: null,
        securityHubStatus,
        stableSince: since,
      } as ReconciliationRecord['requirements'][0],
    ],
  });
  const khalifaFails = report(
    result('1.5', 'FAIL', { assessedAccounts: [A], failingAccounts: [A] })
  );

  it('publishes a stable Security Hub result even when Khalifa disagrees', () => {
    const out = req(
      reconcile(khalifaFails, [f('IAM.9', A, 'PASSED')], previous('PASSED'), config, NOW),
      '1.5'
    );

    expect(out.counts.DISAGREE).toBe(1);
    expect(out.securityHubStatus).toBe('PASSED');
    expect(out.stableSince).toBe(since);
    expect(out.publishable).toBe(true);
    expect(out.blockedBy).toEqual([]);
  });

  it('fails the requirement when any account or region fails', () => {
    const out = req(
      reconcile(
        khalifaFails,
        [f('IAM.9', A, 'PASSED'), f('IAM.9', B, 'FAILED', 'us-east-1')],
        previous('FAILED'),
        config,
        NOW
      ),
      '1.5'
    );

    expect(out.securityHubStatus).toBe('FAILED');
    expect(out.publishable).toBe(true);
  });

  it('blocks and restarts stability when Security Hub has no data somewhere', () => {
    const out = req(
      reconcile(
        khalifaFails,
        [f('IAM.9', A, 'PASSED'), f('IAM.9', B, 'NOT_AVAILABLE')],
        previous('PASSED'),
        config,
        NOW
      ),
      '1.5'
    );

    expect(out.securityHubNoData).toBe(1);
    expect(out.stableSince).toBeNull();
    expect(out.publishable).toBe(false);
    expect(out.blockedBy).toEqual(['SECURITY_HUB_NO_DATA']);
  });

  it('blocks a requirement Security Hub has no result for', () => {
    const out = req(reconcile(khalifaFails, [], null, config, NOW), '1.5');

    expect(out.securityHubStatus).toBeNull();
    expect(out.blockedBy).toEqual(['NO_SECURITY_HUB_RESULT']);
  });

  it('lists every reason, including NOT_ALLOWLISTED and a stability too short', () => {
    const out = req(
      reconcile(
        khalifaFails,
        [f('IAM.9', A, 'PASSED')],
        null,
        { ...config, allowlist: new Set() },
        NOW
      ),
      '1.5'
    );

    expect(out.blockedBy).toEqual(['NOT_ALLOWLISTED', 'NOT_STABLE_LONG_ENOUGH']);
  });
});

describe('Security Hub results that evaluated nothing (CONFIG_EVALUATIONS_EMPTY)', () => {
  // 3.3 <- Config.1, compared per account/region.
  const empty = (accountId: string, region: string) => ({
    ...f('Config.1', accountId, 'PASSED', region),
    evaluated: false,
  });
  const khalifa = (failing: string[]) =>
    report(
      result('3.3', failing.length ? 'FAIL' : 'PASS', {
        assessedAccountRegions: [`${A} us-west-2`, `${A} us-east-1`],
        failingAccountRegions: failing,
      })
    );

  it('is not a pass: compared as no result, and alone gives no Security Hub status', () => {
    const out = req(
      reconcile(khalifa([]), [empty(A, 'us-west-2'), empty(A, 'us-east-1')], null, config, NOW),
      '3.3'
    );

    expect(out.counts).toMatchObject({ AGREE_PASS: 0, SH_NO_RESULT: 2 });
    expect(out.securityHubStatus).toBeNull();
    expect(out.securityHubNotEvaluated).toBe(2);
    expect(out.khalifaFailuresFilled).toBe(0);
    expect(out.blockedBy).toEqual(['NO_SECURITY_HUB_RESULT']);
  });

  it('counts a Khalifa FAIL there as FAILED', () => {
    const out = req(
      reconcile(
        khalifa([`${A} us-east-1`]),
        [f('Config.1', A, 'PASSED', 'us-west-2'), empty(A, 'us-east-1')],
        null,
        config,
        NOW
      ),
      '3.3'
    );

    expect(out.securityHubStatus).toBe('FAILED');
    expect(out.securityHubNotEvaluated).toBe(1);
    expect(out.khalifaFailuresFilled).toBe(1);
    expect(out.counts).toMatchObject({ AGREE_PASS: 1, SH_NO_RESULT: 1, DISAGREE: 0 });
  });

  it('never lets a Khalifa PASS fill it: the real results alone decide', () => {
    const out = req(
      reconcile(
        khalifa([]),
        [f('Config.1', A, 'PASSED', 'us-west-2'), empty(A, 'us-east-1')],
        null,
        config,
        NOW
      ),
      '3.3'
    );

    expect(out.securityHubStatus).toBe('PASSED');
    expect(out.khalifaFailuresFilled).toBe(0);
  });

  it('gives way to a real result for the same account/region', () => {
    const out = req(
      reconcile(
        khalifa([]),
        [empty(A, 'us-west-2'), f('Config.1', A, 'PASSED', 'us-west-2')],
        null,
        config,
        NOW
      ),
      '3.3'
    );

    expect(out.securityHubStatus).toBe('PASSED');
    expect(out.securityHubNotEvaluated).toBe(0);
    expect(out.counts.AGREE_PASS).toBe(1);
  });

  it('fills a per-account Khalifa FAIL into every region it evaluated nothing in', () => {
    // 1.5 <- IAM.9, compared per account.
    const out = req(
      reconcile(
        report(result('1.5', 'FAIL', { assessedAccounts: [A], failingAccounts: [A] })),
        [{ ...f('IAM.9', A, 'PASSED'), evaluated: false }],
        null,
        config,
        NOW
      ),
      '1.5'
    );

    expect(out.securityHubStatus).toBe('FAILED');
    expect(out.khalifaFailuresFilled).toBe(1);
  });
});

describe('runReconciliation fails closed', () => {
  const store = () => ({ getLatest: jest.fn(async () => null), save: jest.fn(async () => {}) });
  const good = report(result('1.5', 'PASS', { assessedAccounts: [A], failingAccounts: [] }));

  it('records STALE, publishing nothing, when Security Hub cannot be read', async () => {
    const s = store();
    const record = await runReconciliation(good, config, {
      readFindings: async () => {
        throw new Error('AccessDenied');
      },
      store: s,
      now: () => NOW,
    });

    expect(record.status).toBe('STALE');
    expect(record.error).toBe('AccessDenied');
    expect(record.requirements).toEqual([]);
    expect(s.save).toHaveBeenCalledWith(record);
  });

  it('records STALE when the run produced no CIS report', async () => {
    const s = store();
    const record = await runReconciliation(null, config, {
      readFindings: jest.fn(),
      store: s,
      now: () => NOW,
    });

    expect(record.status).toBe('STALE');
  });

  it('does not throw when the record cannot be saved', async () => {
    const record = await runReconciliation(good, config, {
      readFindings: async () => [f('IAM.9', A, 'PASSED')],
      store: {
        getLatest: async () => null,
        save: async () => Promise.reject(new Error('throttled')),
      },
      now: () => NOW,
    });

    expect(record.status).toBe('OK');
  });
});

describe('readSecurityHubCisFindings', () => {
  it('reads every page of active CIS v3.0.0 findings and skips incomplete ones', async () => {
    const pages = [
      {
        Findings: [
          {
            AwsAccountId: A,
            Region: 'us-west-2',
            Compliance: { SecurityControlId: 'IAM.9', Status: 'PASSED' },
          },
          { AwsAccountId: B, Region: 'us-west-2', Compliance: { Status: 'FAILED' } },
        ],
        NextToken: 't1',
      },
      {
        Findings: [
          {
            AwsAccountId: C,
            Region: 'us-west-2',
            Compliance: { SecurityControlId: 'S3.8', Status: 'FAILED' },
          },
          {
            AwsAccountId: C,
            Region: 'us-east-1',
            Compliance: {
              SecurityControlId: 'S3.8',
              Status: 'PASSED',
              StatusReasons: [{ ReasonCode: 'CONFIG_EVALUATIONS_EMPTY' }],
            },
          },
        ],
      },
    ];
    const send = jest.fn(async () => pages.shift());

    const out: ShControlFinding[] = await readSecurityHubCisFindings({ send } as never);

    expect(out).toEqual([
      { ...f('IAM.9', A, 'PASSED'), evaluated: true },
      { ...f('S3.8', C, 'FAILED'), evaluated: true },
      { ...f('S3.8', C, 'PASSED', 'us-east-1'), evaluated: false },
    ]);
    const first = (send.mock.calls[0] as unknown[])[0] as { input: Record<string, any> };
    expect(first.input.Filters.ComplianceAssociatedStandardsId[0].Value).toBe(
      'standards/cis-aws-foundations-benchmark/v/3.0.0'
    );
    expect(first.input.Filters.RecordState[0].Value).toBe('ACTIVE');
    expect(
      ((send.mock.calls[1] as unknown[])[0] as { input: Record<string, any> }).input.NextToken
    ).toBe('t1');
  });

  it('refuses to truncate silently', async () => {
    const send = jest.fn(async () => ({ Findings: [], NextToken: 'more' }));

    await expect(readSecurityHubCisFindings({ send } as never)).rejects.toThrow('more than');
  });
});

describe('reconciliationSettingsFromEnv', () => {
  it('is disabled without a role ARN', () => {
    expect(reconciliationSettingsFromEnv({})).toBeNull();
  });

  it('reads the role, region, threshold and allowlist', () => {
    const s = reconciliationSettingsFromEnv({
      RECONCILIATION_SECURITY_HUB_ROLE_ARN:
        'arn:aws:iam::111122223333:role/khalifa-securityhub-reader',
      RECONCILIATION_MIN_AGREEMENT_DAYS: '7',
      RECONCILIATION_PUBLISH_ALLOWLIST: '1.5, 3.3,',
    });

    expect(s).toMatchObject({ region: 'us-east-1', minAgreementDays: 7 });
    expect([...s!.allowlist]).toEqual(['1.5', '3.3']);
  });

  it('falls back to AWS_REGION, then us-east-1', () => {
    const fromAwsRegion = reconciliationSettingsFromEnv({
      RECONCILIATION_SECURITY_HUB_ROLE_ARN: 'arn:x',
      AWS_REGION: 'eu-west-1',
    });
    expect(fromAwsRegion).toMatchObject({ region: 'eu-west-1' });

    const fallback = reconciliationSettingsFromEnv({
      RECONCILIATION_SECURITY_HUB_ROLE_ARN: 'arn:x',
    });
    expect(fallback).toMatchObject({ region: 'us-east-1' });
  });

  it('defaults to 5 days and an empty allowlist (nothing publishable)', () => {
    const s = reconciliationSettingsFromEnv({ RECONCILIATION_SECURITY_HUB_ROLE_ARN: 'arn:x' });

    expect(s!.minAgreementDays).toBe(5);
    expect(s!.allowlist.size).toBe(0);
  });

  it('rejects a non-positive threshold', () => {
    expect(() =>
      reconciliationSettingsFromEnv({
        RECONCILIATION_SECURITY_HUB_ROLE_ARN: 'arn:x',
        RECONCILIATION_MIN_AGREEMENT_DAYS: '0',
      })
    ).toThrow('positive integer');
  });
});
