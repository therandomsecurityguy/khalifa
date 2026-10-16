import type { Request, Response } from 'express';
import type { ReconciliationRecord, RequirementReconciliation } from '@khalifa/risk-engine';
import {
  MAX_RECORD_AGE_MS,
  getPublishableRequirements,
  publishableFrom,
  setReconciliationStoreForTests,
} from '../routes/trust-center';
import { requireTrustCenterSync } from '../middleware/rbac';

const NOW = new Date('2026-10-14T12:00:00Z');

function requirement(overrides: Partial<RequirementReconciliation>): RequirementReconciliation {
  return {
    requirement: '1.8',
    securityHubControls: ['IAM.15'],
    khalifaStatus: 'PASS',
    khalifaScope: 'account',
    counts: {
      AGREE_PASS: 25,
      AGREE_FAIL: 0,
      DISAGREE: 0,
      KHALIFA_AGGREGATE_ONLY: 0,
      KHALIFA_NO_RESULT: 0,
      SH_NO_RESULT: 0,
    },
    disagreements: [],
    agreeingSince: '2026-10-08T19:30:00.000Z',
    agreementDays: 6,
    allowlisted: true,
    publishable: true,
    ...overrides,
  };
}

function record(overrides: Partial<ReconciliationRecord> = {}): ReconciliationRecord {
  return {
    framework: 'CIS_RECONCILIATION',
    generatedAt: '2026-10-14T11:30:00.000Z',
    status: 'OK',
    khalifaReportGeneratedAt: '2026-10-14T11:30:00.000Z',
    minAgreementDays: 5,
    securityHubFindingsRead: 13722,
    requirements: [requirement({})],
    ...overrides,
  };
}

describe('publishableFrom', () => {
  it('emits a publishable, allowlisted requirement with its control title and section', () => {
    expect(publishableFrom(record(), NOW)).toEqual({
      status: 'OK',
      generatedAt: '2026-10-14T11:30:00.000Z',
      requirements: [
        {
          requirement: '1.8',
          title: expect.any(String),
          section: expect.stringMatching(/^1\. /),
          status: 'PASS',
        },
      ],
      mappedFrameworks: [],
      maxAgeHours: 24,
    });
  });

  it.each([
    ['not publishable', { publishable: false }],
    ['not allowlisted', { allowlisted: false }],
    ['without a PASS or FAIL', { khalifaStatus: 'NOT_EVALUATED' }],
    ['not a known CIS control', { requirement: '9.99' }],
  ])('drops a requirement %s', (_name, overrides) => {
    const out = publishableFrom(record({ requirements: [requirement(overrides)] }), NOW);
    expect(out.status).toBe('OK');
    expect(out.requirements).toEqual([]);
  });

  it('emits FAIL as FAIL; how to show it is the sync and SEC-3256 to decide', () => {
    const out = publishableFrom(
      record({ requirements: [requirement({ khalifaStatus: 'FAIL' })] }),
      NOW
    );
    expect(out.requirements[0].status).toBe('FAIL');
  });

  it('lists nothing from a STALE record', () => {
    expect(publishableFrom(record({ status: 'STALE' }), NOW)).toEqual({
      status: 'STALE',
      generatedAt: '2026-10-14T11:30:00.000Z',
      requirements: [],
      mappedFrameworks: [],
      maxAgeHours: 24,
    });
  });

  it('treats a record older than a day as STALE', () => {
    const generatedAt = new Date(NOW.getTime() - MAX_RECORD_AGE_MS - 1).toISOString();
    expect(publishableFrom(record({ generatedAt }), NOW).status).toBe('STALE');
  });

  it.each(['2026-10-15T00:00:00.000Z', 'not-a-date'])(
    'treats a generatedAt of %s as STALE',
    (generatedAt) => {
      expect(publishableFrom(record({ generatedAt }), NOW).status).toBe('STALE');
    }
  );

  it('reports MISSING when no record exists', () => {
    expect(publishableFrom(null, NOW)).toEqual({
      status: 'MISSING',
      generatedAt: null,
      requirements: [],
      mappedFrameworks: [],
      maxAgeHours: 24,
    });
  });

  // The public page must never learn which accounts exist or disagree.
  it('carries no account IDs, ARNs, counts or disagreement details', () => {
    const r = requirement({
      disagreements: [{ accountId: '111111111111', khalifa: 'PASS', securityHub: 'FAILED' }],
    });
    const out = JSON.stringify(publishableFrom(record({ requirements: [r] }), NOW));
    expect(out).not.toMatch(/\d{12}|arn:|IAM\.15|disagree|count|agreement/i);
  });
});

function makeRes() {
  const res: any = {
    statusCode: 200,
    body: undefined,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };
  return res as Response & { statusCode: number; body: any };
}

describe('GET /compliance/reconciliation/publishable', () => {
  afterEach(() => setReconciliationStoreForTests(null));

  it('returns 500 rather than an empty list when the record cannot be read', async () => {
    setReconciliationStoreForTests({
      getLatest: jest.fn().mockRejectedValue(new Error('AccessDenied')),
      save: jest.fn(),
    });
    const res = makeRes();
    jest.spyOn(console, 'error').mockImplementation(() => {});
    await getPublishableRequirements({} as Request, res);
    expect(res.statusCode).toBe(500);
  });

  it('serves the latest record through publishableFrom', async () => {
    const generatedAt = new Date(Date.now() - 60_000).toISOString();
    setReconciliationStoreForTests({
      getLatest: jest.fn().mockResolvedValue(record({ generatedAt })),
      save: jest.fn(),
    });
    const res = makeRes();
    await getPublishableRequirements({} as Request, res);
    expect(res.body.status).toBe('OK');
    expect(res.body.requirements).toHaveLength(1);
  });
});

describe('requireTrustCenterSync', () => {
  const run = (user: unknown) => {
    const next = jest.fn();
    const res = makeRes();
    requireTrustCenterSync({ user } as Request, res, next);
    return { next, res };
  };

  it('admits the sync service token', () => {
    const { next } = run({
      sub: 's',
      groups: [],
      tokenUse: 'access',
      serviceToken: true,
    });
    expect(next).toHaveBeenCalled();
  });

  it.each([
    [
      'a viewer with a trusted email',
      { sub: 'u', email: 'analyst@example.com', groups: [], tokenUse: 'access' },
    ],
    [
      'a Khalifa admin',
      { sub: 'u', email: 'analyst@example.com', groups: ['khalifa-admin'], tokenUse: 'id' },
    ],
    ['no user', undefined],
  ])('refuses %s', (_name, user) => {
    const { next, res } = run(user);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
  });
});

describe('publishableFrom: mapped frameworks', () => {
  // CC9.1 cites KH-2.5, KH-2.8 and KH-2.10; ISO A.8.13 cites the same set.
  const baseline = new Map<string, 'PASS' | 'FAIL'>([
    ['KH-2.5', 'PASS'],
    ['KH-2.8', 'PASS'],
    ['KH-2.10', 'PASS'],
  ]);

  it('publishes a mapped requirement once every mapped control is publishable or assessed', () => {
    const out = publishableFrom(record({ requirements: [] }), NOW, baseline);
    const cc91 = out.mappedFrameworks.find((r) => r.requirement === 'CC9.1');
    expect(cc91).toMatchObject({ framework: 'SOC2', status: 'PASS', section: 'Availability' });
    const a813 = out.mappedFrameworks.find((r) => r.requirement === 'A.8.13');
    expect(a813).toMatchObject({ framework: 'ISO27001', status: 'PASS' });
  });

  it('fails a mapped requirement when any mapped control fails', () => {
    const out = publishableFrom(
      record({ requirements: [] }),
      NOW,
      new Map([
        ['KH-2.5', 'PASS'],
        ['KH-2.8', 'FAIL' as const],
        ['KH-2.10', 'PASS' as const],
      ])
    );
    expect(out.mappedFrameworks.find((r) => r.requirement === 'CC9.1')?.status).toBe('FAIL');
  });

  it('keeps requirements off the page while any mapped control is manual or unevaluated', () => {
    const out = publishableFrom(
      record({ requirements: [] }),
      NOW,
      new Map([
        ['KH-2.5', 'MANUAL' as const],
        ['KH-2.8', 'PASS' as const],
        ['KH-2.10', 'PASS' as const],
      ])
    );
    expect(out.mappedFrameworks).toEqual([]);
  });

  it('gates a CIS-mapped control on reconciliation agreement, not just a stored status', () => {
    // CC6.1 cites 1.5; the stored baseline map alone must not publish it.
    const out = publishableFrom(record({ requirements: [] }), NOW, new Map([['1.5', 'PASS']]));
    expect(out.mappedFrameworks.find((r) => r.requirement === 'CC6.1')).toBeUndefined();

    // Once 1.5 is publishable in the record, CC6.1 publishes too.
    const withCis = publishableFrom(
      record({ requirements: [requirement({ requirement: '1.5', khalifaStatus: 'PASS' })] }),
      NOW,
      new Map([
        ['1.4', 'PASS'],
        ['1.5', 'PASS'],
        ['1.7', 'PASS'],
        ['1.10', 'PASS'],
        ['1.15', 'PASS'],
        ['KH-1.8', 'PASS'],
        ['KH-1.19', 'PASS'],
        ['KH-IAM-1', 'PASS'],
      ])
    );
    expect(withCis.mappedFrameworks.find((r) => r.requirement === 'CC6.1')?.status).toBe('PASS');
  });

  it('leaves mapped frameworks unpublished when the baseline report is unreadable', () => {
    expect(publishableFrom(record(), NOW).mappedFrameworks).toEqual([]);
  });
});

describe('publishableFrom: monitoring window', () => {
  it('publishes the staleness window the API enforces', () => {
    expect(MAX_RECORD_AGE_MS / (60 * 60 * 1000)).toBe(24);
    expect(publishableFrom(record(), NOW).maxAgeHours).toBe(24);
    expect(publishableFrom(null, NOW).maxAgeHours).toBe(24);
    expect(publishableFrom(record({ status: 'STALE' }), NOW).maxAgeHours).toBe(24);
  });
});
