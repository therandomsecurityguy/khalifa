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
