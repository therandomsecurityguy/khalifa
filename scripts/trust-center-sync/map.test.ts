import { CIS_NAME, buildTrustFragment } from './map';
import type { PublishableResponse } from './types';

const response: PublishableResponse = {
  status: 'OK',
  generatedAt: '2026-10-16T00:00:00.000Z',
  requirements: [
    { requirement: '2.1', title: 'CloudTrail enabled', section: '2. Logging', status: 'FAIL' },
    { requirement: '1.10', title: 'MFA for IAM users', section: '1. Identity', status: 'PASS' },
    { requirement: '1.5', title: 'Root has MFA', section: '1. Identity', status: 'PASS' },
  ],
};

describe('buildTrustFragment', () => {
  it('maps PASS to implemented and FAIL to partial', () => {
    const fragment = buildTrustFragment(response);
    const items = fragment.controls.flatMap((domain) => domain.items);
    expect(items.find((item) => item.title === 'Root has MFA')?.status).toBe('implemented');
    expect(items.find((item) => item.title === 'CloudTrail enabled')?.status).toBe('partial');
  });

  it('groups by section and sorts deterministically', () => {
    const fragment = buildTrustFragment(response);
    expect(fragment.controls.map((domain) => domain.domain)).toEqual(['1. Identity', '2. Logging']);
    // Numeric-aware ordering: 1.5 before 1.10.
    expect(fragment.controls[0].items.map((item) => item.title)).toEqual([
      'Root has MFA',
      'MFA for IAM users',
    ]);
  });

  it('never certifies and stamps the record time', () => {
    const fragment = buildTrustFragment(response);
    expect(fragment.frameworks[0]).toEqual({
      id: 'CIS_AWS_FOUNDATIONS',
      name: CIS_NAME,
      status: 'in-progress',
      description:
        'Continuous posture from automated graph evaluation against the AWS configuration. Not a certification.',
      lastVerified: '2026-10-16T00:00:00.000Z',
    });
  });

  it('lists the mapped frameworks as planned while nothing is published for them', () => {
    const fragment = buildTrustFragment(response);
    expect(fragment.frameworks.map((f) => [f.id, f.status])).toEqual([
      ['CIS_AWS_FOUNDATIONS', 'in-progress'],
      ['SOC2', 'planned'],
      ['ISO27001', 'planned'],
      ['PCI_DSS', 'planned'],
      ['NIST_800_53', 'planned'],
    ]);
    expect(fragment.controls.every((domain) => domain.framework === 'CIS_AWS_FOUNDATIONS')).toBe(
      true
    );
  });

  it('publishes mapped requirements under their own framework domains', () => {
    const fragment = buildTrustFragment({
      ...response,
      mappedFrameworks: [
        {
          framework: 'SOC2',
          requirement: 'CC9.1',
          title: 'Availability is protected',
          section: 'Availability',
          status: 'PASS',
        },
        {
          framework: 'ISO27001',
          requirement: 'A.8.13',
          title: 'Information backup is maintained',
          section: 'Technological controls',
          status: 'FAIL',
        },
      ],
    });

    expect(fragment.frameworks.map((f) => f.status)).toEqual([
      'in-progress',
      'in-progress',
      'in-progress',
      'planned',
      'planned',
    ]);
    const soc2 = fragment.controls.find(
      (domain) => domain.framework === 'SOC2' && domain.domain === 'Availability'
    );
    expect(soc2?.items).toEqual([
      {
        title: 'Availability is protected',
        description: 'SOC 2 Trust Services Criteria; requirement CC9.1.',
        status: 'implemented',
      },
    ]);
    const iso = fragment.controls.find((domain) => domain.framework === 'ISO27001');
    expect(iso?.items[0].status).toBe('partial');
  });

  it('marks the framework planned while nothing is publishable', () => {
    const fragment = buildTrustFragment({
      status: 'OK',
      generatedAt: null,
      requirements: [],
    });
    expect(fragment.frameworks[0].status).toBe('planned');
    expect(fragment.frameworks[0].lastVerified).toBeUndefined();
    expect(fragment.controls).toEqual([]);
  });

  it('gives every control a non-empty description', () => {
    const fragment = buildTrustFragment(response);
    for (const domain of fragment.controls) {
      for (const item of domain.items) {
        expect(item.description.length).toBeGreaterThan(0);
      }
    }
  });

  it('trips on identifiers that must never reach the page', () => {
    expect(() =>
      buildTrustFragment({
        status: 'OK',
        generatedAt: null,
        requirements: [
          {
            requirement: '1.1',
            title: 'Bucket arn:aws:s3:::example is public',
            section: '1. Identity',
            status: 'FAIL',
          },
        ],
      })
    ).toThrow('forbidden value');
    expect(() =>
      buildTrustFragment({
        status: 'OK',
        generatedAt: null,
        requirements: [
          {
            requirement: '1.1',
            title: 'Account 111122223333',
            section: '1. Identity',
            status: 'PASS',
          },
        ],
      })
    ).toThrow('forbidden value');
  });
});

describe('projections', () => {
  const base = {
    status: 'OK' as const,
    generatedAt: '2026-10-14T11:30:00.000Z',
    requirements: [],
    mappedFrameworks: [],
  };

  it('maps known metrics to fixed public labels with plain numbers', () => {
    const fragment = buildTrustFragment({
      ...base,
      projections: [
        {
          metric: 'openRiskScore',
          perDay: -2.345,
          confidence: 'medium',
          basisDays: 30,
          horizonDays: 30,
          projectedValue: 830.12,
        },
      ],
    });

    expect(fragment.projections).toEqual([
      {
        label: 'Open backlog risk score',
        perDay: -2.35,
        confidence: 'medium',
        basisDays: 30,
        horizonDays: 30,
        projectedValue: 830.12,
      },
    ]);
  });

  it('drops unknown metrics, bad confidences and out-of-range windows', () => {
    const fragment = buildTrustFragment({
      ...base,
      projections: [
        {
          metric: 'mystery' as never,
          perDay: 1,
          confidence: 'high',
          basisDays: 30,
          horizonDays: 30,
          projectedValue: 10,
        },
        {
          metric: 'sloBurning',
          perDay: 1,
          confidence: 'certain' as never,
          basisDays: 30,
          horizonDays: 30,
          projectedValue: 10,
        },
        {
          metric: 'sloBurning',
          perDay: Number.NaN,
          confidence: 'low',
          basisDays: 30,
          horizonDays: 30,
          projectedValue: 10,
        },
        {
          metric: 'openIssuesBySeverity',
          perDay: 1,
          confidence: 'low',
          basisDays: 999,
          horizonDays: 30,
          projectedValue: 10,
        },
      ],
    });

    expect(fragment.projections).toBeUndefined();
  });

  it('omits projections entirely when the API sends none', () => {
    expect(buildTrustFragment(base).projections).toBeUndefined();
  });
});
