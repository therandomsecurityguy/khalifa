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
    expect(fragment.frameworks).toEqual([
      {
        name: CIS_NAME,
        status: 'in-progress',
        description:
          'Continuous posture from automated graph evaluation against the AWS configuration. Not a certification.',
        lastVerified: '2026-10-16T00:00:00.000Z',
      },
    ]);
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
