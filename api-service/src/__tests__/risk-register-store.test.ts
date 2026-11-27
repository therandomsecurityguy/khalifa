import {
  mapRiskRecord,
  parseRiskFields,
  riskLevel,
  riskScore,
  toRiskEntry,
  type RiskRecord,
} from '../services/risk-register-store';

const KNOWN = new Set(['KH-IAM-1', 'KH-AI-4']);
const NOW = new Date('2026-11-27T00:00:00.000Z');

function body(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    title: 'Shared admin role',
    inherent: { likelihood: 3, impact: 4 },
    ...overrides,
  };
}

describe('risk scoring', () => {
  it('multiplies and bands the 1-5 scale', () => {
    expect(riskScore({ likelihood: 3, impact: 4 })).toBe(12);
    expect(riskLevel(4)).toBe('low');
    expect(riskLevel(5)).toBe('medium');
    expect(riskLevel(9)).toBe('medium');
    expect(riskLevel(10)).toBe('high');
    expect(riskLevel(16)).toBe('high');
    expect(riskLevel(17)).toBe('critical');
    expect(riskLevel(25)).toBe('critical');
  });
});

describe('parseRiskFields', () => {
  it('fills safe defaults from a minimal body', () => {
    const parsed = parseRiskFields(body(), 'analyst@example.com', KNOWN, NOW);

    expect(parsed).toEqual({
      fields: {
        title: 'Shared admin role',
        description: '',
        category: 'security',
        owner: 'analyst@example.com',
        status: 'open',
        inherent: { likelihood: 3, impact: 4 },
        residual: null,
        treatment: 'mitigate',
        acceptanceExpiry: null,
        reviewCadenceDays: 90,
        lastReviewedAt: null,
        linkedIssueIds: [],
        linkedControls: [],
      },
    });
  });

  it('accepts a full body with residual, links, and an accepted treatment', () => {
    const parsed = parseRiskFields(
      body({
        title: '  Third-party model  ',
        description: 'Vendor model used for summarisation.',
        category: 'ai',
        owner: 'risk@example.com',
        status: 'accepted',
        residual: { likelihood: 2, impact: 2 },
        treatment: 'accept',
        acceptanceExpiry: '2027-01-01T00:00:00.000Z',
        reviewCadenceDays: 30,
        lastReviewedAt: '2026-11-01T00:00:00.000Z',
        linkedIssueIds: ['RULE-032-abc', 'RULE-032-abc'],
        linkedControls: ['KH-IAM-1', 'KH-AI-4'],
      }),
      'analyst@example.com',
      KNOWN,
      NOW
    );
    if ('error' in parsed) throw new Error(parsed.error);

    expect(parsed.fields).toMatchObject({
      title: 'Third-party model',
      category: 'ai',
      status: 'accepted',
      residual: { likelihood: 2, impact: 2 },
      treatment: 'accept',
      acceptanceExpiry: '2027-01-01T00:00:00.000Z',
      reviewCadenceDays: 30,
      // Deduplicated.
      linkedIssueIds: ['RULE-032-abc'],
      linkedControls: ['KH-IAM-1', 'KH-AI-4'],
    });
  });

  it('nulls the acceptance expiry when the treatment is not accept', () => {
    const parsed = parseRiskFields(
      body({ treatment: 'mitigate', acceptanceExpiry: '2027-01-01T00:00:00.000Z' }),
      'analyst@example.com',
      KNOWN,
      NOW
    );
    if ('error' in parsed) throw new Error(parsed.error);
    expect(parsed.fields.acceptanceExpiry).toBeNull();
  });

  it.each([
    [{}, 'title is required'],
    [{ title: 'x'.repeat(201), inherent: { likelihood: 1, impact: 1 } }, 'title is required'],
    [body({ inherent: { likelihood: 0, impact: 1 } }), 'inherent.likelihood'],
    [body({ inherent: { likelihood: 1, impact: 9 } }), 'inherent.impact'],
    [body({ inherent: 'high' }), 'inherent must be an object'],
    [body({ residual: { likelihood: 1, impact: 9 } }), 'residual.impact'],
    [body({ category: 'legal' }), 'category must be one of'],
    [body({ treatment: 'ignore' }), 'treatment must be one of'],
    [body({ treatment: 'accept' }), 'acceptanceExpiry is required'],
    [
      body({ treatment: 'accept', acceptanceExpiry: '2020-01-01T00:00:00Z' }),
      'acceptanceExpiry must be in the future',
    ],
    [body({ treatment: 'accept', acceptanceExpiry: '2099-01-01T00:00:00Z' }), 'within 3650 days'],
    [body({ reviewCadenceDays: 0 }), 'reviewCadenceDays'],
    [body({ lastReviewedAt: 'soon' }), 'lastReviewedAt'],
    [body({ linkedControls: ['NOPE-1'] }), 'unknown: NOPE-1'],
    [body({ linkedIssueIds: ['x'.repeat(65)] }), 'linkedIssueIds'],
  ])('rejects %j with its named field', (input, message) => {
    const parsed = parseRiskFields(input as Record<string, unknown>, 'a@b', KNOWN, NOW);

    expect('error' in parsed && parsed.error).toContain(message);
  });
});

describe('toRiskEntry', () => {
  const record: RiskRecord = {
    id: 'r1',
    title: 'Shared admin role',
    description: '',
    category: 'security',
    owner: 'a@b',
    status: 'open',
    inherent: { likelihood: 4, impact: 5 },
    residual: null,
    treatment: 'mitigate',
    acceptanceExpiry: null,
    reviewCadenceDays: 30,
    lastReviewedAt: '2026-11-01T00:00:00.000Z',
    linkedIssueIds: [],
    linkedControls: [],
    createdAt: '2026-10-01T00:00:00.000Z',
    createdBy: 'a@b',
    updatedAt: '2026-11-01T00:00:00.000Z',
    updatedBy: 'a@b',
  };

  it('derives score, level, and the next review date', () => {
    expect(toRiskEntry(record)).toMatchObject({
      inherentScore: 20,
      inherentLevel: 'critical',
      residualScore: null,
      residualLevel: null,
      nextReviewAt: '2026-12-01T00:00:00.000Z',
    });
  });

  it('falls back to createdAt for the review basis when never reviewed', () => {
    expect(toRiskEntry({ ...record, lastReviewedAt: null }).nextReviewAt).toBe(
      '2026-10-31T00:00:00.000Z'
    );
  });
});

describe('mapRiskRecord', () => {
  it('degrades a malformed row to safe defaults', () => {
    expect(mapRiskRecord({ id: 'r1' })).toMatchObject({
      title: '',
      category: 'security',
      status: 'open',
      inherent: { likelihood: 1, impact: 1 },
      residual: null,
      treatment: 'mitigate',
      reviewCadenceDays: 90,
      acceptanceExpiry: null,
      linkedIssueIds: [],
      linkedControls: [],
    });
  });

  it('drops unknown enums and out-of-range ratings, keeping valid ones', () => {
    const mapped = mapRiskRecord({
      id: 'r1',
      category: 'legal',
      treatment: 'ignore',
      inherent: { likelihood: 9, impact: 9 },
      residual: { likelihood: 2, impact: 3 },
    });

    expect(mapped.category).toBe('security');
    expect(mapped.treatment).toBe('mitigate');
    expect(mapped.inherent).toEqual({ likelihood: 1, impact: 1 });
    expect(mapped.residual).toEqual({ likelihood: 2, impact: 3 });
  });
});
