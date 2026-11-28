import {
  mapAccessReviewRecord,
  parseAccessReviewFields,
  parseReviewDecision,
  summarizeCompletion,
  toAccessReviewEntry,
  type AccessReviewRecord,
  type ReviewDecision,
} from '../services/access-review-store';

const ARN_1 = 'arn:aws:iam::111122223333:role/Admin';
const ARN_2 = 'arn:aws:iam::111122223333:user/deploy';

describe('toAccessReviewEntry', () => {
  const record: AccessReviewRecord = {
    id: 'q4-2026',
    name: 'Q4 2026',
    description: '',
    status: 'active',
    dueAt: null,
    principals: [ARN_1, ARN_2],
    decisions: [
      {
        principalArn: ARN_1,
        decision: 'approve',
        note: '',
        decidedBy: 'a@b',
        decidedAt: '2026-11-27T00:00:00.000Z',
      },
    ],
    snapshot: null,
    summary: null,
    createdAt: '2026-11-01T00:00:00.000Z',
    createdBy: 'a@b',
    updatedAt: '2026-11-27T00:00:00.000Z',
    updatedBy: 'a@b',
  };

  it('derives decided and pending counts', () => {
    expect(toAccessReviewEntry(record)).toMatchObject({ decided: 1, pending: 1 });
  });
});

describe('parseAccessReviewFields', () => {
  it('fills safe defaults from a minimal body', () => {
    const parsed = parseAccessReviewFields({ name: ' Q4 review ', principals: [ARN_1] });

    expect(parsed).toEqual({
      fields: {
        name: 'Q4 review',
        description: '',
        status: 'draft',
        dueAt: null,
        principals: [ARN_1],
      },
    });
  });

  it('accepts a full body and deduplicates principals', () => {
    const parsed = parseAccessReviewFields({
      name: 'Q4 review',
      description: 'Quarterly access review.',
      status: 'active',
      dueAt: '2026-12-31T00:00:00.000Z',
      principals: [ARN_1, ARN_2, ARN_1],
    });
    if ('error' in parsed) throw new Error(parsed.error);

    expect(parsed.fields).toMatchObject({
      status: 'active',
      dueAt: '2026-12-31T00:00:00.000Z',
      principals: [ARN_1, ARN_2],
    });
  });

  it.each([
    [{}, 'name is required'],
    [{ name: 'x'.repeat(201), principals: [ARN_1] }, 'name is required'],
    [{ name: 'x', principals: [] }, 'principals must be 1-200 ARNs'],
    [{ name: 'x' }, 'principals must list'],
    [{ name: 'x', principals: ['not-an-arn'] }, 'must be IAM user or role ARNs'],
    [{ name: 'x', principals: [ARN_1], status: 'open' }, 'status must be one of'],
    [{ name: 'x', principals: [ARN_1], dueAt: 'soon' }, 'dueAt must be an ISO timestamp'],
    [
      {
        name: 'x',
        principals: Array.from({ length: 201 }, (_, i) => `arn:aws:iam::111122223333:role/R${i}`),
      },
      'principals must be 1-200 ARNs',
    ],
  ])('rejects %j with its named field', (input, message) => {
    const parsed = parseAccessReviewFields(input as Record<string, unknown>);

    expect('error' in parsed && parsed.error).toContain(message);
  });
});

describe('parseReviewDecision', () => {
  it('accepts a covered decision shape and defaults the note', () => {
    expect(parseReviewDecision({ principalArn: ARN_1, decision: 'revoke' })).toEqual({
      decision: { principalArn: ARN_1, decision: 'revoke', note: '' },
    });
  });

  it.each([
    [{ decision: 'approve' }, 'principalArn must be'],
    [{ principalArn: 'nope', decision: 'approve' }, 'principalArn must be'],
    [{ principalArn: ARN_1, decision: 'maybe' }, 'decision must be one of'],
    [{ principalArn: ARN_1, decision: 'approve', note: 'x'.repeat(501) }, 'note must be'],
  ])('rejects %j with its named field', (input, message) => {
    const parsed = parseReviewDecision(input as Record<string, unknown>);

    expect('error' in parsed && parsed.error).toContain(message);
  });
});

describe('summarizeCompletion', () => {
  const decisions: ReviewDecision[] = [
    {
      principalArn: ARN_1,
      decision: 'approve',
      note: '',
      decidedBy: 'a@b',
      decidedAt: '2026-11-27T00:00:00.000Z',
    },
  ];

  it('snapshots the graph state per principal and counts decisions', () => {
    const { snapshot, summary } = summarizeCompletion(
      [ARN_1, ARN_2],
      decisions,
      [
        {
          id: ARN_1,
          label: 'IamRole',
          properties: { is_admin: true },
        },
      ],
      'analyst@example.com',
      '2026-11-27T12:00:00.000Z'
    );

    expect(snapshot).toEqual([
      { principalArn: ARN_1, exists: true, label: 'IamRole', isAdmin: true },
      { principalArn: ARN_2, exists: false, label: '', isAdmin: null },
    ]);
    expect(summary).toEqual({
      generatedAt: '2026-11-27T12:00:00.000Z',
      generatedBy: 'analyst@example.com',
      decisions: { approve: 1, revoke: 0, abstain: 0, pending: 1 },
      snapshotted: 2,
    });
  });
});

describe('mapAccessReviewRecord', () => {
  it('degrades a malformed row to safe defaults', () => {
    expect(mapAccessReviewRecord({ id: 'r1' })).toMatchObject({
      name: '',
      status: 'draft',
      dueAt: null,
      principals: [],
      decisions: [],
      snapshot: null,
      summary: null,
    });
  });

  it('drops unknown decision kinds, malformed entries, and non-boolean flags', () => {
    const mapped = mapAccessReviewRecord({
      id: 'r1',
      status: 'paused',
      decisions: [
        { principalArn: ARN_1, decision: 'maybe', decidedBy: 'a', decidedAt: 'x' },
        { decision: 'approve' },
      ],
      snapshot: [{ principalArn: ARN_1, exists: 'yes', isAdmin: 'no' }],
      summary: { decisions: { approve: -1, pending: 2 } },
    });

    expect(mapped.status).toBe('draft');
    expect(mapped.decisions).toEqual([
      { principalArn: ARN_1, decision: 'abstain', note: '', decidedBy: 'a', decidedAt: 'x' },
    ]);
    expect(mapped.snapshot).toEqual([
      { principalArn: ARN_1, exists: false, label: '', isAdmin: null },
    ]);
    expect(mapped.summary).toMatchObject({
      decisions: { approve: 0, revoke: 0, abstain: 0, pending: 2 },
    });
  });
});
