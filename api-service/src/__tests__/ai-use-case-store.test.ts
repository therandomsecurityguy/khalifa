import { mapUseCaseRecord, parseUseCaseFields, slugify } from '../services/ai-use-case-store';

describe('slugify', () => {
  it('derives a stable slug and refuses names with no alphanumerics', () => {
    expect(slugify('Support Assistant v2')).toBe('support-assistant-v2');
    expect(slugify('  Memory Recall — Prod  ')).toBe('memory-recall-prod');
    expect(slugify('!!!')).toBe('');
  });
});

describe('parseUseCaseFields', () => {
  it('accepts a minimal body and fills the safe defaults', () => {
    const parsed = parseUseCaseFields({ name: ' Support assistant ' }, 'caller@example.com');

    expect(parsed).toEqual({
      fields: {
        name: 'Support assistant',
        description: '',
        owner: 'caller@example.com',
        status: 'draft',
        assets: [],
        dataClasses: [],
        assessment: null,
      },
    });
  });

  it('accepts assets, data classes, and an assessment', () => {
    const parsed = parseUseCaseFields(
      {
        name: 'Recall',
        owner: 'team-ai',
        status: 'approved',
        assets: ['arn:aws:bedrock:us-east-1:111122223333:agent/agent-1'],
        dataClasses: ['internal', 'internal'],
        assessment: {
          status: 'approved',
          riskTier: 'high',
          owner: 'risk@example.com',
          humanOversight: 'Analyst reviews weekly.',
          impacts: 'Customer-facing answers.',
          notes: '',
          reviewedAt: '2026-11-20T00:00:00.000Z',
        },
      },
      'caller@example.com'
    );

    if ('error' in parsed) throw new Error(parsed.error);
    expect(parsed.fields.status).toBe('approved');
    expect(parsed.fields.dataClasses).toEqual(['internal']);
    expect(parsed.fields.assessment?.riskTier).toBe('high');
    expect(parsed.fields.assessment?.reviewedAt).toBe('2026-11-20T00:00:00.000Z');
  });

  it.each([
    [{}, 'name is required'],
    [{ name: 'x', status: 'live' }, 'status must be one of'],
    [{ name: 'x', assets: ['not-an-arn'] }, 'assets entries must be ARNs'],
    [{ name: 'x', assets: Array(51).fill('arn:aws:s3:::b') }, 'assets must be at most'],
    [{ name: 'x', assessment: { riskTier: 'extreme' } }, 'assessment.riskTier'],
    [{ name: 'x', assessment: { reviewedAt: 'not-a-date' } }, 'reviewedAt'],
    [{ name: 'x', description: 'y'.repeat(2001) }, 'description'],
  ])('rejects %j with a named-field message', (body, message) => {
    const parsed = parseUseCaseFields(body as Record<string, unknown>, 'caller@example.com');

    expect('error' in parsed && parsed.error).toContain(message);
  });
});

describe('mapUseCaseRecord', () => {
  it('maps a full record', () => {
    const mapped = mapUseCaseRecord({
      id: 'support',
      name: 'Support',
      description: 'd',
      owner: 'team-ai',
      status: 'approved',
      assets: ['arn:aws:bedrock:us-east-1:111122223333:agent/a'],
      dataClasses: ['internal'],
      assessment: {
        status: 'approved',
        riskTier: 'medium',
        owner: 'risk',
        humanOversight: 'weekly',
        impacts: 'none',
        notes: '',
        reviewedAt: '2026-11-20T00:00:00.000Z',
        updatedAt: '2026-11-20T00:00:00.000Z',
        updatedBy: 'risk',
      },
      createdAt: '2026-11-01T00:00:00.000Z',
      createdBy: 'team-ai',
      updatedAt: '2026-11-20T00:00:00.000Z',
      updatedBy: 'risk',
    });

    expect(mapped.status).toBe('approved');
    expect(mapped.assets).toHaveLength(1);
    expect(mapped.assessment?.riskTier).toBe('medium');
  });

  it('degrades a malformed row to safe defaults', () => {
    const mapped = mapUseCaseRecord({
      id: 'x',
      status: 'live',
      assets: ['ok', 7, 'arn:aws:s3:::b'],
      assessment: 'junk',
    });

    expect(mapped.status).toBe('draft');
    expect(mapped.assets).toEqual(['ok', 'arn:aws:s3:::b']);
    expect(mapped.assessment).toBeNull();
    expect(mapped.owner).toBe('');
  });
});
