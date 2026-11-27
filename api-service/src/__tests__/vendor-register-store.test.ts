import {
  mapVendorRecord,
  parseVendorFields,
  toVendorEntry,
  type VendorRecord,
} from '../services/vendor-register-store';

function body(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return { name: 'Example Cloud', ...overrides };
}

describe('parseVendorFields', () => {
  it('fills safe defaults from a minimal body', () => {
    const parsed = parseVendorFields(body(), 'analyst@example.com');

    expect(parsed).toEqual({
      fields: {
        name: 'Example Cloud',
        category: 'other',
        purpose: '',
        location: '',
        dpaUrl: null,
        dataClasses: [],
        owner: 'analyst@example.com',
        status: 'active',
        subprocessor: false,
        renewalAt: null,
        reviewCadenceDays: 365,
        lastReviewedAt: null,
      },
    });
  });

  it('accepts a full body with an https DPA, subprocessor fields, and dates', () => {
    const parsed = parseVendorFields(
      body({
        name: '  Example AI  ',
        category: 'ai',
        purpose: 'Hosted inference',
        location: 'us-east-1',
        dpaUrl: 'https://example.com/dpa',
        dataClasses: ['internal', 'internal'],
        owner: 'procurement@example.com',
        status: 'under-review',
        subprocessor: true,
        renewalAt: '2027-06-01T00:00:00.000Z',
        reviewCadenceDays: 180,
        lastReviewedAt: '2026-11-01T00:00:00.000Z',
      }),
      'analyst@example.com'
    );
    if ('error' in parsed) throw new Error(parsed.error);

    expect(parsed.fields).toMatchObject({
      name: 'Example AI',
      category: 'ai',
      purpose: 'Hosted inference',
      location: 'us-east-1',
      dpaUrl: 'https://example.com/dpa',
      dataClasses: ['internal'],
      status: 'under-review',
      subprocessor: true,
      renewalAt: '2027-06-01T00:00:00.000Z',
      reviewCadenceDays: 180,
    });
  });

  it.each([
    [{}, 'name is required'],
    [{ name: 'x'.repeat(201) }, 'name is required'],
    [body({ category: 'hardware' }), 'category must be one of'],
    [body({ status: 'paused' }), 'status must be one of'],
    [body({ dpaUrl: 'http://example.com/dpa' }), 'dpaUrl must use https'],
    [body({ dpaUrl: 'ftp://example.com/dpa' }), 'dpaUrl must use https'],
    [body({ dpaUrl: 'not a url' }), 'dpaUrl must be a valid URL'],
    [body({ dataClasses: ['x'.repeat(65)] }), 'dataClasses'],
    [body({ subprocessor: 'yes' }), 'subprocessor must be a boolean'],
    [body({ subprocessor: true }), 'purpose and location are required'],
    [body({ subprocessor: true, purpose: 'p', location: 'l', renewalAt: 'soon' }), 'renewalAt'],
    [body({ reviewCadenceDays: 0 }), 'reviewCadenceDays'],
    [body({ lastReviewedAt: 'soon' }), 'lastReviewedAt'],
  ])('rejects %j with its named field', (input, message) => {
    const parsed = parseVendorFields(input as Record<string, unknown>, 'a@b');

    expect('error' in parsed && parsed.error).toContain(message);
  });
});

describe('toVendorEntry', () => {
  const record: VendorRecord = {
    id: 'example-cloud',
    name: 'Example Cloud',
    category: 'cloud',
    purpose: '',
    location: '',
    dpaUrl: null,
    dataClasses: [],
    owner: 'a@b',
    status: 'active',
    subprocessor: false,
    renewalAt: null,
    reviewCadenceDays: 365,
    lastReviewedAt: '2026-11-01T00:00:00.000Z',
    createdAt: '2026-10-01T00:00:00.000Z',
    createdBy: 'a@b',
    updatedAt: '2026-11-01T00:00:00.000Z',
    updatedBy: 'a@b',
  };

  it('derives the next review date from the last review plus the cadence', () => {
    expect(toVendorEntry(record).nextReviewAt).toBe('2027-11-01T00:00:00.000Z');
  });

  it('falls back to createdAt for the review basis when never reviewed', () => {
    const entry = toVendorEntry({ ...record, lastReviewedAt: null, reviewCadenceDays: 30 });
    expect(entry.nextReviewAt).toBe('2026-10-31T00:00:00.000Z');
  });
});

describe('mapVendorRecord', () => {
  it('degrades a malformed row to safe defaults', () => {
    expect(mapVendorRecord({ id: 'v1' })).toMatchObject({
      name: '',
      category: 'other',
      status: 'active',
      subprocessor: false,
      dpaUrl: null,
      reviewCadenceDays: 365,
      renewalAt: null,
      lastReviewedAt: null,
      dataClasses: [],
    });
  });

  it('drops a non-https DPA and unknown enums, keeping valid ones', () => {
    const mapped = mapVendorRecord({
      id: 'v1',
      category: 'hardware',
      status: 'paused',
      dpaUrl: 'http://example.com/dpa',
      subprocessor: 'true',
      dataClasses: ['internal', 7],
    });

    expect(mapped.category).toBe('other');
    expect(mapped.status).toBe('active');
    expect(mapped.dpaUrl).toBeNull();
    expect(mapped.subprocessor).toBe(false);
    expect(mapped.dataClasses).toEqual(['internal']);
  });
});
