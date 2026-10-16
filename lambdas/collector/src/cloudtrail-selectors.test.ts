import { summarizeEventSelectors } from './cloudtrail-selectors';

const S3_ALL = { Type: 'AWS::S3::Object', Values: ['arn:aws:s3'] };

describe('summarizeEventSelectors: basic selectors', () => {
  it('treats an omitted ReadWriteType as All', () => {
    const s = summarizeEventSelectors([{ DataResources: [S3_ALL] }], undefined);

    expect(s).toMatchObject({ logsAllS3ObjectWrites: true, logsAllS3ObjectReads: true });
  });

  it.each([
    ['WriteOnly', true, false],
    ['ReadOnly', false, true],
    ['All', true, true],
  ])('ReadWriteType %s -> writes %s, reads %s', (rw, writes, reads) => {
    const s = summarizeEventSelectors([{ ReadWriteType: rw, DataResources: [S3_ALL] }], undefined);

    expect(s.logsAllS3ObjectWrites).toBe(writes);
    expect(s.logsAllS3ObjectReads).toBe(reads);
  });

  // 3.8 and 3.9 require every bucket. A trail logging one bucket has data
  // events but does not satisfy either control.
  it('does not count S3 data events scoped to specific buckets', () => {
    const s = summarizeEventSelectors(
      [{ DataResources: [{ Type: 'AWS::S3::Object', Values: ['arn:aws:s3:::one-bucket/'] }] }],
      undefined
    );

    expect(s.hasDataEvents).toBe(true);
    expect(s.logsAllS3ObjectWrites).toBe(false);
    expect(s.logsAllS3ObjectReads).toBe(false);
  });

  it('does not count Lambda data events as S3', () => {
    const s = summarizeEventSelectors(
      [{ DataResources: [{ Type: 'AWS::Lambda::Function', Values: ['arn:aws:lambda'] }] }],
      undefined
    );

    expect(s.hasDataEvents).toBe(true);
    expect(s.logsAllS3ObjectWrites).toBe(false);
  });

  it('records management events unless explicitly excluded', () => {
    expect(summarizeEventSelectors([{}], undefined).includeManagementEvents).toBe(true);
    expect(
      summarizeEventSelectors([{ IncludeManagementEvents: false }], undefined)
        .includeManagementEvents
    ).toBe(false);
  });
});

// The previous code read only EventSelectors. A trail on advanced selectors
// reported no management events and no data events at all.
describe('summarizeEventSelectors: advanced selectors', () => {
  const data = (extra: object[] = []) => ({
    FieldSelectors: [
      { Field: 'eventCategory', Equals: ['Data'] },
      { Field: 'resources.type', Equals: ['AWS::S3::Object'] },
      ...extra,
    ],
  });

  it('reads management events from advanced selectors', () => {
    const s = summarizeEventSelectors(undefined, [
      { FieldSelectors: [{ Field: 'eventCategory', Equals: ['Management'] }] },
    ]);

    expect(s.includeManagementEvents).toBe(true);
  });

  it('treats an absent readOnly field as reads and writes', () => {
    const s = summarizeEventSelectors(undefined, [data()]);

    expect(s).toMatchObject({ logsAllS3ObjectWrites: true, logsAllS3ObjectReads: true });
  });

  it.each([
    ['false', true, false],
    ['true', false, true],
  ])('readOnly Equals %s -> writes %s, reads %s', (value, writes, reads) => {
    const s = summarizeEventSelectors(undefined, [data([{ Field: 'readOnly', Equals: [value] }])]);

    expect(s.logsAllS3ObjectWrites).toBe(writes);
    expect(s.logsAllS3ObjectReads).toBe(reads);
  });

  it('counts a whole-partition StartsWith as every bucket', () => {
    const s = summarizeEventSelectors(undefined, [
      data([{ Field: 'resources.ARN', StartsWith: ['arn:aws:s3:::'] }]),
    ]);

    expect(s.logsAllS3ObjectWrites).toBe(true);
  });

  it.each([
    ['a single bucket', { Field: 'resources.ARN', StartsWith: ['arn:aws:s3:::one-bucket/'] }],
    ['an exclusion', { Field: 'resources.ARN', NotStartsWith: ['arn:aws:s3:::logs/'] }],
    ['an exact match', { Field: 'resources.ARN', Equals: ['arn:aws:s3:::one-bucket/key'] }],
  ])('does not count a selector narrowed to %s', (_label, arnSelector) => {
    const s = summarizeEventSelectors(undefined, [data([arnSelector])]);

    expect(s.hasDataEvents).toBe(true);
    expect(s.logsAllS3ObjectWrites).toBe(false);
    expect(s.logsAllS3ObjectReads).toBe(false);
  });

  // A readOnly shape the code does not recognise is left uncounted rather than
  // guessed at: a missed PASS is recoverable, a false one is not.
  it('leaves an unrecognised readOnly shape uncounted', () => {
    const s = summarizeEventSelectors(undefined, [
      data([{ Field: 'readOnly', NotEquals: ['true'] }]),
    ]);

    expect(s.logsAllS3ObjectWrites).toBe(false);
    expect(s.logsAllS3ObjectReads).toBe(false);
  });

  it('returns all false for a trail with no selectors at all', () => {
    expect(summarizeEventSelectors(undefined, undefined)).toEqual({
      includeManagementEvents: false,
      logsAllManagementEvents: false,
      hasDataEvents: false,
      logsAllS3ObjectWrites: false,
      logsAllS3ObjectReads: false,
    });
  });
});

// Advanced selectors accept many narrowing fields. Ignoring an unrecognised one
// reported a PutObject-only selector as logging every write and every read --
// a false PASS on 3.8 and 3.9.
describe('summarizeEventSelectors: narrowing fields', () => {
  const s3Data = (extra: object) => [
    {
      FieldSelectors: [
        { Field: 'eventCategory', Equals: ['Data'] },
        { Field: 'resources.type', Equals: ['AWS::S3::Object'] },
        extra,
      ],
    },
  ];

  it.each([
    ['eventName', { Field: 'eventName', Equals: ['PutObject'] }],
    ['userIdentity.arn', { Field: 'userIdentity.arn', Equals: ['arn:aws:iam::1:role/r'] }],
    ['errorCode', { Field: 'errorCode', Equals: ['AccessDenied'] }],
    ['vpcEndpointId', { Field: 'vpcEndpointId', Equals: ['vpce-1'] }],
    ['eventSource', { Field: 'eventSource', Equals: ['s3.amazonaws.com'] }],
  ])('does not count a selector narrowed by %s', (_label, narrowing) => {
    const s = summarizeEventSelectors(undefined, s3Data(narrowing));

    expect(s.hasDataEvents).toBe(true);
    expect(s.logsAllS3ObjectWrites).toBe(false);
    expect(s.logsAllS3ObjectReads).toBe(false);
  });
});

// CloudTrail.1 (CIS 3.1) needs a trail capturing management reads AND writes.
describe('summarizeEventSelectors: management read and write', () => {
  it.each([
    ['basic, ReadWriteType omitted', [{}], undefined, true],
    ['basic, All', [{ ReadWriteType: 'All' }], undefined, true],
    ['basic, ReadOnly', [{ ReadWriteType: 'ReadOnly' }], undefined, false],
    ['basic, WriteOnly', [{ ReadWriteType: 'WriteOnly' }], undefined, false],
    [
      'basic, ReadOnly + WriteOnly selectors',
      [{ ReadWriteType: 'ReadOnly' }, { ReadWriteType: 'WriteOnly' }],
      undefined,
      true,
    ],
    ['basic, management excluded', [{ IncludeManagementEvents: false }], undefined, false],
  ])('%s -> %s', (_label, basic, advanced, want) => {
    expect(summarizeEventSelectors(basic, advanced).logsAllManagementEvents).toBe(want);
  });

  const mgmt = (extra: object[] = []) => ({
    FieldSelectors: [{ Field: 'eventCategory', Equals: ['Management'] }, ...extra],
  });

  it.each([
    ['advanced, no readOnly', [mgmt()], true],
    ['advanced, readOnly true', [mgmt([{ Field: 'readOnly', Equals: ['true'] }])], false],
    [
      'advanced, read + write selectors',
      [
        mgmt([{ Field: 'readOnly', Equals: ['true'] }]),
        mgmt([{ Field: 'readOnly', Equals: ['false'] }]),
      ],
      true,
    ],
    // Excluding an event source narrows what is logged, so it is not "all".
    [
      'advanced, eventSource excluded',
      [mgmt([{ Field: 'eventSource', NotEquals: ['kms.amazonaws.com'] }])],
      false,
    ],
  ])('%s -> %s', (_label, advanced, want) => {
    expect(summarizeEventSelectors(undefined, advanced).logsAllManagementEvents).toBe(want);
  });
});
