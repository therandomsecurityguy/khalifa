// GetEventSelectors returns either basic EventSelectors or AdvancedEventSelectors,
// never both. The collector previously read only the basic form, so a trail on
// advanced selectors -- the current default for new trails -- reported no
// management events and no data events at all.
//
// It also flattened everything to one has_data_events boolean, which discards
// the two things CIS 3.8 and 3.9 turn on: whether the data events are S3 object
// events for every bucket, and whether they cover writes, reads, or both.

export interface EventSelectorSummary {
  includeManagementEvents: boolean;
  // Management events with both reads and writes, which CloudTrail.1 (CIS 3.1)
  // requires. includeManagementEvents alone is true for a read-only trail.
  logsAllManagementEvents: boolean;
  hasDataEvents: boolean;
  logsAllS3ObjectWrites: boolean;
  logsAllS3ObjectReads: boolean;
}

interface BasicSelector {
  ReadWriteType?: string;
  IncludeManagementEvents?: boolean;
  DataResources?: { Type?: string; Values?: string[] }[];
}

interface FieldSelector {
  Field?: string;
  Equals?: string[];
  StartsWith?: string[];
  EndsWith?: string[];
  NotEquals?: string[];
  NotStartsWith?: string[];
  NotEndsWith?: string[];
}

interface AdvancedSelector {
  FieldSelectors?: FieldSelector[];
}

// Basic selectors express "every bucket" as the bare S3 ARN prefix.
const ALL_BUCKETS = new Set(['arn:aws:s3', 'arn:aws:s3:::']);

// The only fields whose effect on "every S3 object event" this code can
// reason about. Advanced selectors also accept eventName, eventSource,
// errorCode, userIdentity.arn, vpcEndpointId and others -- every one of which
// narrows what is logged. A selector logging only PutObject, or only one
// principal's calls, is not "all write events", so a selector carrying any
// field outside this set is left uncounted.
const UNDERSTOOD_FIELDS = new Set(['eventCategory', 'resources.type', 'readOnly', 'resources.ARN']);
// For management events the only non-narrowing fields are the category and
// readOnly; an eventSource exclusion, for one, is no longer "all" events.
const MANAGEMENT_FIELDS = new Set(['eventCategory', 'readOnly']);

function onlyUnderstoodFields(selector: AdvancedSelector): boolean {
  return (selector.FieldSelectors ?? []).every((f) => UNDERSTOOD_FIELDS.has(f.Field ?? ''));
}

function field(selector: AdvancedSelector, name: string): FieldSelector | undefined {
  return (selector.FieldSelectors ?? []).find((f) => f.Field === name);
}

function onlyEquals(f: FieldSelector | undefined, value: string): boolean {
  return f?.Equals?.length === 1 && f.Equals[0] === value;
}

// A resources.ARN selector scopes the events to some buckets. Treated as every
// bucket only when it is a plain StartsWith on the whole-partition prefix; any
// other operator narrows it, and narrowing is not what 3.8 and 3.9 require.
function coversAllBuckets(selector: AdvancedSelector): boolean {
  const arn = field(selector, 'resources.ARN');
  if (!arn) return true;
  const narrowing =
    arn.Equals || arn.EndsWith || arn.NotEquals || arn.NotStartsWith || arn.NotEndsWith;
  return !narrowing && (arn.StartsWith ?? []).some((prefix) => ALL_BUCKETS.has(prefix));
}

export function summarizeEventSelectors(
  basic: BasicSelector[] | undefined,
  advanced: AdvancedSelector[] | undefined
): EventSelectorSummary {
  const summary: EventSelectorSummary = {
    includeManagementEvents: false,
    logsAllManagementEvents: false,
    hasDataEvents: false,
    logsAllS3ObjectWrites: false,
    logsAllS3ObjectReads: false,
  };

  let managementReads = false;
  let managementWrites = false;
  for (const selector of basic ?? []) {
    // ReadWriteType defaults to All when omitted.
    const rw = selector.ReadWriteType ?? 'All';
    if (selector.IncludeManagementEvents !== false) {
      summary.includeManagementEvents = true;
      if (rw === 'All' || rw === 'ReadOnly') managementReads = true;
      if (rw === 'All' || rw === 'WriteOnly') managementWrites = true;
    }
    const resources = selector.DataResources ?? [];
    if (resources.length > 0) summary.hasDataEvents = true;
    const allS3 = resources.some(
      (r) => r.Type === 'AWS::S3::Object' && (r.Values ?? []).some((v) => ALL_BUCKETS.has(v))
    );
    if (allS3 && (rw === 'All' || rw === 'WriteOnly')) summary.logsAllS3ObjectWrites = true;
    if (allS3 && (rw === 'All' || rw === 'ReadOnly')) summary.logsAllS3ObjectReads = true;
  }

  for (const selector of advanced ?? []) {
    const category = field(selector, 'eventCategory');
    if (onlyEquals(category, 'Management')) {
      summary.includeManagementEvents = true;
      const narrowed = (selector.FieldSelectors ?? []).some(
        (f) => !MANAGEMENT_FIELDS.has(f.Field ?? '')
      );
      const readOnly = field(selector, 'readOnly');
      if (!narrowed && !readOnly) {
        managementReads = true;
        managementWrites = true;
      } else if (!narrowed && onlyEquals(readOnly, 'true')) {
        managementReads = true;
      } else if (!narrowed && onlyEquals(readOnly, 'false')) {
        managementWrites = true;
      }
      continue;
    }
    if (!onlyEquals(category, 'Data')) continue;
    summary.hasDataEvents = true;
    if (!onlyEquals(field(selector, 'resources.type'), 'AWS::S3::Object')) continue;
    if (!coversAllBuckets(selector)) continue;
    if (!onlyUnderstoodFields(selector)) continue;

    // readOnly absent means both reads and writes. Equals true is reads only,
    // Equals false writes only. Any other shape is left uncounted rather than
    // guessed at -- a missed PASS is recoverable, a false one is not.
    const readOnly = field(selector, 'readOnly');
    if (!readOnly) {
      summary.logsAllS3ObjectWrites = true;
      summary.logsAllS3ObjectReads = true;
    } else if (onlyEquals(readOnly, 'false')) {
      summary.logsAllS3ObjectWrites = true;
    } else if (onlyEquals(readOnly, 'true')) {
      summary.logsAllS3ObjectReads = true;
    }
  }

  summary.logsAllManagementEvents = managementReads && managementWrites;
  return summary;
}
