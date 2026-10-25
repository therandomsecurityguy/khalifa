import type { GraphVertex } from '@/types';

export interface Fact {
  id: string;
  label: string;
  value: string;
  // Set when this fact is one the rule's query matched on.
  decisive: boolean;
}

type Props = Record<string, unknown>;
type Format = (value: unknown, props: Props) => string | undefined;
interface Spec {
  id: string;
  label: string;
  key?: string;
  format?: Format;
}

const yesNo: Format = (value) => (value === true ? 'yes' : value === false ? 'no' : undefined);
const text: Format = (value) =>
  typeof value === 'string' || typeof value === 'number' ? String(value) : undefined;
const days: Format = (value) =>
  typeof value === 'number' ? `${value} day${value === 1 ? '' : 's'}` : undefined;
const date: Format = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return undefined;
  return new Date(value).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
};
const list: Format = (value) => {
  const items = listItems(value);
  return items.length ? items.join(', ') : undefined;
};
const ports: Format = (_value, props) => {
  if (props.protocol === '-1') return 'all';
  const from = props.port_from;
  const to = props.port_to;
  if (typeof from !== 'number') return text(props.port_range, props);
  return typeof to === 'number' && to !== from ? `${from}–${to}` : String(from);
};
const metadataTokens: Format = (value) =>
  value === 'optional' ? 'IMDSv1 allowed' : value === 'required' ? 'IMDSv2 required' : undefined;
const lastUsed: Format = (value, props) => {
  const when = date(value, props);
  const ago = props.last_used_days_ago;
  if (!when) return typeof ago === 'number' ? `${ago} days ago` : 'never';
  return typeof ago === 'number' ? `${when} · ${ago} days ago` : when;
};

const SPECS: Record<string, Spec[]> = {
  AccessKey: [
    { id: 'status', label: 'Status' },
    { id: 'key_age_days', label: 'Age', format: days },
    { id: 'created_date', label: 'Created', format: date },
    { id: 'last_used_days_ago', label: 'Last used', key: 'last_used_date', format: lastUsed },
  ],
  IamUser: [
    { id: 'password_enabled', label: 'Console password', format: yesNo },
    { id: 'mfa_enabled', label: 'MFA', format: yesNo },
    {
      id: 'likely_workload_identity_candidate',
      label: 'Looks like a workload identity',
      format: yesNo,
    },
  ],
  IamRole: [
    { id: 'has_cross_account_trust', label: 'Cross-account trust', format: yesNo },
    { id: 'is_admin_role', label: 'Admin role', format: yesNo },
  ],
  IamPolicyStatement: [
    { id: 'effect', label: 'Effect' },
    { id: 'actions', label: 'Actions', format: list },
    { id: 'resources', label: 'Resources', format: list },
    { id: 'has_wildcard_action', label: 'Wildcard action', format: yesNo },
    { id: 'has_wildcard_resource', label: 'Wildcard resource', format: yesNo },
    { id: 'has_cross_account_principal', label: 'Cross-account principal', format: yesNo },
    { id: 'principal_account_ids', label: 'Shared with accounts', format: list },
    { id: 'principal_is_anyone', label: 'Allows anyone (*)', format: yesNo },
    { id: 'principal_org_restricted', label: 'Limited to an organization', format: yesNo },
    { id: 'grants_secret_read', label: 'Reads secrets', format: yesNo },
    { id: 'secret_grant_scope', label: 'Secret scope' },
  ],
  SecurityGroupRule: [
    { id: 'direction', label: 'Direction' },
    { id: 'protocol', label: 'Protocol' },
    { id: 'ports', label: 'Ports', key: 'port_from', format: ports },
    { id: 'cidr_block', label: 'Source' },
  ],
  Ec2Instance: [
    { id: 'state', label: 'State' },
    { id: 'is_internet_exposed', label: 'Internet exposed', format: yesNo },
    { id: 'metadata_http_tokens', label: 'Instance metadata', format: metadataTokens },
    { id: 'public_ip', label: 'Public IP' },
  ],
  S3Bucket: [
    { id: 'is_publicly_accessible', label: 'Publicly accessible', format: yesNo },
    { id: 'data_classification', label: 'Data classification' },
    { id: 'versioning_enabled', label: 'Versioning', format: yesNo },
  ],
  RdsInstance: [
    { id: 'is_publicly_accessible', label: 'Publicly accessible', format: yesNo },
    { id: 'storage_encrypted', label: 'Storage encrypted', format: yesNo },
    { id: 'data_classification', label: 'Data classification' },
  ],
  EksCluster: [
    { id: 'version', label: 'Version' },
    { id: 'endpoint_public_access', label: 'Public API endpoint', format: yesNo },
    { id: 'public_access_cidrs', label: 'Allowed CIDRs', format: list },
    { id: 'endpoint_world_open', label: 'Open to the world', format: yesNo },
  ],
  LambdaFunction: [
    { id: 'runtime', label: 'Runtime' },
    { id: 'is_in_vpc', label: 'In a VPC', format: yesNo },
    { id: 'has_internet_access', label: 'Internet access', format: yesNo },
    { id: 'function_url_auth_type', label: 'Function URL auth' },
    { id: 'function_url_public', label: 'Public function URL', format: yesNo },
    { id: 'public_invoke_policy', label: 'Anyone can invoke', format: yesNo },
    { id: 'role', label: 'Execution role' },
  ],
  KmsKey: [
    { id: 'key_state', label: 'Key state' },
    { id: 'key_manager', label: 'Managed by' },
    { id: 'rotation_enabled', label: 'Rotation', format: yesNo },
  ],
  Vpc: [{ id: 'flow_logs_enabled', label: 'Flow logs', format: yesNo }],
  ConfigRecorder: [{ id: 'recording', label: 'Recording', format: yesNo }],
  GuardDutyDetector: [{ id: 'status', label: 'Status' }],
  AccessAnalyzer: [{ id: 'status', label: 'Status' }],
  SecurityHubFinding: [
    { id: 'title', label: 'Finding' },
    { id: 'severity', label: 'Severity' },
    { id: 'workflow_state', label: 'Workflow' },
    { id: 'record_state', label: 'Record state' },
    { id: 'created_at', label: 'First observed', format: date },
    { id: 'updated_at', label: 'Last updated', format: date },
  ],
  GuardDutyFinding: [
    { id: 'title', label: 'Finding' },
    { id: 'severity', label: 'Severity', key: 'severity_label' },
    { id: 'finding_class', label: 'Class' },
    { id: 'action_type', label: 'Action' },
  ],
  CloudTrailAnomaly: [
    { id: 'anomaly_type', label: 'Anomaly' },
    { id: 'principal_arn', label: 'Principal' },
    { id: 'source_ip', label: 'Source IP' },
    { id: 'event_count', label: 'Events' },
    { id: 'first_seen', label: 'First seen', format: date },
    { id: 'last_seen', label: 'Last seen', format: date },
  ],
  DataClassificationFinding: [
    { id: 'secret_count', label: 'Secrets found' },
    { id: 'data_classification', label: 'Classification' },
    { id: 'pii_types', label: 'PII types', format: list },
    { id: 'classifier', label: 'Classifier' },
    { id: 'confidence', label: 'Confidence' },
  ],
  ContainerImage: [
    { id: 'tag', label: 'Tag' },
    { id: 'severity', label: 'Severity' },
    { id: 'cvss_base_score', label: 'CVSS' },
  ],
  Vulnerability: [
    { id: 'cve_id', label: 'CVE' },
    { id: 'severity', label: 'Severity' },
    { id: 'cvss_base_score', label: 'CVSS' },
    { id: 'exploit_available', label: 'Exploit known', format: yesNo },
    { id: 'fixed_versions', label: 'Fixed in' },
    { id: 'inspector_score', label: 'Inspector score' },
  ],
};

// Fact ids each rule's query matches on.
const DECISIVE: Record<string, string[]> = {
  'RULE-001': ['is_internet_exposed', 'data_classification'],
  'RULE-002': ['ports', 'cidr_block'],
  'RULE-003': ['severity', 'cvss_base_score', 'is_internet_exposed'],
  'RULE-004': ['is_internet_exposed', 'function_url_public', 'public_invoke_policy', 'is_admin'],
  'RULE-005': ['crown_jewel'],
  'RULE-006': ['effect', 'has_wildcard_resource'],
  'RULE-007': ['is_publicly_accessible', 'data_classification'],
  'RULE-008': ['is_publicly_accessible', 'data_classification'],
  'RULE-009': [
    'is_internet_exposed',
    'function_url_public',
    'public_invoke_policy',
    'data_classification',
  ],
  'RULE-010': ['principal_account_ids', 'principal_is_anyone', 'principal_org_restricted'],
  'RULE-011': ['is_publicly_accessible', 'data_classification'],
  'RULE-012': ['secret_count'],
  'RULE-013': ['status', 'key_age_days'],
  'RULE-014': ['status', 'last_used_days_ago'],
  'RULE-015': ['password_enabled', 'mfa_enabled'],
  'RULE-016': ['effect', 'grants_secret_read', 'secret_grant_scope'],
  'RULE-017': ['status'],
  'RULE-018': ['severity', 'workflow_state', 'record_state', 'is_internet_exposed'],
  'RULE-019': ['endpoint_public_access', 'endpoint_world_open'],
  'RULE-020': ['anomaly_type'],
  'RULE-021': ['anomaly_type'],
  'RULE-022': ['anomaly_type'],
  'RULE-023': ['anomaly_type'],
  'RULE-024': ['metadata_http_tokens', 'state'],
  'RULE-025': ['status'],
  'RULE-026': ['key_manager', 'key_state', 'rotation_enabled'],
  'RULE-027': ['flow_logs_enabled'],
  'RULE-028': ['recording'],
  'RULE-029': ['finding_class', 'severity', 'is_internet_exposed'],
  'RULE-030': ['risk_level', 'escalation_type'],
  'RULE-031': ['is_admin', 'status'],
  'RULE-032': ['env', 'principal_account_ids', 'principal_is_anyone'],
  'RULE-033': ['principal_account_ids', 'principal_is_anyone'],
  'RULE-034': ['is_admin', 'is_admin_role'],
};

// Properties that identify or bookkeep a vertex rather than describe it.
const SKIP = new Set([
  'id',
  'arn',
  'name',
  'Name',
  'account_id',
  'region',
  'active',
  'missing',
  'observed_at',
  'inventory_observed_at',
  'collection_scope',
  'collection_run_id',
  'unresolved',
]);
const FALLBACK_LIMIT = 8;

export function evidenceFor(vertex: GraphVertex, ruleId: string): Fact[] {
  const props = vertex.properties ?? {};
  const decisive = new Set(DECISIVE[ruleId] ?? []);
  const specs = SPECS[vertex.label] ?? fallbackSpecs(props);
  const facts: Fact[] = [];
  for (const spec of specs) {
    const value = (spec.format ?? text)(props[spec.key ?? spec.id], props);
    if (value === undefined) continue;
    facts.push({ id: spec.id, label: spec.label, value, decisive: decisive.has(spec.id) });
  }
  return facts;
}

function fallbackSpecs(props: Props): Spec[] {
  return Object.entries(props)
    .filter(
      ([key, value]) =>
        !SKIP.has(key) &&
        !key.startsWith('collection_') &&
        (typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string')
    )
    .slice(0, FALLBACK_LIMIT)
    .map(([key, value]) => ({
      id: key,
      label: humanize(key),
      format: typeof value === 'boolean' ? yesNo : text,
    }));
}

function humanize(key: string): string {
  const words = key
    .replace(/^is_|^has_/, '')
    .split('_')
    .filter(Boolean)
    .join(' ');
  return words.charAt(0).toUpperCase() + words.slice(1);
}

function listItems(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value !== 'string' || !value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed.map(String);
  } catch {
    // Not JSON; treat as a comma-separated list.
  }
  return value.split(',').map((item) => item.trim());
}
