import type {
  AccountCoverage,
  AccountSummary,
  AttackPathSearchParams,
  AttackPathSearchResponse,
  CatalogRule,
  EffectivePermissions,
  EscalationPath,
  IntegrationsStatus,
  JobOutput,
  Issue,
  IssueDetail,
  IssueLifecycleResponse,
  LeastPrivilegeFinding,
  LeastPrivilegeSummary,
  ResourceDetail,
  ResourceLabelCount,
  ResourceGraph,
  ResourceSearchResponse,
  AttackPathSimulationResponse,
  AttackScenarioDetail,
  AttackScenarioRunResponse,
  RuleQualityResponse,
  SecretDetail,
  SecretInventory,
  SecretReaderCounts,
  RightsizingRecommendation,
  IssueStatus,
  Session,
  Severity,
  SeverityStatusCounts,
  TrendSeries,
  UnusedPermissions,
} from '@/types';

const API_BASE_URL = '/api';

export interface RequestOptions {
  signal?: AbortSignal;
}

export type ApiErrorKind =
  | 'network'
  | 'timeout'
  | 'unauthenticated'
  | 'unauthorized'
  | 'not-found'
  | 'unavailable'
  | 'client'
  | 'server';

const RETRYABLE_KINDS: ReadonlySet<ApiErrorKind> = new Set([
  'network',
  'timeout',
  'unavailable',
  'server',
]);

function classifyStatus(status: number): ApiErrorKind {
  if (status === 0) return 'network';
  if (status === 401) return 'unauthenticated';
  if (status === 403) return 'unauthorized';
  if (status === 404) return 'not-found';
  if (status === 408 || status === 504) return 'timeout';
  if (status === 502 || status === 503) return 'unavailable';
  return status >= 500 ? 'server' : 'client';
}

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly kind: ApiErrorKind;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.kind = classifyStatus(status);
  }

  get retryable(): boolean {
    return RETRYABLE_KINDS.has(this.kind);
  }
}

export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.kind === 'not-found';
}

export function isAbortError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { name?: unknown }).name === 'AbortError'
  );
}

export interface ErrorDescription {
  kind: ApiErrorKind | 'unknown';
  title: string;
  message: string;
  retryable: boolean;
}

// Copy for every failure the UI can show. Server messages are surfaced only
// where they help the reader act (validation and not-found), never for auth
// or infrastructure failures.
export function describeError(error: unknown): ErrorDescription {
  if (error instanceof ApiError) {
    switch (error.kind) {
      case 'network':
        return {
          kind: error.kind,
          title: 'Connection failed',
          message: 'The request did not reach Khalifa. Check your network and try again.',
          retryable: true,
        };
      case 'timeout':
        return {
          kind: error.kind,
          title: 'Request timed out',
          message: 'Khalifa took too long to answer. Try again.',
          retryable: true,
        };
      case 'unauthenticated':
        return {
          kind: error.kind,
          title: 'Sign-in required',
          message: 'Your Cloudflare Access session has ended. Sign in again to continue.',
          retryable: false,
        };
      case 'unauthorized':
        return {
          kind: error.kind,
          title: 'No access',
          message: 'Your account cannot view this. Viewer access is required.',
          retryable: false,
        };
      case 'not-found':
        return {
          kind: error.kind,
          title: 'Not found',
          message: error.message || 'Nothing exists at this address.',
          retryable: false,
        };
      case 'unavailable':
        return {
          kind: error.kind,
          title: 'Khalifa is unavailable',
          message: 'The API is not responding right now. Try again in a moment.',
          retryable: true,
        };
      case 'client':
        return {
          kind: error.kind,
          title: 'Request rejected',
          message: error.message || 'The API rejected this request.',
          retryable: false,
        };
      case 'server':
        return {
          kind: error.kind,
          title: 'Something went wrong',
          message: 'Khalifa hit an unexpected error. Try again.',
          retryable: true,
        };
    }
  }
  return {
    kind: 'unknown',
    title: 'Something went wrong',
    message:
      error instanceof Error && error.message ? error.message : 'An unexpected error occurred.',
    retryable: true,
  };
}

function queryString(params: Record<string, unknown> = {}): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') {
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item) => search.append(key, String(item)));
      return;
    }
    search.append(key, String(value));
  });
  const encoded = search.toString();
  return encoded ? `?${encoded}` : '';
}

export async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  let response: Response;
  try {
    response = await fetch(url, {
      ...options,
      headers,
      credentials: 'same-origin',
    });
  } catch (error) {
    if (isAbortError(error)) throw error;
    throw new ApiError(0, 'Network request failed');
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
    throw new ApiError(
      response.status,
      typeof body.message === 'string' && body.message ? body.message : `HTTP ${response.status}`,
      typeof body.code === 'string' ? body.code : undefined
    );
  }

  return response;
}

async function request<T>(
  path: string,
  options: RequestOptions,
  init: RequestInit = {}
): Promise<T> {
  const response = await fetchWithAuth(`${API_BASE_URL}${path}`, {
    ...init,
    signal: options.signal,
  });
  return response.json() as Promise<T>;
}

export function getSession(options: RequestOptions = {}): Promise<Session> {
  return request('/session', options);
}

export function getIssues(
  filters: Record<string, unknown> = {},
  options: RequestOptions = {}
): Promise<{ items: Issue[]; nextToken?: string; totalCount: number }> {
  return request(`/issues${queryString(filters)}`, options);
}

export function getIssue(id: string, options: RequestOptions = {}): Promise<IssueDetail> {
  return request(`/issues/${encodeURIComponent(id)}`, options);
}

export function listRules(options: RequestOptions = {}): Promise<{ rules: CatalogRule[] }> {
  return request('/rules', options);
}

export function getRule(id: string, options: RequestOptions = {}): Promise<CatalogRule> {
  return request(`/rules/${encodeURIComponent(id)}`, options);
}

export function suppressIssue(
  id: string,
  reason: string,
  expiresAt: string,
  options: RequestOptions = {}
): Promise<IssueLifecycleResponse> {
  return request(`/issues/${encodeURIComponent(id)}/suppress`, options, {
    method: 'POST',
    body: JSON.stringify({ reason, expiresAt }),
  });
}

export function reopenIssue(
  id: string,
  options: RequestOptions = {}
): Promise<IssueLifecycleResponse> {
  return request(`/issues/${encodeURIComponent(id)}/reopen`, options, { method: 'POST' });
}

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low'];
const STATUSES: IssueStatus[] = ['open', 'suppressed', 'resolved'];

// Missing or non-numeric cells read as zero so a partial response still renders.
export function normalizeIssueSummary(value: unknown): SeverityStatusCounts {
  const raw = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const counts = (raw.counts && typeof raw.counts === 'object' ? raw.counts : {}) as Record<
    string,
    Record<string, unknown> | undefined
  >;
  return Object.fromEntries(
    SEVERITIES.map((severity) => [
      severity,
      Object.fromEntries(
        STATUSES.map((status) => {
          const cell = counts[severity]?.[status];
          return [status, typeof cell === 'number' && Number.isFinite(cell) ? cell : 0];
        })
      ),
    ])
  ) as SeverityStatusCounts;
}

export function getIssueSchedule(
  options: RequestOptions = {}
): Promise<{ lastRunAt: string | null; nextRunAt: string | null; intervalMinutes: number | null }> {
  return request('/issues/schedule', options);
}

export async function getIssueSummary(options: RequestOptions = {}): Promise<SeverityStatusCounts> {
  return normalizeIssueSummary(await request<unknown>('/issues/summary', options));
}

export function searchAttackPaths(
  params: AttackPathSearchParams,
  options: RequestOptions = {}
): Promise<AttackPathSearchResponse> {
  return request(`/attack-paths/search${queryString({ ...params })}`, options);
}

export function getDataSources(
  options: RequestOptions = {}
): Promise<{ accounts: AccountCoverage[]; jobs: JobOutput[] }> {
  return request('/data-sources', options);
}

export function getSecrets(options: RequestOptions = {}): Promise<SecretInventory> {
  return request('/secrets', options);
}

export function getSecretReaderCounts(options: RequestOptions = {}): Promise<SecretReaderCounts> {
  return request('/secrets/reader-counts', options);
}

export function getSecret(arn: string, options: RequestOptions = {}): Promise<SecretDetail> {
  return request(`/secrets/${encodeURIComponent(arn)}`, options);
}

export function listAttackScenarios(
  options: RequestOptions = {}
): Promise<{ scenarios: AttackScenarioDetail[] }> {
  return request('/attack-scenarios', options);
}

export function runAttackScenario(
  id: string,
  options: RequestOptions = {}
): Promise<AttackScenarioRunResponse> {
  return request(`/attack-scenarios/${encodeURIComponent(id)}`, options);
}

export function getRuleQuality(options: RequestOptions = {}): Promise<RuleQualityResponse> {
  return request('/rules/quality', options);
}

export function getPathSimulation(
  ruleId: string,
  options: RequestOptions = {}
): Promise<AttackPathSimulationResponse> {
  return request(`/attack-paths/simulate${queryString({ ruleId })}`, options);
}

export function getAccounts(options: RequestOptions = {}): Promise<{ accounts: AccountSummary[] }> {
  return request('/accounts', options);
}

export function getResource(
  arn: string,
  options: RequestOptions = {},
  includeNeighbors = true,
  includeIssues = true
): Promise<ResourceDetail> {
  return request(
    `/resources/${encodeURIComponent(arn)}${queryString({ includeNeighbors, includeIssues })}`,
    options
  );
}

export function getResourceLabels(
  options: RequestOptions = {}
): Promise<{ labels: ResourceLabelCount[] }> {
  return request('/resources/labels', options);
}

export function getResourceProperties(
  label: string,
  options: RequestOptions = {}
): Promise<{ properties: string[] }> {
  return request(`/resources/properties${queryString({ label })}`, options);
}

export function getPropertyValues(
  label: string,
  property: string,
  options: RequestOptions = {}
): Promise<{ values: Array<{ value: string; count: number; name?: string }>; more: boolean }> {
  return request(`/resources/values${queryString({ label, property })}`, options);
}

export function searchResources(
  label: string,
  property?: string,
  value?: string,
  limit = 100,
  options: RequestOptions = {},
  nextToken?: string
): Promise<ResourceSearchResponse> {
  return request(
    `/resources/search${queryString({ label, property, value, limit, nextToken })}`,
    options
  );
}

export function getResourceGraph(
  arn: string,
  depth = 2,
  options: RequestOptions = {}
): Promise<ResourceGraph> {
  return request(`/resources/graph${queryString({ arn, depth })}`, options);
}

export interface ComplianceAssessmentSummary {
  totalControls: number;
  passed: number;
  failed: number;
  manual: number;
  notApplicable: number;
  notEvaluated: number;
  coveragePercent: number;
}

export function assessmentCounts(
  value?: { summary?: Partial<ComplianceAssessmentSummary> } | null
): ComplianceAssessmentSummary {
  return {
    totalControls: value?.summary?.totalControls ?? 0,
    passed: value?.summary?.passed ?? 0,
    failed: value?.summary?.failed ?? 0,
    manual: value?.summary?.manual ?? 0,
    notApplicable: value?.summary?.notApplicable ?? 0,
    notEvaluated: value?.summary?.notEvaluated ?? 0,
    coveragePercent: value?.summary?.coveragePercent ?? 0,
  };
}

export function formatTimestamp(value?: string): string {
  if (!value) return 'Never';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? 'Never' : parsed.toLocaleString();
}

export interface ComplianceFrameworkSummary {
  framework: string;
  version: string;
  totalControls: number;
  automatedControls: number;
  manualControls: number;
  coveragePercent: number;
  lastAssessment: string;
  summary: ComplianceAssessmentSummary;
}

export interface ComplianceControl {
  id: string;
  title: string;
  section: string;
  severity: string;
  automated: boolean;
  status: string;
  relatedRules?: string[];
  // Regional controls only: the regions the result covers.
  regionsEvaluated?: string[];
}

export interface ComplianceMappedControl {
  controlId: string;
  framework: string;
  status: string;
  issues: string[];
}

export interface ComplianceCitation {
  framework: string;
  requirement: string;
  title: string;
}

export interface ComplianceControlDetail extends ComplianceControl {
  framework: string;
  lastEvaluated: string;
  remediationHint?: string;
  description?: string;
  evidenceRequirements?: string[];
  evidence: ComplianceEvidence[];
  relatedIssues: ComplianceRelatedIssue[];
  // Mapped-framework requirements only: the canonical controls behind it.
  mappedControls?: ComplianceMappedControl[];
  // Canonical controls only: mapped-framework requirements citing it.
  citedBy?: ComplianceCitation[];
}

export interface ComplianceEvidence {
  controlId: string;
  resourceId: string;
  resourceType: string;
  status: string;
  details: Record<string, unknown>;
  collectedAt: string;
  collectedBy: string;
}

// One related rule and its actual open issues. openCount is null when the
// issue store could not be read -- unknown, not zero.
export interface ComplianceRelatedIssue {
  ruleId: string;
  ruleName: string;
  openCount: number | null;
  highestSeverity: string | null;
  issues: { id: string; severity: string; resourceId: string; resourceName?: string }[];
}

export interface ComplianceDriftItem {
  controlId: string;
  controlTitle: string;
  section: string;
  severity: string;
  detectedAt: string;
  description: string;
  relatedRules: string[];
  remediation: string;
}

export interface ComplianceDriftReport {
  framework: string;
  generatedAt: string;
  totalDriftItems: number;
  criticalDrift: number;
  highDrift: number;
  mediumDrift: number;
  lowDrift: number;
  driftItems: ComplianceDriftItem[];
}

export interface ComplianceReportControlResult {
  control: {
    id: string;
    title: string;
    section: string;
    severity: string;
    automated: boolean;
  };
  status: string;
  evidence: unknown[];
  issues: string[];
  lastEvaluated: string;
}

export interface ComplianceReport {
  framework: string;
  generatedAt: string;
  summary: ComplianceAssessmentSummary;
  controls: ComplianceReportControlResult[];
}

export interface FrameworkSummary {
  framework: string;
  version: string;
  totalControls: number;
  automatedControls: number;
  manualControls: number;
  coveragePercent: number;
  lastAssessment: string;
  sections: string[];
  summary: ComplianceAssessmentSummary;
}

export function getFrameworks(
  options: RequestOptions = {}
): Promise<{ frameworks: ComplianceFrameworkSummary[] }> {
  return request('/compliance/frameworks', options);
}

export function getFrameworkSummary(
  framework: string,
  options: RequestOptions = {}
): Promise<FrameworkSummary> {
  return request(`/compliance/frameworks/${encodeURIComponent(framework)}`, options);
}

export function getFrameworkControls(
  framework: string,
  options: RequestOptions = {}
): Promise<{ controls: ComplianceControl[] }> {
  return request(`/compliance/frameworks/${encodeURIComponent(framework)}/controls`, options);
}

export function getControlDetails(
  framework: string,
  controlId: string,
  options: RequestOptions = {}
): Promise<ComplianceControlDetail> {
  return request(
    `/compliance/frameworks/${encodeURIComponent(framework)}/controls/${encodeURIComponent(controlId)}`,
    options
  );
}

export function getComplianceReport(
  framework: string,
  options: RequestOptions = {}
): Promise<ComplianceReport> {
  return request(`/compliance/frameworks/${encodeURIComponent(framework)}/report`, options);
}

export async function getComplianceReportCsv(
  framework: string,
  options: RequestOptions = {}
): Promise<Blob> {
  const response = await fetchWithAuth(
    `${API_BASE_URL}/compliance/frameworks/${encodeURIComponent(framework)}/report?format=csv`,
    { signal: options.signal }
  );
  return response.blob();
}

export function getDriftReport(
  framework: string,
  options: RequestOptions = {}
): Promise<ComplianceDriftReport> {
  return request(`/compliance/frameworks/${encodeURIComponent(framework)}/drift`, options);
}

export function getLeastPrivilegeFindings(
  filters: Record<string, unknown> = {},
  options: RequestOptions = {}
): Promise<{ items: LeastPrivilegeFinding[]; nextToken?: string; totalCount: number }> {
  return request(`/identity/least-privilege${queryString(filters)}`, options);
}

export function getLeastPrivilegeSummary(
  options: RequestOptions = {}
): Promise<LeastPrivilegeSummary> {
  return request('/identity/least-privilege/summary', options);
}

export function getLeastPrivilegeFinding(
  accountId: string,
  principalArn: string,
  options: RequestOptions = {}
): Promise<LeastPrivilegeFinding> {
  return request(
    `/identity/least-privilege/${encodeURIComponent(accountId)}/${encodeURIComponent(principalArn)}`,
    options
  );
}

export function getEffectivePermissions(
  principal: string,
  options: RequestOptions = {}
): Promise<EffectivePermissions> {
  return request(`/identity/effective-permissions/${encodeURIComponent(principal)}`, options);
}

export function getEscalationPaths(
  filters: Record<string, unknown> = {},
  options: RequestOptions = {}
): Promise<{ paths: EscalationPath[]; total: number }> {
  return request(`/identity/escalation-paths${queryString(filters)}`, options);
}

export function getUnusedPermissions(
  principal: string,
  options: RequestOptions = {}
): Promise<UnusedPermissions> {
  return request(`/identity/unused-permissions${queryString({ principal })}`, options);
}

export function getRightsizingRecommendation(
  principal: string,
  options: RequestOptions = {}
): Promise<RightsizingRecommendation> {
  return request(`/identity/rightsizing/${encodeURIComponent(principal)}`, options);
}

export function getTrustGraph(
  filters: Record<string, unknown> = {},
  options: RequestOptions = {}
): Promise<ResourceGraph & { nextToken?: string }> {
  return request(`/identity/trust-graph${queryString(filters)}`, options);
}

export function listTrendMetrics(options: RequestOptions = {}): Promise<{ metrics: string[] }> {
  return request('/trends', options);
}

export function getTrend(
  metric: string,
  days = 90,
  options: RequestOptions = {}
): Promise<TrendSeries> {
  return request(`/trends/${encodeURIComponent(metric)}${queryString({ days })}`, options);
}

export function getIntegrationsStatus(options: RequestOptions = {}): Promise<IntegrationsStatus> {
  return request('/integrations/status', options);
}
