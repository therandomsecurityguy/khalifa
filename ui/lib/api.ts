const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'https://api.security-graph.example.com';

export async function fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
  const token = typeof window !== 'undefined' ? localStorage.getItem('id_token') : null;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Request failed' }));
    throw new Error(error.message || `HTTP ${response.status}`);
  }

  return response;
}

export async function getIssues(filters: Record<string, unknown> = {}): Promise<unknown> {
  const params = new URLSearchParams();

  Object.entries(filters).forEach(([key, value]) => {
    if (value !== undefined && value !== null) {
      if (Array.isArray(value)) {
        value.forEach((v) => params.append(key, v));
      } else {
        params.append(key, String(value));
      }
    }
  });

  const url = `${API_BASE_URL}/issues${params.toString() ? `?${params.toString()}` : ''}`;
  const response = await fetchWithAuth(url);
  return response.json();
}

export async function getIssue(id: string): Promise<any> {
  const response = await fetchWithAuth(`${API_BASE_URL}/issues/${id}`);
  return response.json();
}

export async function getIssueCounts(): Promise<any> {
  const response = await fetchWithAuth(`${API_BASE_URL}/issues/counts`);
  return response.json();
}

export async function getIssueStats(): Promise<any> {
  const response = await fetchWithAuth(`${API_BASE_URL}/issues/stats`);
  return response.json();
}

export async function getAttackPaths(
  fromSelector: string,
  toSelector: string,
  maxPathLength?: number
): Promise<any> {
  const params = new URLSearchParams({ fromSelector, toSelector });
  if (maxPathLength) params.append('maxPathLength', String(maxPathLength));

  const response = await fetchWithAuth(`${API_BASE_URL}/attack-paths?${params.toString()}`);
  return response.json();
}

export async function getResource(
  arn: string,
  includeNeighbors = true,
  includeIssues = true
): Promise<any> {
  const params = new URLSearchParams({
    includeNeighbors: String(includeNeighbors),
    includeIssues: String(includeIssues),
  });

  const response = await fetchWithAuth(`${API_BASE_URL}/resources/${arn}?${params.toString()}`);
  return response.json();
}

export async function searchResources(
  label: string,
  property?: string,
  value?: string,
  limit = 100
): Promise<any> {
  const params = new URLSearchParams({ label, limit: String(limit) });
  if (property) params.append('property', property);
  if (value) params.append('value', value);

  const response = await fetchWithAuth(`${API_BASE_URL}/resources/search?${params.toString()}`);
  return response.json();
}

export interface ComplianceFrameworkSummary {
  framework: string;
  version: string;
  totalControls: number;
  automatedControls: number;
  manualControls: number;
  coveragePercent: number;
  lastAssessment: string;
  summary: {
    totalControls: number;
    passed: number;
    failed: number;
    manual: number;
    notApplicable: number;
    notEvaluated: number;
    coveragePercent: number;
  };
}

export interface ComplianceControl {
  id: string;
  title: string;
  section: string;
  severity: string;
  automated: boolean;
  status: string;
  relatedRules?: string[];
}

export interface ComplianceControlDetail extends ComplianceControl {
  framework: string;
  lastEvaluated: string;
  remediationHint?: string;
  description?: string;
  evidenceRequirements?: string[];
  evidence: ComplianceEvidence[];
  relatedIssues: ComplianceRelatedIssue[];
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

export interface ComplianceRelatedIssue {
  ruleId: string;
  severity: string;
  status: string;
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
  summary: ComplianceFrameworkSummary['summary'];
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
  summary: ComplianceFrameworkSummary['summary'];
}

export async function getFrameworks(): Promise<{ frameworks: ComplianceFrameworkSummary[] }> {
  const response = await fetchWithAuth(`${API_BASE_URL}/compliance/frameworks`);
  return response.json();
}

export async function getFrameworkSummary(framework: string): Promise<FrameworkSummary> {
  const response = await fetchWithAuth(`${API_BASE_URL}/compliance/frameworks/${framework}`);
  return response.json();
}

export async function getFrameworkControls(
  framework: string
): Promise<{ controls: ComplianceControl[] }> {
  const response = await fetchWithAuth(
    `${API_BASE_URL}/compliance/frameworks/${framework}/controls`
  );
  return response.json();
}

export async function getControlDetails(
  framework: string,
  controlId: string
): Promise<ComplianceControlDetail> {
  const response = await fetchWithAuth(
    `${API_BASE_URL}/compliance/frameworks/${framework}/controls/${controlId}`
  );
  return response.json();
}

export async function getComplianceReport(
  framework: string,
  format?: 'json' | 'csv'
): Promise<ComplianceReport> {
  const params = format ? `?format=${format}` : '';
  const response = await fetchWithAuth(
    `${API_BASE_URL}/compliance/frameworks/${framework}/report${params}`
  );
  return response.json();
}

export async function getDriftReport(framework: string): Promise<ComplianceDriftReport> {
  const response = await fetchWithAuth(`${API_BASE_URL}/compliance/frameworks/${framework}/drift`);
  return response.json();
}
