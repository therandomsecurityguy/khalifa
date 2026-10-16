import type {
  PublishableMappedRequirement,
  PublishableResponse,
  PublishableRequirement,
  PublishableStatus,
  PublishedFramework,
} from './types';

export const PUBLISHABLE_PATH = '/compliance/reconciliation/publishable';
const DEFAULT_TIMEOUT_MS = 15_000;

export interface FetchPublishableOptions {
  apiUrl: string;
  clientId: string;
  clientSecret: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

/**
 * Reads the sanitized publishable endpoint through Cloudflare Access. The
 * service token headers are exchanged by the Access proxy for the
 * cf-access-jwt-assertion the API verifies; the client id must equal the
 * API's reconciliation.trustCenterSyncClientId.
 */
export async function fetchPublishable(
  options: FetchPublishableOptions
): Promise<PublishableResponse> {
  const apiUrl = options.apiUrl.trim().replace(/\/+$/, '');
  if (!apiUrl) throw new Error('KHALIFA_API_URL is required');
  if (!options.clientId.trim()) throw new Error('CF_ACCESS_CLIENT_ID is required');
  if (!options.clientSecret.trim()) throw new Error('CF_ACCESS_CLIENT_SECRET is required');

  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let body: unknown;
  try {
    const response = await fetchImpl(`${apiUrl}${PUBLISHABLE_PATH}`, {
      headers: {
        accept: 'application/json',
        'CF-Access-Client-Id': options.clientId,
        'CF-Access-Client-Secret': options.clientSecret,
      },
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error(`publishable endpoint returned HTTP ${response.status}`);
    }
    body = await response.json();
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error(`publishable endpoint timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }

  return parsePublishableResponse(body);
}

const STATUSES: PublishableStatus[] = ['PASS', 'FAIL'];

/** Strictly re-projects the payload onto the fields that may leave Khalifa. */
export function parsePublishableResponse(body: unknown): PublishableResponse {
  if (!body || typeof body !== 'object') {
    throw new Error('publishable endpoint returned a non-object payload');
  }
  const record = body as Record<string, unknown>;
  const status = record.status;
  if (status !== 'OK' && status !== 'STALE' && status !== 'MISSING') {
    throw new Error(`publishable endpoint returned an unknown status: ${String(status)}`);
  }
  const generatedAt =
    typeof record.generatedAt === 'string' && record.generatedAt ? record.generatedAt : null;
  if (!Array.isArray(record.requirements)) {
    throw new Error('publishable endpoint payload has no requirements array');
  }

  const requirements: PublishableRequirement[] = record.requirements.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`requirement ${index} is not an object`);
    }
    const item = entry as Record<string, unknown>;
    const requirement = textField(item, 'requirement', index);
    const title = textField(item, 'title', index);
    const section = textField(item, 'section', index);
    const itemStatus = item.status;
    if (!STATUSES.includes(itemStatus as PublishableStatus)) {
      throw new Error(`requirement ${requirement} has an unknown status: ${String(itemStatus)}`);
    }
    return { requirement, title, section, status: itemStatus as PublishableStatus };
  });

  const rawMapped = record.mappedFrameworks ?? [];
  if (!Array.isArray(rawMapped)) {
    throw new Error('publishable endpoint payload has a malformed mappedFrameworks');
  }
  const mappedFrameworks: PublishableMappedRequirement[] = rawMapped.map((entry, index) => {
    if (!entry || typeof entry !== 'object') {
      throw new Error(`mapped requirement ${index} is not an object`);
    }
    const item = entry as Record<string, unknown>;
    const framework = item.framework;
    if (framework !== 'SOC2' && framework !== 'ISO27001') {
      throw new Error(`mapped requirement ${index} has an unknown framework: ${String(framework)}`);
    }
    const requirement = textField(item, 'requirement', index);
    const title = textField(item, 'title', index);
    const section = textField(item, 'section', index);
    const itemStatus = item.status;
    if (!STATUSES.includes(itemStatus as PublishableStatus)) {
      throw new Error(`requirement ${requirement} has an unknown status: ${String(itemStatus)}`);
    }
    return {
      framework: framework as PublishedFramework,
      requirement,
      title,
      section,
      status: itemStatus as PublishableStatus,
    } as PublishableMappedRequirement;
  });

  return { status, generatedAt, requirements, mappedFrameworks };
}

function textField(item: Record<string, unknown>, field: string, index: number | string): string {
  const value = item[field];
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`requirement ${index} is missing ${field}`);
  }
  return value;
}
