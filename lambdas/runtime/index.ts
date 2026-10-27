import { timingSafeEqual } from 'crypto';
import { createServer, type IncomingMessage, type Server } from 'http';
import { OrganizationsClient } from '@aws-sdk/client-organizations';
import { SQSClient } from '@aws-sdk/client-sqs';
import { createHandler as createInventoryHandler } from '../list-accounts';
import { collect, collectGuardDutyFindings, type CollectorEvent } from '../collector';
import { processBatch } from '../incremental-collector';
import { createGraphWriterHandler, createRuntimeWriter } from '../graph-writer';
import { createHttpGraphWriter } from '../shared/graph-writer-client';
import type { GraphMutationBatch, GraphWriter } from '../shared/graph-batch-writer';
import type { WorkItem } from '../shared/account-inventory';
import type { GraphReconcile } from '../shared/types';
import { parseCollectionConfig } from '../shared/account-inventory';
import { Logger } from '../shared/types';
import { runComplianceOnce } from '../../packages/risk-engine/src/run-compliance-once';
import { runOnce } from '../../packages/risk-engine/src/run-once';
import { isNeptuneRetryable } from '../../packages/risk-engine/src/neptune-client';
import { runDspmScan } from '../dspm-scanner';
import { runLeastPrivilegeSweep } from '../least-privilege-sweep';
import { runPolicyEvaluation } from '../policy-evaluator';
import {
  analyzeCloudTrail,
  normalizeAthenaResultsLocation,
  validateAnalysisDays,
} from '../cloudtrail-analyzer';
import {
  analyzeFlowLogs,
  normalizeAthenaResultsLocation as normalizeFlowLogResultsLocation,
} from '../flow-log-analyzer';
import { validateObservationDays } from '../flow-log-analyzer/src/queries';
import { importThreatIntel, parseS3Uri, validateTtlDays } from '../threat-intel-import';
import { recomputeMinIntervalSeconds, runRecomputeWorker } from '../recompute-worker';

export { createHttpGraphWriter } from '../shared/graph-writer-client';

export type RuntimeCommand =
  | 'risk'
  | 'compliance'
  | 'organization-collector'
  | 'incremental-collector'
  | 'graph-writer'
  | 'cloudtrail-analyzer'
  | 'flow-log-analyzer'
  | 'threat-intel-import'
  | 'recompute-worker'
  | 'dspm-scanner'
  | 'policy-evaluator'
  | 'least-privilege-sweep';

interface RuntimeDependencies {
  inventory?: () => Promise<{ workItems: WorkItem[] }>;
  collect?: typeof collect;
  collectGuardDutyFindings?: typeof collectGuardDutyFindings;
  processBatch?: typeof processBatch;
  runCompliance?: typeof runComplianceOnce;
  runRisk?: typeof runOnce;
  analyzeCloudTrail?: typeof analyzeCloudTrail;
  analyzeFlowLogs?: typeof analyzeFlowLogs;
  importThreatIntel?: typeof importThreatIntel;
  runRecomputeWorker?: typeof runRecomputeWorker;
  runDspm?: typeof runDspmScan;
  runPolicyEvaluation?: typeof runPolicyEvaluation;
  runLeastPrivilegeSweep?: typeof runLeastPrivilegeSweep;
  graphWriter?: ReturnType<typeof createRuntimeWriter>;
  fetch?: typeof fetch;
  random?: () => number;
}

const logger = new Logger('runtime');
const commands = new Set<RuntimeCommand>([
  'risk',
  'compliance',
  'organization-collector',
  'incremental-collector',
  'graph-writer',
  'cloudtrail-analyzer',
  'flow-log-analyzer',
  'threat-intel-import',
  'recompute-worker',
  'dspm-scanner',
  'policy-evaluator',
  'least-privilege-sweep',
]);

const help = `Usage: runtime <command> [--check]

Commands:
  organization-collector  Discover approved accounts and collect them once
  incremental-collector   Long-poll the incremental SQS queue
  graph-writer             Serve graph persistence over internal HTTP
  compliance               Run all compliance assessments once
  risk                     Run all enabled risk rules once
  cloudtrail-analyzer      Query org CloudTrail usage into AccessAnalyzerCache
  flow-log-analyzer        Aggregate VPC flow logs into TrafficObservations
  threat-intel-import      Import customer threat-intel lists into ThreatIndicators
  recompute-worker         Drain the recompute queue and re-run policy evaluation
  dspm-scanner             Scan S3 objects and Lambda env vars for secrets
  policy-evaluator         Resolve effective permissions and escalation paths once
  least-privilege-sweep     Rightsize over-permissioned principals once`;

function required(environment: NodeJS.ProcessEnv, name: string): string {
  const value = environment[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function requiredSecret(environment: NodeJS.ProcessEnv, name: string, minimum = 16): string {
  const value = required(environment, name);
  if (value !== value.trim() || value.length < minimum) {
    throw new Error(`${name} must be at least ${minimum} characters without outer whitespace`);
  }
  return value;
}

function secretsEqual(left: string, right: string): boolean {
  const expected = Buffer.from(left);
  const provided = Buffer.from(right);
  if (expected.length !== provided.length) {
    timingSafeEqual(expected, expected);
    return false;
  }
  return timingSafeEqual(expected, provided);
}

function bearerToken(request: IncomingMessage): string {
  const header = request.headers.authorization;
  return header?.startsWith('Bearer ') ? header.slice(7) : '';
}

function positiveInteger(
  environment: NodeJS.ProcessEnv,
  name: string,
  fallback: number,
  maximum = Number.MAX_SAFE_INTEGER
): number {
  const value = environment[name];
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`${name} must be an integer between 1 and ${maximum}`);
  }
  return parsed;
}

function requiredUrl(environment: NodeJS.ProcessEnv, name: string): string {
  const value = required(environment, name);
  const url = new URL(value);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error(`${name} must use http or https`);
  }
  return url.toString().replace(/\/$/, '');
}

function validateCollection(environment: NodeJS.ProcessEnv): void {
  parseCollectionConfig(environment);
  if (!/^\d{12}$/.test(required(environment, 'HOME_ACCOUNT_ID'))) {
    throw new Error('HOME_ACCOUNT_ID must be a valid 12-digit AWS account ID');
  }
  const externalId = environment.COLLECTOR_EXTERNAL_ID || '';
  if (externalId !== externalId.trim() || externalId.length < 16) {
    throw new Error(
      'COLLECTOR_EXTERNAL_ID must be at least 16 characters without outer whitespace'
    );
  }
  required(environment, 'AWS_REGION');
  requiredUrl(environment, 'GRAPH_WRITER_URL');
}

export function validateRuntime(command: RuntimeCommand, environment: NodeJS.ProcessEnv): void {
  if (command === 'risk') {
    required(environment, 'NEPTUNE_ENDPOINT');
    return;
  }
  if (command === 'compliance') {
    required(environment, 'NEPTUNE_ENDPOINT');
    required(environment, 'COMPLIANCE_EVIDENCE_TABLE');
    required(environment, 'COMPLIANCE_REPORTS_TABLE');
    return;
  }
  if (command === 'graph-writer') {
    required(environment, 'AWS_REGION');
    required(environment, 'NEPTUNE_ENDPOINT');
    requiredSecret(environment, 'GRAPH_WRITER_TOKEN');
    positiveInteger(environment, 'GRAPH_WRITER_PORT', 8080, 65535);
    positiveInteger(environment, 'GRAPH_WRITER_MAX_BODY_BYTES', 4 * 1024 * 1024);
    positiveInteger(environment, 'GRAPH_WRITER_CONCURRENCY', 4, 20);
    return;
  }
  if (command === 'dspm-scanner') {
    required(environment, 'AWS_REGION');
    if (!environment.GRAPH_WRITER_FUNCTION_NAME?.trim()) {
      requiredUrl(environment, 'GRAPH_WRITER_URL');
      requiredSecret(environment, 'GRAPH_WRITER_TOKEN');
    }
    const scanMode = environment.DSPM_SCAN_MODE?.trim();
    if (scanMode && !['tagged-only', 'all', 'off'].includes(scanMode)) {
      throw new Error("DSPM_SCAN_MODE must be one of 'tagged-only', 'all', 'off'");
    }
    if (environment.MACIE_ENABLED && !['true', 'false'].includes(environment.MACIE_ENABLED)) {
      throw new Error("MACIE_ENABLED must be 'true' or 'false'");
    }
    return;
  }
  if (command === 'policy-evaluator') {
    required(environment, 'NEPTUNE_ENDPOINT');
    return;
  }
  if (command === 'least-privilege-sweep') {
    required(environment, 'NEPTUNE_ENDPOINT');
    required(environment, 'ACCESS_ANALYZER_TABLE');
    required(environment, 'LEAST_PRIVILEGE_TABLE');
    return;
  }
  if (command === 'flow-log-analyzer') {
    required(environment, 'AWS_REGION');
    required(environment, 'ATHENA_DATABASE');
    required(environment, 'ATHENA_WORKGROUP');
    normalizeFlowLogResultsLocation(environment.ATHENA_RESULTS_S3_LOCATION);
    required(environment, 'TRAFFIC_OBSERVATIONS_TABLE');
    validateObservationDays(environment.FLOW_LOG_DAYS ?? '7', 'FLOW_LOG_DAYS');
    return;
  }
  if (command === 'recompute-worker') {
    required(environment, 'AWS_REGION');
    required(environment, 'RECOMPUTE_QUEUE_URL');
    required(environment, 'NEPTUNE_ENDPOINT');
    recomputeMinIntervalSeconds(environment);
    return;
  }
  if (command === 'threat-intel-import') {
    required(environment, 'AWS_REGION');
    required(environment, 'THREAT_INDICATORS_TABLE');
    const ipList = environment.THREAT_INTEL_IP_LIST_S3_URI?.trim();
    const accountList = environment.THREAT_INTEL_ACCOUNT_LIST_S3_URI?.trim();
    if (!ipList && !accountList) {
      throw new Error(
        'THREAT_INTEL_IP_LIST_S3_URI or THREAT_INTEL_ACCOUNT_LIST_S3_URI is required'
      );
    }
    if (ipList) parseS3Uri(ipList);
    if (accountList) parseS3Uri(accountList);
    validateTtlDays(environment.THREAT_INTEL_TTL_DAYS ?? '90');
    return;
  }
  if (command === 'cloudtrail-analyzer') {
    required(environment, 'AWS_REGION');
    required(environment, 'ATHENA_DATABASE');
    required(environment, 'ATHENA_WORKGROUP');
    normalizeAthenaResultsLocation(environment.ATHENA_RESULTS_S3_LOCATION);
    required(environment, 'ACCESS_ANALYZER_TABLE');
    validateAnalysisDays(environment.ANALYSIS_DAYS || '90', 'ANALYSIS_DAYS');
    if (environment.GRAPH_WRITER_URL?.trim()) {
      requiredUrl(environment, 'GRAPH_WRITER_URL');
      requiredSecret(environment, 'GRAPH_WRITER_TOKEN');
      graphWriterRetryAttempts(environment);
    }
    return;
  }

  validateCollection(environment);
  requiredSecret(environment, 'GRAPH_WRITER_TOKEN');
  graphWriterRetryAttempts(environment);
  if (command === 'organization-collector') {
    parseGuardDutyFindingsConfig(environment);
    positiveInteger(environment, 'COLLECTION_CONCURRENCY', 4, 20);
    positiveInteger(environment, 'COLLECTION_MAX_ATTEMPTS', 3, 10);
    positiveInteger(environment, 'COLLECTION_RETRY_DELAY_MS', 1000, 60_000);
  } else {
    requiredUrl(environment, 'SQS_QUEUE_URL');
  }
}

const GRAPH_WRITER_RETRY_DELAY_MS = 1_000;

// GuardDuty findings are read from the delegated administrator, not from each
// member account. Unset administrator id leaves the sweep off; the member role
// in that account needs guardduty:ListFindings and GetFindings first.
export function parseGuardDutyFindingsConfig(
  environment: NodeJS.ProcessEnv
): { administratorAccountId: string; regions: string[] } | undefined {
  const administratorAccountId = environment.GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID?.trim();
  if (!administratorAccountId) return undefined;
  if (!/^\d{12}$/.test(administratorAccountId)) {
    throw new Error('GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID must be a valid 12-digit AWS account ID');
  }
  const regions = [
    ...new Set(
      (environment.GUARDDUTY_FINDING_REGIONS || '')
        .split(',')
        .map((region) => region.trim())
        .filter(Boolean)
    ),
  ];
  if (regions.length === 0) {
    throw new Error(
      'GUARDDUTY_FINDING_REGIONS is required when GUARDDUTY_ADMINISTRATOR_ACCOUNT_ID is set'
    );
  }
  for (const region of regions) {
    if (!/^[a-z]{2}(-gov)?-[a-z]+-\d+$/.test(region)) {
      throw new Error(`GUARDDUTY_FINDING_REGIONS has an invalid region: ${region}`);
    }
  }
  return { administratorAccountId, regions };
}

function graphWriterRetryAttempts(environment: NodeJS.ProcessEnv): number {
  return positiveInteger(environment, 'GRAPH_WRITER_RETRY_ATTEMPTS', 5, 10);
}

function httpGraphWriter(
  environment: NodeJS.ProcessEnv,
  dependencies: RuntimeDependencies
): GraphWriter {
  return createHttpGraphWriter(
    requiredUrl(environment, 'GRAPH_WRITER_URL'),
    positiveInteger(environment, 'GRAPH_WRITER_TIMEOUT_MS', 30_000, 300_000),
    dependencies.fetch,
    requiredSecret(environment, 'GRAPH_WRITER_TOKEN'),
    { attempts: graphWriterRetryAttempts(environment), delayMs: GRAPH_WRITER_RETRY_DELAY_MS }
  );
}

function isReconcile(value: unknown): value is GraphReconcile {
  const candidate = value as Partial<GraphReconcile> | null;
  const text = (field: unknown) => typeof field === 'string' && field.trim().length > 0;
  const optional = (field: unknown) => field === undefined || text(field);
  return (
    !!candidate &&
    text(candidate.scope) &&
    text(candidate.runId) &&
    text(candidate.observedAt) &&
    optional(candidate.accountId) &&
    optional(candidate.region)
  );
}

async function readBody(request: IncomingMessage, maxBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bytes += buffer.length;
    if (bytes > maxBytes) throw new Error('Graph mutation payload is too large');
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function respond(response: import('http').ServerResponse, status: number, body: object): void {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

export function createGraphWriterServer(
  writeGraph: GraphWriter,
  maxBytes: number,
  maxConcurrency = 4,
  token = ''
): Server {
  let active = 0;
  return createServer(async (request, response) => {
    if (request.method === 'GET' && (request.url === '/livez' || request.url === '/readyz')) {
      respond(response, 200, { status: 'ok' });
      return;
    }
    if (request.method !== 'POST' || request.url !== '/mutations') {
      respond(response, 404, { error: 'Not found' });
      return;
    }
    if (!token || !secretsEqual(token, bearerToken(request))) {
      respond(response, 401, { error: 'Unauthorized' });
      return;
    }
    if (active >= maxConcurrency) {
      respond(response, 503, { error: 'Graph writer is busy', retryable: true });
      return;
    }

    active++;
    try {
      const body = await readBody(request, maxBytes);
      let mutation: unknown;
      try {
        mutation = JSON.parse(body);
      } catch {
        respond(response, 400, { error: 'Graph mutation must be valid JSON' });
        return;
      }
      const graphMutation = mutation as Partial<GraphMutationBatch> | null;
      if (
        !graphMutation ||
        !Array.isArray(graphMutation.nodes) ||
        !Array.isArray(graphMutation.edges)
      ) {
        respond(response, 400, { error: 'Graph mutation requires nodes and edges arrays' });
        return;
      }
      if (graphMutation.reconcile != null && !isReconcile(graphMutation.reconcile)) {
        respond(response, 400, { error: 'reconcile requires scope, runId, and observedAt' });
        return;
      }
      respond(response, 200, await writeGraph(graphMutation as GraphMutationBatch));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      logger.error('Graph mutation failed', { error: message });
      if (message === 'Graph mutation payload is too large') {
        respond(response, 413, { error: message });
        return;
      }
      // Transient Neptune failures (connection, conflict, timeout, memory limit)
      // are 503 so the collector retries the batch. Anything else is permanent
      // and retrying would only repeat it.
      const retryable = isNeptuneRetryable(error);
      respond(response, retryable ? 503 : 500, { error: 'Graph persistence failed', retryable });
    } finally {
      active--;
    }
  });
}

async function delay(milliseconds: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolve) => {
    const done = () => {
      clearTimeout(timeout);
      signal.removeEventListener('abort', done);
      resolve();
    };
    const timeout = setTimeout(done, milliseconds);
    signal.addEventListener('abort', done, { once: true });
  });
}

// Fisher-Yates over a copy. Account collection stops at the run deadline, so a
// fixed order would leave the same accounts uncollected every run.
export function shuffle<T>(items: readonly T[], random: () => number = Math.random): T[] {
  const shuffled = [...items];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

export async function runBounded<T>(
  items: T[],
  concurrency: number,
  signal: AbortSignal,
  operation: (item: T) => Promise<void>
): Promise<void> {
  if (!Number.isSafeInteger(concurrency) || concurrency < 1) {
    throw new Error('Concurrency must be a positive integer');
  }
  let next = 0;
  const errors: Error[] = [];
  const worker = async () => {
    while (!signal.aborted) {
      const index = next++;
      if (index >= items.length) return;
      try {
        await operation(items[index]);
      } catch (error) {
        errors.push(error instanceof Error ? error : new Error(String(error)));
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, worker));
  if (errors.length === 1) throw errors[0];
  if (errors.length > 1) {
    throw new Error(
      `${errors.length} operations failed: ${errors.map((error) => error.message).join('; ')}`
    );
  }
}

async function runOrganization(
  environment: NodeJS.ProcessEnv,
  signal: AbortSignal,
  dependencies: RuntimeDependencies
): Promise<void> {
  const writeGraph = httpGraphWriter(environment, dependencies);
  const inventory = dependencies.inventory
    ? await dependencies.inventory()
    : await createInventoryHandler(
        new OrganizationsClient({ maxAttempts: 3 }),
        writeGraph,
        environment
      )();
  const collectWorkItem = dependencies.collect || collect;
  const attempts = positiveInteger(environment, 'COLLECTION_MAX_ATTEMPTS', 3, 10);
  const retryDelay = positiveInteger(environment, 'COLLECTION_RETRY_DELAY_MS', 1000, 60_000);

  let accountFailure: unknown;
  try {
    await runBounded(
      shuffle(inventory.workItems, dependencies.random),
      positiveInteger(environment, 'COLLECTION_CONCURRENCY', 4, 20),
      signal,
      async (item) => {
        let lastError: Error | undefined;
        for (let attempt = 1; attempt <= attempts && !signal.aborted; attempt++) {
          try {
            const result = await collectWorkItem(item as CollectorEvent, writeGraph);
            if (result.status === 'SUCCEEDED') return;
            if (result.retryableServices.length === 0) {
              // Denied APIs and collector errors do not change between attempts; the
              // coverage vertices already record the gap.
              logger.warn('Collection degraded', {
                accountId: item.accountId,
                region: item.region,
                failedServices: result.failedServices,
              });
              return;
            }
            lastError = new Error(
              `${item.accountId}/${item.region} incomplete: ${result.retryableServices.join(', ')}`
            );
          } catch (error) {
            lastError = error instanceof Error ? error : new Error(String(error));
            logger.error('Account collection attempt failed', {
              accountId: item.accountId,
              region: item.region,
              attempt,
              error: lastError.message,
              stack: lastError.stack,
            });
          }
          if (attempt < attempts) {
            await delay(Math.min(retryDelay * 2 ** (attempt - 1), 60_000), signal);
          }
        }
        if (signal.aborted) return;
        throw lastError || new Error(`${item.accountId}/${item.region} collection failed`);
      }
    );
  } catch (error) {
    // Recorded, not thrown yet: the GuardDuty sweep below reads the
    // administrator account only and must not be skipped because one member
    // account failed. The failure is rethrown after it.
    accountFailure = error;
  }
  if (signal.aborted) return;
  if (accountFailure) {
    logger.error('Organization collection incomplete', {
      workItems: inventory.workItems.length,
      error: accountFailure instanceof Error ? accountFailure.message : String(accountFailure),
    });
  } else {
    logger.info('Organization collection complete', { workItems: inventory.workItems.length });
  }

  // After every account, so DETECTS_ON edges find the resource vertices this
  // sweep just wrote. A failed region is logged and keeps its previous
  // findings; it does not fail the account collection that already succeeded.
  const guardDuty = parseGuardDutyFindingsConfig(environment);
  if (guardDuty) {
    await (dependencies.collectGuardDutyFindings || collectGuardDutyFindings)(guardDuty, {
      write: writeGraph,
    });
  }
  if (accountFailure) throw accountFailure;
}

async function runIncremental(
  environment: NodeJS.ProcessEnv,
  signal: AbortSignal,
  dependencies: RuntimeDependencies
): Promise<void> {
  const writeGraph = httpGraphWriter(environment, dependencies);
  const runBatch = dependencies.processBatch || processBatch;
  const sqsClient = new SQSClient({ region: environment.AWS_REGION });
  while (!signal.aborted) {
    try {
      const result = await runBatch({
        sqsClient,
        writeGraph,
        environment,
        abortSignal: signal,
      });
      if (result.failed > 0) {
        logger.warn('Incremental batch left messages on the queue', {
          failed: result.failed,
          processed: result.processed,
        });
      }
      if (environment.RUNTIME_ONCE === 'true') return;
    } catch (error) {
      if (signal.aborted) return;
      throw error;
    }
  }
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '0.0.0.0', () => {
      server.off('error', reject);
      resolve();
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve()))
  );
}

function waitForStop(signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) =>
    signal.addEventListener('abort', () => resolve(), { once: true })
  );
}

async function runGraphWriter(
  environment: NodeJS.ProcessEnv,
  signal: AbortSignal,
  dependencies: RuntimeDependencies
): Promise<void> {
  const writer = dependencies.graphWriter || createRuntimeWriter();
  const server = createGraphWriterServer(
    createGraphWriterHandler(writer),
    positiveInteger(environment, 'GRAPH_WRITER_MAX_BODY_BYTES', 4 * 1024 * 1024),
    positiveInteger(environment, 'GRAPH_WRITER_CONCURRENCY', 4, 20),
    requiredSecret(environment, 'GRAPH_WRITER_TOKEN')
  );
  try {
    const port = positiveInteger(environment, 'GRAPH_WRITER_PORT', 8080, 65535);
    await listen(server, port);
    logger.info('Graph writer listening', { port });
    await waitForStop(signal);
  } finally {
    if (server.listening) await close(server);
    await writer.close();
  }
}

export async function runCommand(
  command: RuntimeCommand,
  environment: NodeJS.ProcessEnv,
  signal: AbortSignal,
  dependencies: RuntimeDependencies = {}
): Promise<void> {
  validateRuntime(command, environment);
  if (command === 'organization-collector') {
    await runOrganization(environment, signal, dependencies);
  } else if (command === 'incremental-collector') {
    await runIncremental(environment, signal, dependencies);
  } else if (command === 'graph-writer') {
    await runGraphWriter(environment, signal, dependencies);
  } else if (command === 'compliance') {
    const summary = await (dependencies.runCompliance || runComplianceOnce)(
      required(environment, 'NEPTUNE_ENDPOINT')
    );
    logger.info('Compliance complete', summary);
  } else if (command === 'cloudtrail-analyzer') {
    const writeGraph = environment.GRAPH_WRITER_URL?.trim()
      ? httpGraphWriter(environment, dependencies)
      : undefined;
    const writeAnomalies = writeGraph
      ? async (batch: { nodes: unknown[]; observedAt: string }) => {
          if (!Array.isArray(batch.nodes) || batch.nodes.length === 0) {
            return { written: 0 };
          }
          const result = await writeGraph({
            nodes: batch.nodes as never,
            edges: [],
            observedAt: batch.observedAt,
          });
          return { written: result.written };
        }
      : undefined;
    const summary = await (dependencies.analyzeCloudTrail || analyzeCloudTrail)(
      {},
      writeAnomalies ? { writeAnomalies, signal } : { signal },
      environment
    );
    logger.info('CloudTrail analysis complete', summary);
  } else if (command === 'flow-log-analyzer') {
    const summary = await (dependencies.analyzeFlowLogs || analyzeFlowLogs)(
      {},
      { signal },
      environment
    );
    logger.info('Flow-log analysis complete', summary);
  } else if (command === 'threat-intel-import') {
    const summary = await (dependencies.importThreatIntel || importThreatIntel)(
      {},
      {},
      environment
    );
    logger.info('Threat-intel import complete', summary);
  } else if (command === 'recompute-worker') {
    const summary = await (dependencies.runRecomputeWorker || runRecomputeWorker)(environment, {
      signal,
    });
    logger.info('Recompute worker stopped', summary);
  } else if (command === 'dspm-scanner') {
    const summary = await (dependencies.runDspm || runDspmScan)({}, {}, environment);
    logger.info('DSPM scan complete', summary);
  } else if (command === 'policy-evaluator') {
    const summary = await (dependencies.runPolicyEvaluation || runPolicyEvaluation)(
      {},
      environment
    );
    logger.info('Policy evaluation complete', summary);
  } else if (command === 'least-privilege-sweep') {
    const summary = await (dependencies.runLeastPrivilegeSweep || runLeastPrivilegeSweep)(
      {},
      environment
    );
    logger.info('Least privilege sweep complete', summary);
  } else {
    const summary = await (dependencies.runRisk || runOnce)(
      required(environment, 'NEPTUNE_ENDPOINT')
    );
    logger.info('Risk assessment complete', summary);
  }
}

export async function main(
  args: string[] = process.argv.slice(2),
  environment: NodeJS.ProcessEnv = process.env,
  dependencies: RuntimeDependencies = {}
): Promise<void> {
  if (args.includes('--help')) {
    console.log(help);
    return;
  }
  const command = (args.find((argument) => !argument.startsWith('--')) || 'risk') as RuntimeCommand;
  if (!commands.has(command)) throw new Error(`Unknown runtime command: ${command}`);
  validateRuntime(command, environment);
  if (args.includes('--check')) {
    logger.info('Runtime configuration valid', { command });
    return;
  }

  const controller = new AbortController();
  const stop = () => controller.abort();
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    await runCommand(command, environment, controller.signal, dependencies);
  } finally {
    process.off('SIGINT', stop);
    process.off('SIGTERM', stop);
  }
}

if (require.main === module) {
  main().catch((error: unknown) => {
    logger.error('Runtime failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined,
    });
    process.exitCode = 1;
  });
}
