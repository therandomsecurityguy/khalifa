import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';
import { getApiNeptuneClient } from './api-dependencies';

const DEFAULT_TIMEOUT = 1_500;
const REQUIRED_CONFIGURATION = ['NEPTUNE_ENDPOINT', 'COGNITO_USER_POOL_ID', 'COGNITO_CLIENT_ID'];

export interface ReadinessResult {
  status: 'ready' | 'not_ready';
  checks: {
    configuration: { ok: boolean; missing?: string[] };
    neptune: { ok: boolean };
    dynamodb: { ok: boolean };
  };
}

interface ReadinessDependencies {
  checkNeptune: (timeout: number) => Promise<void>;
  checkDynamo: (timeout: number) => Promise<void>;
  timeout?: number;
}

export class ReadinessService {
  constructor(private readonly dependencies: ReadinessDependencies) {}

  async check(): Promise<ReadinessResult> {
    const missing = REQUIRED_CONFIGURATION.filter((name) => !process.env[name]?.trim());
    const configuration = missing.length ? { ok: false, missing } : { ok: true };
    if (!configuration.ok) {
      return {
        status: 'not_ready',
        checks: { configuration, neptune: { ok: false }, dynamodb: { ok: false } },
      };
    }

    const timeout = this.dependencies.timeout ?? DEFAULT_TIMEOUT;
    const [neptune, dynamodb] = await Promise.allSettled([
      this.dependencies.checkNeptune(timeout),
      this.dependencies.checkDynamo(timeout),
    ]);
    const checks = {
      configuration,
      neptune: { ok: neptune.status === 'fulfilled' },
      dynamodb: { ok: dynamodb.status === 'fulfilled' },
    };
    return {
      status: checks.neptune.ok && checks.dynamodb.ok ? 'ready' : 'not_ready',
      checks,
    };
  }
}

const dynamoClient = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
const readinessService = new ReadinessService({
  checkNeptune: (timeout) => getApiNeptuneClient().healthCheck(timeout),
  checkDynamo: async (timeout) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      await dynamoClient.send(
        new ScanCommand({
          TableName: process.env.ISSUES_TABLE || 'SecurityIssues',
          Limit: 1,
          Select: 'COUNT',
        }),
        { abortSignal: controller.signal }
      );
    } finally {
      clearTimeout(timer);
    }
  },
});

export function getReadinessService(): ReadinessService {
  return readinessService;
}

export function closeReadinessDependencies(): void {
  dynamoClient.destroy();
}
