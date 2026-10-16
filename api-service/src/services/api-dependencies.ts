import { NeptuneClient } from './neptune-client';

let neptuneClient: NeptuneClient | null = null;

export function getApiNeptuneClient(): NeptuneClient {
  if (!neptuneClient) {
    neptuneClient = new NeptuneClient({
      endpoint: process.env.NEPTUNE_ENDPOINT || '',
      region: process.env.AWS_REGION,
      timeout: readPositiveInteger('NEPTUNE_QUERY_TIMEOUT_MS', 30_000),
      maxAttempts: readPositiveInteger('NEPTUNE_MAX_ATTEMPTS', 3),
    });
  }
  return neptuneClient;
}

export async function closeApiNeptuneClient(): Promise<void> {
  const client = neptuneClient;
  neptuneClient = null;
  if (client) await client.close();
}

function readPositiveInteger(name: string, fallback: number): number {
  const value = process.env[name];
  if (!value?.trim()) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}
