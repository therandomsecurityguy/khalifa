import { AssumeRoleCommand, STSClient } from '@aws-sdk/client-sts';
import { getSecretRecord } from './secrets-client';

interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration?: Date;
}

interface StsClient {
  send(command: AssumeRoleCommand): Promise<{
    Credentials?: {
      AccessKeyId?: string;
      SecretAccessKey?: string;
      SessionToken?: string;
      Expiration?: Date;
    };
  }>;
}

interface TargetCredentialsOptions {
  accountId: string;
  region: string;
  homeAccountId?: string;
  externalId?: string;
  roleName?: string;
  client?: StsClient;
}

const ACCOUNT_ID_PATTERN = /^\d{12}$/;
const ROLE_NAME_PATTERN = /^[\w+=,.@-]{1,64}$/;

/**
 * Prefers the runtime secret over the environment. Lambda no longer carries
 * COLLECTOR_EXTERNAL_ID; the container runtime still receives it from External
 * Secrets, so the environment remains the fallback.
 */
export async function resolveCollectorExternalId(
  environment: NodeJS.ProcessEnv = process.env
): Promise<string | undefined> {
  const secretId = environment.COLLECTOR_EXTERNAL_ID_SECRET_ARN;
  if (secretId) {
    const record = await getSecretRecord(secretId);
    return record.COLLECTOR_EXTERNAL_ID;
  }
  return environment.COLLECTOR_EXTERNAL_ID;
}

export async function getTargetCredentials({
  accountId,
  region,
  homeAccountId = process.env.HOME_ACCOUNT_ID,
  externalId,
  roleName = process.env.COLLECTOR_ROLE_NAME || 'SecurityGraphCollectorRole',
  client = new STSClient({ region, maxAttempts: 3, retryMode: 'standard' }),
}: TargetCredentialsOptions): Promise<AwsCredentials | undefined> {
  // Lambda passes no external id: it comes from the runtime secret. The
  // container runtime still gets it from External Secrets via the environment.
  const resolvedExternalId = externalId ?? (await resolveCollectorExternalId());
  if (!ACCOUNT_ID_PATTERN.test(accountId)) {
    throw new Error('A valid 12-digit accountId is required');
  }
  if (!homeAccountId) {
    throw new Error('HOME_ACCOUNT_ID is required');
  }
  if (!ACCOUNT_ID_PATTERN.test(homeAccountId)) {
    throw new Error('HOME_ACCOUNT_ID must be a valid 12-digit AWS account ID');
  }
  if (!ROLE_NAME_PATTERN.test(roleName)) {
    throw new Error('COLLECTOR_ROLE_NAME is invalid');
  }
  if (accountId === homeAccountId) {
    return undefined;
  }
  if (
    !resolvedExternalId ||
    resolvedExternalId !== resolvedExternalId.trim() ||
    resolvedExternalId.length < 16
  ) {
    throw new Error(
      'COLLECTOR_EXTERNAL_ID must be at least 16 characters without outer whitespace'
    );
  }

  const response = await client.send(
    new AssumeRoleCommand({
      RoleArn: `arn:aws:iam::${accountId}:role/${roleName}`,
      RoleSessionName: `KhalifaCollector-${Date.now()}`,
      DurationSeconds: 3600,
      ExternalId: resolvedExternalId,
    })
  );
  const credentials = response.Credentials;
  if (!credentials?.AccessKeyId || !credentials.SecretAccessKey || !credentials.SessionToken) {
    throw new Error(`AssumeRole returned incomplete credentials for account ${accountId}`);
  }

  return {
    accessKeyId: credentials.AccessKeyId,
    secretAccessKey: credentials.SecretAccessKey,
    sessionToken: credentials.SessionToken,
    expiration: credentials.Expiration,
  };
}
