import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const smClient = new SecretsManagerClient({ region: process.env.AWS_REGION || 'us-east-1' });

export async function getSecret(
  secretArn: string
): Promise<{ username: string; password: string }> {
  const command = new GetSecretValueCommand({ SecretId: secretArn });
  const response = await smClient.send(command);
  return JSON.parse(response.SecretString || '{}');
}

/** Reads a JSON secret as a string map (for non-credential secrets). */
export async function getSecretRecord(secretId: string): Promise<Record<string, string>> {
  const command = new GetSecretValueCommand({ SecretId: secretId });
  const response = await smClient.send(command);
  const parsed = JSON.parse(response.SecretString || '{}');
  return parsed && typeof parsed === 'object' ? parsed : {};
}
