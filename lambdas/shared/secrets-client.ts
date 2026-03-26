import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const smClient = new SecretsManagerClient({ region: 'us-east-1' });

export async function getSecret(secretArn: string): Promise<{ username: string; password: string }> {
  const command = new GetSecretValueCommand({ SecretId: secretArn });
  const response = await smClient.send(command);
  return JSON.parse(response.SecretString || '{}');
}
