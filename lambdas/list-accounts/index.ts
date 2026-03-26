import { OrganizationsClient, ListAccountsCommand } from '@aws-sdk/client-organizations';
import { Logger } from '../../shared/types';

const logger = new Logger('list-accounts');
const orgClient = new OrganizationsClient({});

export const handler = async (): Promise<{ accounts: string[] }> => {
  logger.info('Starting account listing');

  const mockMode = process.env.MOCK_MODE === 'true';
  
  if (mockMode) {
    logger.info('Mock mode enabled, returning mock accounts');
    return { accounts: ['123456789012', '223456789012', '323456789012'] };
  }

  const accounts: string[] = [];
  let nextToken: string | undefined;

  do {
    const command = new ListAccountsCommand({ NextToken: nextToken });
    const response = await orgClient.send(command);
    
    for (const account of response.Accounts || []) {
      if (account.Status === 'ACTIVE') {
        accounts.push(account.Id!);
      }
    }
    
    nextToken = response.NextToken;
  } while (nextToken);

  logger.info(`Found ${accounts.length} active accounts`);
  return { accounts };
};
