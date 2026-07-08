import { Macie2Client, ListFindingsCommand, GetFindingsCommand } from '@aws-sdk/client-macie2';
import type { Classifier, ClassificationMatch, PiiType } from './classifier';

const MACIE_TYPE_MAP: Record<string, PiiType> = {
  AWS_API_KEY: 'aws_access_key',
  AWS_SECRET_KEY: 'aws_secret_key',
  Email_Address: 'email',
  Phone_Number: 'phone',
  US_Social_Security_Number: 'ssn',
  Credit_Card_Number: 'credit_card',
  Private_Key: 'private_key',
};

export class MacieClassifier implements Classifier {
  readonly name = 'macie';
  private client: Macie2Client;

  constructor() {
    this.client = new Macie2Client({ region: process.env.AWS_REGION || 'us-east-1' });
  }

  async classify(_content: string): Promise<ClassificationMatch[]> {
    return [];
  }

  async getFindingsForBucket(bucketName: string): Promise<ClassificationMatch[]> {
    try {
      const listResult = await this.client.send(
        new ListFindingsCommand({
          findingCriteria: {
            criterion: {
              'resources.S3Bucket.name': { eq: [bucketName] },
            },
          },
          maxResults: 50,
        })
      );

      const findingIds = listResult.findingIds || [];
      if (findingIds.length === 0) return [];

      const getResult = await this.client.send(
        new GetFindingsCommand({ findingIds: findingIds.slice(0, 50) })
      );

      const matches: ClassificationMatch[] = [];
      const byType = new Map<PiiType, number>();

      for (const finding of getResult.findings || []) {
        const typeName = finding.type || '';
        const piiType = MACIE_TYPE_MAP[typeName];
        if (!piiType) continue;
        byType.set(piiType, (byType.get(piiType) || 0) + 1);
      }

      for (const [piiType, count] of byType) {
        matches.push({
          piiType,
          count,
          sample: '[macie]',
          confidence: 0.95,
        });
      }

      return matches;
    } catch {
      return [];
    }
  }
}
