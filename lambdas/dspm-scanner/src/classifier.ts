export type PiiType =
  | 'aws_access_key'
  | 'aws_secret_key'
  | 'gcp_service_account'
  | 'private_key'
  | 'jwt'
  | 'credit_card'
  | 'high_entropy_secret'
  | 'github_token'
  | 'slack_token'
  | 'stripe_key'
  | 'email'
  | 'phone'
  | 'ssn';

export interface ClassificationMatch {
  piiType: PiiType;
  count: number;
  confidence: number;
}

export interface ClassificationResult {
  piiTypes: PiiType[];
  secretCount: number;
  matches: ClassificationMatch[];
  sampleSize: number;
  skippedKms: number;
  confidence: number;
  scannedAt: string;
  classifier: string;
}

export interface Classifier {
  readonly name: string;
  classify(content: string): Promise<ClassificationMatch[]>;
}

export type DataClassification = 'public' | 'internal' | 'restricted' | 'secret';

export function promoteClassification(result: ClassificationResult): {
  classification: DataClassification;
  confidence: number;
} {
  const hasSecret =
    result.piiTypes.includes('private_key') ||
    result.piiTypes.includes('aws_secret_key') ||
    result.piiTypes.includes('gcp_service_account') ||
    result.piiTypes.includes('high_entropy_secret') ||
    result.piiTypes.includes('github_token') ||
    result.piiTypes.includes('slack_token') ||
    result.piiTypes.includes('stripe_key');
  const hasRestricted =
    result.piiTypes.includes('aws_access_key') ||
    result.piiTypes.includes('jwt') ||
    result.piiTypes.includes('credit_card') ||
    result.piiTypes.includes('ssn');
  const hasPii = result.piiTypes.includes('email') || result.piiTypes.includes('phone');

  if (hasSecret || result.secretCount > 0) {
    return { classification: 'secret', confidence: result.confidence };
  }
  if (hasRestricted) {
    return { classification: 'restricted', confidence: result.confidence };
  }
  if (hasPii) {
    return { classification: 'restricted', confidence: result.confidence * 0.8 };
  }
  return { classification: 'internal', confidence: result.confidence * 0.5 };
}
