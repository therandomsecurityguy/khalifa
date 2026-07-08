import { RegexClassifier } from './regex-classifier';
import { promoteClassification, type ClassificationResult } from './classifier';

describe('RegexClassifier', () => {
  const classifier = new RegexClassifier();

  test('detects AWS access keys', async () => {
    const content = 'AKIAIOSFODNN7EXAMPLE some text AKIAI44QKWDGEXAMPLES';
    const matches = await classifier.classify(content);
    const awsKeys = matches.filter((m) => m.piiType === 'aws_access_key');
    expect(awsKeys.length).toBe(1);
    expect(awsKeys[0].count).toBe(2);
    expect(awsKeys[0].confidence).toBe(0.95);
  });

  test('detects private keys', async () => {
    const content =
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----';
    const matches = await classifier.classify(content);
    const privateKeys = matches.filter((m) => m.piiType === 'private_key');
    expect(privateKeys.length).toBe(1);
    expect(privateKeys[0].confidence).toBe(0.99);
  });

  test('detects JWT tokens', async () => {
    const content =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const matches = await classifier.classify(content);
    const jwts = matches.filter((m) => m.piiType === 'jwt');
    expect(jwts.length).toBe(1);
    expect(jwts[0].confidence).toBe(0.9);
  });

  test('detects valid credit cards with Luhn check', async () => {
    const content = '4111-1111-1111-1111 5500 0000 0000 0004';
    const matches = await classifier.classify(content);
    const cards = matches.filter((m) => m.piiType === 'credit_card');
    expect(cards.length).toBe(1);
    expect(cards[0].count).toBeGreaterThanOrEqual(1);
  });

  test('filters out invalid credit card numbers via Luhn check', async () => {
    const content = '1234-5678-9012-3456';
    const matches = await classifier.classify(content);
    const cards = matches.filter((m) => m.piiType === 'credit_card');
    expect(cards.length).toBe(0);
  });

  test('detects emails', async () => {
    const content = 'contact: admin@example.com, support@test.org';
    const matches = await classifier.classify(content);
    const emails = matches.filter((m) => m.piiType === 'email');
    expect(emails.length).toBe(1);
    expect(emails[0].count).toBe(2);
  });

  test('detects SSNs', async () => {
    const content = 'SSN: 123-45-6789';
    const matches = await classifier.classify(content);
    const ssns = matches.filter((m) => m.piiType === 'ssn');
    expect(ssns.length).toBe(1);
    expect(ssns[0].confidence).toBe(0.85);
  });

  test('detects GCP service account JSON', async () => {
    const content = '{"type": "service_account", "project_id": "my-project"}';
    const matches = await classifier.classify(content);
    const gcp = matches.filter((m) => m.piiType === 'gcp_service_account');
    expect(gcp.length).toBe(1);
    expect(gcp[0].confidence).toBe(0.95);
  });

  test('returns empty for clean content', async () => {
    const content = 'This is a normal text file with no secrets or PII data.';
    const matches = await classifier.classify(content);
    expect(matches.filter((m) => m.piiType !== 'high_entropy_secret')).toHaveLength(0);
  });

  test('detects high entropy strings as potential secrets', async () => {
    const content = 'token=Z8m5Wq3xK2vR7nYp1J4sL6tH9bF0cD2eG5iA8uM3oP6rS9wT2yU5';
    const matches = await classifier.classify(content);
    const secrets = matches.filter((m) => m.piiType === 'high_entropy_secret');
    expect(secrets.length).toBe(1);
    expect(secrets[0].confidence).toBe(0.7);
  });
});

describe('promoteClassification', () => {
  test('promotes secret when private keys found', () => {
    const result: ClassificationResult = {
      piiTypes: ['private_key'],
      secretCount: 1,
      matches: [{ piiType: 'private_key', count: 1, sample: '...', confidence: 0.99 }],
      sampleSize: 10,
      confidence: 0.99,
      scannedAt: new Date().toISOString(),
      classifier: 'regex',
    };
    const { classification, confidence } = promoteClassification(result);
    expect(classification).toBe('secret');
    expect(confidence).toBe(0.99);
  });

  test('promotes restricted for AWS access keys', () => {
    const result: ClassificationResult = {
      piiTypes: ['aws_access_key'],
      secretCount: 0,
      matches: [{ piiType: 'aws_access_key', count: 1, sample: 'AKIA...', confidence: 0.95 }],
      sampleSize: 10,
      confidence: 0.95,
      scannedAt: new Date().toISOString(),
      classifier: 'regex',
    };
    const { classification } = promoteClassification(result);
    expect(classification).toBe('restricted');
  });

  test('promotes restricted for emails with reduced confidence', () => {
    const result: ClassificationResult = {
      piiTypes: ['email'],
      secretCount: 0,
      matches: [{ piiType: 'email', count: 5, sample: 'a@b.com', confidence: 0.4 }],
      sampleSize: 10,
      confidence: 0.4,
      scannedAt: new Date().toISOString(),
      classifier: 'regex',
    };
    const { classification, confidence } = promoteClassification(result);
    expect(classification).toBe('restricted');
    expect(confidence).toBeLessThan(0.4);
  });

  test('falls back to internal for no PII', () => {
    const result: ClassificationResult = {
      piiTypes: [],
      secretCount: 0,
      matches: [],
      sampleSize: 10,
      confidence: 0,
      scannedAt: new Date().toISOString(),
      classifier: 'regex',
    };
    const { classification } = promoteClassification(result);
    expect(classification).toBe('internal');
  });
});
