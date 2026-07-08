import type { Classifier, ClassificationMatch, PiiType } from './classifier';

interface PatternDef {
  piiType: PiiType;
  pattern: RegExp;
  confidence: number;
}

const PATTERNS: PatternDef[] = [
  { piiType: 'aws_access_key', pattern: /AKIA[0-9A-Z]{16}/g, confidence: 0.95 },
  {
    piiType: 'aws_secret_key',
    pattern: /(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])/g,
    confidence: 0.5,
  },
  { piiType: 'gcp_service_account', pattern: /"type":\s*"service_account"/g, confidence: 0.95 },
  {
    piiType: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    confidence: 0.99,
  },
  {
    piiType: 'jwt',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    confidence: 0.9,
  },
  { piiType: 'credit_card', pattern: /\b(?:\d[ -]*?){13,19}\b/g, confidence: 0.6 },
  {
    piiType: 'email',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    confidence: 0.4,
  },
  {
    piiType: 'phone',
    pattern: /\b\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b/g,
    confidence: 0.3,
  },
  { piiType: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, confidence: 0.85 },
];

const HIGH_ENTROPY_THRESHOLD = 4.5;
const MIN_SECRET_LENGTH = 20;
const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';

function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const c of str) {
    freq.set(c, (freq.get(c) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function findHighEntropySecrets(content: string): string[] {
  const candidates: string[] = [];
  const tokens = content.match(/[A-Za-z0-9+/=_-]{20,}/g) || [];
  const seen = new Set<string>();
  for (const token of tokens) {
    if (seen.has(token)) continue;
    seen.add(token);
    if (token.length < MIN_SECRET_LENGTH) continue;
    const isBase64 = [...token].every((c) => BASE64_CHARS.includes(c));
    if (!isBase64) continue;
    const entropy = shannonEntropy(token);
    if (entropy >= HIGH_ENTROPY_THRESHOLD) {
      candidates.push(token);
    }
  }
  return candidates;
}

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = parseInt(digits[i], 10);
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export class RegexClassifier implements Classifier {
  readonly name = 'regex';

  async classify(content: string): Promise<ClassificationMatch[]> {
    const matches: ClassificationMatch[] = [];

    for (const { piiType, pattern, confidence } of PATTERNS) {
      const found = content.match(pattern);
      if (!found || found.length === 0) continue;

      let validCount = found.length;
      if (piiType === 'credit_card') {
        validCount = found.filter((f) => luhnCheck(f)).length;
      }

      if (validCount === 0) continue;
      matches.push({
        piiType,
        count: validCount,
        sample: found[0].slice(0, 20) + (found[0].length > 20 ? '...' : ''),
        confidence,
      });
    }

    const highEntropy = findHighEntropySecrets(content);
    if (highEntropy.length > 0) {
      matches.push({
        piiType: 'high_entropy_secret',
        count: highEntropy.length,
        sample: highEntropy[0].slice(0, 20) + '...',
        confidence: 0.7,
      });
    }

    return matches;
  }
}
