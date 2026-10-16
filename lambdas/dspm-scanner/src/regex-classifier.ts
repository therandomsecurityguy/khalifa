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
  {
    piiType: 'github_token',
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b/g,
    confidence: 0.95,
  },
  {
    piiType: 'slack_token',
    pattern: /\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9-]{10,}\b/g,
    confidence: 0.9,
  },
  { piiType: 'stripe_key', pattern: /\b(?:sk|rk|pk)_live_[0-9a-zA-Z]{24,}\b/g, confidence: 0.95 },
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

// Credit cards are found in two stages so the regex itself stays linear.
// The old single pattern (lazy separator inside a bounded repetition) could
// backtrack exponentially on hostile input like "1 1 1 1 ..." and pin the
// scanner CPU on attacker-controlled object bytes. The candidate scan only
// matches bounded digit/separator spans; Luhn validation then runs over each
// 13-19-digit window so cards embedded next to other digit groups are still
// found without trusting any single greedy span.
const CREDIT_CARD_CANDIDATE_PATTERN = /[0-9](?:[ -]?[0-9]){11,35}/g;
const MIN_CARD_DIGITS = 13;
const MAX_CARD_DIGITS = 19;

function countCreditCards(span: string): number {
  const digits = span.replace(/\D/g, '');
  if (digits.length < MIN_CARD_DIGITS) return 0;
  // A span that strips to a card-sized number is validated as a whole; only
  // longer digit runs (e.g. cards glued to other numbers) need windowing.
  if (digits.length <= MAX_CARD_DIGITS) return luhnCheck(digits) ? 1 : 0;
  const seen = new Set<string>();
  let count = 0;
  const maxStart = digits.length - MIN_CARD_DIGITS;
  for (let start = 0; start <= maxStart; start++) {
    const maxLength = Math.min(MAX_CARD_DIGITS, digits.length - start);
    for (let length = MIN_CARD_DIGITS; length <= maxLength; length++) {
      const window = digits.slice(start, start + length);
      if (seen.has(window)) continue;
      seen.add(window);
      if (luhnCheck(window)) count++;
    }
  }
  return count;
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

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input: string): Uint8Array {
  let bits = 0;
  let value = 0;
  const output: number[] = [];
  for (const char of input) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) return new Uint8Array(0);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

function crc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of data) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export function isValidAwsAccessKey(key: string): boolean {
  if (!/^[A-Z0-9]{20}$/.test(key)) return false;
  const decoded = base32Decode(key.slice(4));
  if (decoded.length !== 10) return false;
  const data = decoded.slice(0, 6);
  const checksum = ((decoded[6] << 24) | (decoded[7] << 16) | (decoded[8] << 8) | decoded[9]) >>> 0;
  return crc32(data) === checksum;
}

export class RegexClassifier implements Classifier {
  readonly name = 'regex';

  async classify(content: string): Promise<ClassificationMatch[]> {
    const matches: ClassificationMatch[] = [];

    for (const { piiType, pattern, confidence } of PATTERNS) {
      const found = content.match(pattern);
      if (!found || found.length === 0) continue;

      let validCount = found.length;
      if (piiType === 'aws_access_key') {
        validCount = found.filter((f) => isValidAwsAccessKey(f)).length;
      }

      if (validCount === 0) continue;
      matches.push({
        piiType,
        count: validCount,
        confidence,
      });
    }

    const creditCardCandidates = content.match(CREDIT_CARD_CANDIDATE_PATTERN) || [];
    const validCreditCards = creditCardCandidates.reduce(
      (sum, span) => sum + countCreditCards(span),
      0
    );
    if (validCreditCards > 0) {
      matches.push({
        piiType: 'credit_card',
        count: validCreditCards,
        confidence: 0.6,
      });
    }

    const highEntropy = findHighEntropySecrets(content);
    if (highEntropy.length > 0) {
      matches.push({
        piiType: 'high_entropy_secret',
        count: highEntropy.length,
        confidence: 0.7,
      });
    }

    return matches;
  }
}
