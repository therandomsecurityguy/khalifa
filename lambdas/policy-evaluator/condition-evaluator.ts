import type { ConditionResult, ConditionEvaluationContext, IamConditionBlock } from './types';

export function evaluateCondition(
  operator: string,
  key: string,
  values: string[],
  context: ConditionEvaluationContext
): ConditionResult {
  const contextValue = getContextValue(key, context);
  if (contextValue === undefined && operator !== 'Null') return 'conditional';
  const cv = contextValue ?? '';

  switch (operator) {
    case 'StringEquals':
    case 'string:eq':
      return values.some((v) => cv.toLowerCase() === v.toLowerCase());
    case 'StringNotEquals':
      return values.every((v) => cv.toLowerCase() !== v.toLowerCase());
    case 'StringEqualsIgnoreCase':
      return values.some((v) => cv.toLowerCase() === v.toLowerCase());
    case 'StringNotEqualsIgnoreCase':
      return values.every((v) => cv.toLowerCase() !== v.toLowerCase());
    case 'StringLike':
      return values.some((v) => wildcardMatch(v, cv));
    case 'StringNotLike':
      return values.every((v) => !wildcardMatch(v, cv));
    case 'IpAddress':
    case 'NotIpAddress':
      const ipResult = values.some((v) => isIpInCidr(cv, v));
      return operator === 'IpAddress' ? ipResult : !ipResult;
    case 'ArnEquals':
    case 'ArnLike':
      return values.some((v) => arnMatch(v, cv));
    case 'ArnNotEquals':
    case 'ArnNotLike':
      return values.every((v) => !arnMatch(v, cv));
    case 'NumericEquals':
      return values.some((v) => parseFloat(cv) === parseFloat(v));
    case 'NumericNotEquals':
      return values.every((v) => parseFloat(cv) !== parseFloat(v));
    case 'NumericLessThan':
      return values.some((v) => parseFloat(cv) < parseFloat(v));
    case 'NumericLessThanEquals':
      return values.some((v) => parseFloat(cv) <= parseFloat(v));
    case 'NumericGreaterThan':
      return values.some((v) => parseFloat(cv) > parseFloat(v));
    case 'NumericGreaterThanEquals':
      return values.some((v) => parseFloat(cv) >= parseFloat(v));
    case 'Bool':
      return values.some((v) => {
        const boolCv = cv.toLowerCase();
        return (
          (v.toLowerCase() === 'true' && boolCv === 'true') ||
          (v.toLowerCase() === 'false' && boolCv === 'false')
        );
      });
    case 'DateEquals':
      return values.some((v) => new Date(cv).getTime() === new Date(v).getTime());
    case 'DateLessThan':
      return values.some((v) => new Date(cv).getTime() < new Date(v).getTime());
    case 'DateGreaterThan':
      return values.some((v) => new Date(cv).getTime() > new Date(v).getTime());
    case 'Null':
      const isNull = cv === '';
      return values[0]?.toLowerCase() === 'true' ? isNull : !isNull;
    default:
      return 'conditional';
  }
}

export function evaluateConditionBlock(
  conditionBlock: IamConditionBlock,
  context: ConditionEvaluationContext
): ConditionResult {
  for (const [operator, keys] of Object.entries(conditionBlock)) {
    for (const [key, values] of Object.entries(keys)) {
      const result = evaluateCondition(operator, key, values as string[], context);
      if (result === false) return false;
      if (result === 'conditional') return 'conditional';
    }
  }
  return true;
}

function getContextValue(key: string, context: ConditionEvaluationContext): string | undefined {
  const keyLower = key.toLowerCase();
  if (keyLower === 'aws:sourcevpc' || keyLower === 'aws_sourcevpc') return context.sourceVpc;
  if (keyLower === 'aws:sourceip' || keyLower === 'aws_sourceip') return context.sourceIp;
  if (keyLower === 'aws:sourcearn' || keyLower === 'aws_sourcearn') return context.sourceArn;
  if (keyLower === 'aws:useragent' || keyLower === 'aws_useragent') return context.userAgent;
  if (keyLower === 'aws:securetransport' || keyLower === 'aws_securetransport') {
    return context.secureTransport !== undefined ? String(context.secureTransport) : undefined;
  }
  if (keyLower === 'aws:tokenactions' || keyLower === 'aws_tokenactions') {
    return context.tokenActions?.join(',');
  }
  if (keyLower === 's3:prefix' || keyLower === 's3_prefix') return context.s3Prefix;
  if (
    keyLower.startsWith('kms:encryptioncontext:') ||
    keyLower.startsWith('kms_encryptioncontext_')
  ) {
    const ctxKey = key.split(':').slice(2).join(':');
    return context.encryptionContext?.[ctxKey];
  }
  if (keyLower === 'kms:keyorigin' || keyLower === 'kms_keyorigin') return context.keyOrigin;
  if (keyLower === 'kms:calleraccount' || keyLower === 'kms_calleraccount')
    return context.callerAccount;
  if (keyLower === 'kms:viaservice' || keyLower === 'kms_viaservice') return context.viaService;
  if (keyLower === 'aws:principalaccount' || keyLower === 'aws_principalaccount') {
    return context.principal?.split(':')[4];
  }

  const keyWithoutPrefix = key
    .replace(/^(aws|s3|kms|ec2|lambda|dynamodb|rds|ssm):/i, '')
    .toLowerCase();
  for (const [ctxKey, ctxVal] of Object.entries(context)) {
    if (ctxVal === undefined || ctxVal === null) continue;
    if (typeof ctxVal === 'object' && !Array.isArray(ctxVal)) continue;
    const normalizedCtxKey = ctxKey.toLowerCase();
    if (normalizedCtxKey === keyWithoutPrefix || normalizedCtxKey === keyLower) {
      return String(ctxVal);
    }
  }

  return undefined;
}

function wildcardMatch(pattern: string, text: string): boolean {
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  const regex = new RegExp(`^${regexStr}$`, 'i');
  return regex.test(text);
}

function arnMatch(pattern: string, arn: string): boolean {
  return wildcardMatch(pattern, arn);
}

function isIpInCidr(ip: string, cidr: string): boolean {
  if (!cidr.includes('/')) return ip === cidr;
  const [networkStr, prefixLenStr] = cidr.split('/');
  const prefixLen = parseInt(prefixLenStr, 10);
  const ipInt = ipToInt(ip);
  const networkInt = ipToInt(networkStr);
  if (ipInt === null || networkInt === null) return false;
  const mask = prefixLen === 0 ? 0 : (~0 << (32 - prefixLen)) >>> 0;
  return (ipInt & mask) === (networkInt & mask);
}

function ipToInt(ip: string): number | null {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export const KNOWN_CONDITION_KEYS: Record<string, string[]> = {
  aws: [
    'aws:SourceVpc',
    'aws:SourceIp',
    'aws:SourceArn',
    'aws:SourceAccount',
    'aws:UserAgent',
    'aws:SecureTransport',
    'aws:TokenActions',
    'aws:PrincipalAccount',
    'aws:PrincipalOrgID',
    'aws:PrincipalTag',
    'aws:PrincipalType',
  ],
  s3: [
    's3:prefix',
    's3:list-type',
    's3:x-amz-content-sha256',
    's3:authType',
    's3:ResourceAccount',
    's3:ExistingObjectTag',
  ],
  kms: [
    'kms:EncryptionContext',
    'kms:GrantIsForAWSResource',
    'kms:ViaService',
    'kms:CallerAccount',
    'kms:KeyOrigin',
    'kms:EncryptionContextMatches',
    'kms:ReEncryptOn',
  ],
  ec2: [
    'ec2:ResourceTag',
    'ec2:AvailabilityZone',
    'ec2:Region',
    'ec2:InstanceType',
    'ec2:RootDeviceType',
    'ec2:Vpc',
  ],
  lambda: [
    'lambda:FunctionArn',
    'lambda:FunctionAuthType',
    'lambda:FunctionRequestAuthType',
    'lambda:CodeSigningConfigArn',
  ],
  dynamodb: [
    'dynamodb:LeadingKeys',
    'dynamodb:Select',
    'dynamodb:Attributes',
    'dynamodb:ReturnConsumedCapacity',
    'dynamodb:ReturnValues',
  ],
  rds: ['rds:db-tag', 'rds:DatabaseEngine', 'rds:DatabaseClass', 'rds:StorageType'],
  ssm: ['ssm:resourceTag', 'ssm:RunDocumentName'],
};
