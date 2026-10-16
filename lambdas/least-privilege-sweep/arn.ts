export function extractAccountId(arn: string): string {
  const parts = arn.split(':');
  return parts.length >= 5 ? parts[4] : '';
}

export function extractPrincipalType(arn: string): 'role' | 'user' | 'unknown' {
  const parts = arn.split(':');
  const type = parts.length >= 6 ? parts[5] : '';
  const principalType = type.split('/')[0];
  if (principalType === 'role' || principalType === 'user') return principalType;
  return 'unknown';
}

export function isServiceLinkedRole(arn: string): boolean {
  return arn.includes('/aws-service-role/');
}
