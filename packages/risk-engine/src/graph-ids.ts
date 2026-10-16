/**
 * Deterministic graph ids that both writers (CIEM lambdas) and readers (API,
 * rules) must agree on. Neptune serves id lookups from its index, so anything
 * looked up per principal is keyed here instead of by a property filter that
 * scans the whole label.
 */
export function effectivePermissionId(principalArn: string): string {
  return `eff-perm:${principalArn}`;
}
