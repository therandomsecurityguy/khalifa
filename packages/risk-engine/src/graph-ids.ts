export function effectivePermissionId(principalArn: string): string {
  return `eff-perm:${principalArn}`;
}
