// IamRole vertex ids are arn:aws:iam::<account>:role/<RoleName> without the
// role's path (collectIam builds them from RoleName). An edge to any other form,
// such as a Lambda's role ARN with /service-role/, points at no vertex and the
// graph writer drops it, so every edge to a role goes through this.
const ROLE_ARN = /^arn:aws:iam::(\d{12}):role\/(?:.*\/)?([^/]+)$/;

export function roleVertexId(accountId: string, arnOrName: string): string {
  const match = ROLE_ARN.exec(arnOrName);
  return match
    ? `arn:aws:iam::${match[1]}:role/${match[2]}`
    : `arn:aws:iam::${accountId}:role/${arnOrName}`;
}

export function isRoleArn(value: string): boolean {
  return ROLE_ARN.test(value);
}
