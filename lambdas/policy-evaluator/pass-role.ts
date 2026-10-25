import type { EscalationPath, IamConditionBlock, ParsedStatement } from './types';
import {
  isActionMatched,
  isResourceMatched,
  parsePolicyDocument,
  parseTrustPolicyDocument,
} from './policy-parser';

// Compute a principal can launch with a passed role, keyed by the service
// principal the role must trust. Any one action set, fully allowed, is enough.
export const PASS_ROLE_COMPUTE: Record<string, string[][]> = {
  'lambda.amazonaws.com': [
    ['lambda:CreateFunction', 'lambda:InvokeFunction'],
    ['lambda:CreateFunction', 'lambda:CreateEventSourceMapping'],
    ['lambda:CreateFunction', 'lambda:AddPermission'],
  ],
  'ec2.amazonaws.com': [['ec2:RunInstances']],
  'cloudformation.amazonaws.com': [['cloudformation:CreateStack'], ['cloudformation:UpdateStack']],
  'glue.amazonaws.com': [['glue:CreateDevEndpoint'], ['glue:CreateJob', 'glue:StartJobRun']],
  'sagemaker.amazonaws.com': [
    ['sagemaker:CreateNotebookInstance'],
    ['sagemaker:CreateTrainingJob'],
    ['sagemaker:CreateProcessingJob'],
  ],
  'codebuild.amazonaws.com': [['codebuild:CreateProject', 'codebuild:StartBuild']],
  'ecs-tasks.amazonaws.com': [['ecs:RegisterTaskDefinition', 'ecs:RunTask']],
};

const PASS_ROLE = 'iam:PassRole';

interface PassRoleGrant {
  resources: string[];
  notResources?: string[];
  // Service patterns from iam:PassedToService; undefined means any service.
  services?: string[];
}

export interface PassRoleCapability {
  principalArn: string;
  accountId: string;
  grants: PassRoleGrant[];
  denied: string[];
  // Service principals whose compute this principal can create.
  services: string[];
}

export interface PassableAdminRole {
  arn: string;
  accountId: string;
  // The ARN PassRole resources match against, with the role's path.
  passArn: string;
  trustedServices: string[];
}

function accountOf(arn: string): string | undefined {
  return /^arn:aws[\w-]*:iam::(\d{12}):/.exec(arn)?.[1];
}

function coversAction(statement: ParsedStatement, action: string): boolean {
  if (statement.notActions) return !statement.notActions.some((p) => isActionMatched(p, action));
  return statement.actions.some((p) => isActionMatched(p, action));
}

function hasConditions(statement: ParsedStatement): boolean {
  return !!statement.conditions && Object.keys(statement.conditions).length > 0;
}

// The services an Allow is limited to by iam:PassedToService; undefined when
// it has no conditions, null when another condition narrows it in ways this
// check does not model (the statement is then not counted).
function passedToServices(conditions: IamConditionBlock | undefined): string[] | undefined | null {
  if (!conditions || Object.keys(conditions).length === 0) return undefined;
  const services: string[] = [];
  for (const [operator, keys] of Object.entries(conditions)) {
    if (operator !== 'StringEquals' && operator !== 'StringLike') return null;
    for (const [key, values] of Object.entries(keys)) {
      if (key.toLowerCase() !== 'iam:passedtoservice') return null;
      services.push(...(Array.isArray(values) ? values : [values]));
    }
  }
  return services;
}

function actionAllowed(statements: ParsedStatement[], action: string): boolean {
  const denied = statements.some(
    (s) =>
      s.effect === 'Deny' &&
      !hasConditions(s) &&
      coversAction(s, action) &&
      !s.notResources &&
      s.resources.includes('*')
  );
  if (denied) return false;
  return statements.some(
    (s) => s.effect === 'Allow' && !hasConditions(s) && coversAction(s, action)
  );
}

// What a principal's own policies let it pass and launch. Undefined when it
// cannot do both, so only principals that matter are kept between phases.
export function passRoleCapability(
  principalArn: string,
  policyDocuments: string[]
): PassRoleCapability | undefined {
  const accountId = accountOf(principalArn);
  if (!accountId) return undefined;

  const statements: ParsedStatement[] = [];
  for (const document of policyDocuments) {
    try {
      statements.push(...parsePolicyDocument(document).Statement);
    } catch {
      // An unparseable document grants nothing, as in the effect resolver.
    }
  }

  const grants: PassRoleGrant[] = [];
  const denied: string[] = [];
  for (const statement of statements) {
    if (!coversAction(statement, PASS_ROLE)) continue;
    if (statement.effect === 'Deny') {
      // A conditional or NotResource Deny is not modelled; leaving it out can
      // only report more, never hide a path.
      if (!hasConditions(statement) && !statement.notResources) denied.push(...statement.resources);
      continue;
    }
    const services = passedToServices(statement.conditions);
    if (services === null) continue;
    grants.push({
      resources: statement.notResources ? ['*'] : statement.resources,
      notResources: statement.notResources,
      services,
    });
  }
  if (grants.length === 0) return undefined;

  const services = Object.entries(PASS_ROLE_COMPUTE)
    .filter(([, actionSets]) =>
      actionSets.some((actions) => actions.every((action) => actionAllowed(statements, action)))
    )
    .map(([service]) => service);
  if (services.length === 0) return undefined;

  return { principalArn, accountId, grants, denied, services };
}

export function passableAdminRole(
  arn: string,
  path: string,
  trustPolicyJson: string
): PassableAdminRole | undefined {
  const accountId = accountOf(arn);
  const name = /:role\/(?:.*\/)?([^/]+)$/.exec(arn)?.[1];
  if (!accountId || !name || !trustPolicyJson) return undefined;
  let trustedServices: string[];
  try {
    trustedServices = parseTrustPolicyDocument(trustPolicyJson)
      .filter((entry) => entry.principalType === 'Service')
      .map((entry) => entry.principalValue.toLowerCase())
      .filter((service) => service in PASS_ROLE_COMPUTE);
  } catch {
    return undefined;
  }
  if (trustedServices.length === 0) return undefined;
  const rolePath = path.startsWith('/') && path.endsWith('/') ? path : '/';
  return {
    arn,
    accountId,
    passArn: `arn:aws:iam::${accountId}:role${rolePath}${name}`,
    trustedServices: [...new Set(trustedServices)],
  };
}

function grantAllows(grant: PassRoleGrant, role: PassableAdminRole, service: string): boolean {
  if (!grant.resources.some((pattern) => isResourceMatched(pattern, role.passArn))) return false;
  if (grant.notResources?.some((pattern) => isResourceMatched(pattern, role.passArn))) return false;
  return !grant.services || grant.services.some((pattern) => isResourceMatched(pattern, service));
}

// A principal that can pass a same-account admin role to a service the role
// trusts, and create that service's compute, can run code as the role.
export function detectPassRoleEscalations(
  capabilities: PassRoleCapability[],
  adminRoles: PassableAdminRole[],
  detectedAt: string = new Date().toISOString()
): EscalationPath[] {
  const paths: EscalationPath[] = [];
  for (const capability of capabilities) {
    for (const role of adminRoles) {
      if (role.accountId !== capability.accountId || role.arn === capability.principalArn) continue;
      if (capability.denied.some((pattern) => isResourceMatched(pattern, role.passArn))) continue;
      const via = role.trustedServices.filter(
        (service) =>
          capability.services.includes(service) &&
          capability.grants.some((grant) => grantAllows(grant, role, service))
      );
      if (via.length === 0) continue;
      paths.push({
        id: `esc-path:${capability.principalArn}:${role.arn}:pass-role`,
        sourceArn: capability.principalArn,
        targetArn: role.arn,
        path: [{ from: capability.principalArn, to: role.arn, edgeType: 'CAN_PASS_ROLE' }],
        pathLength: 1,
        riskLevel: 'critical',
        escalationType: 'pass_role',
        conditions: {},
        via: via.sort(),
        detectedAt,
      });
    }
  }
  return paths;
}
