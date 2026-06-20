export interface ParsedStatement {
  sid?: string;
  effect: 'Allow' | 'Deny';
  actions: string[];
  resources: string[];
  conditions?: IamConditionBlock;
  notActions?: string[];
  notResources?: string[];
}

export interface IamConditionBlock {
  [operator: string]: {
    [key: string]: string | string[];
  };
}

export interface EffectivePermission {
  id: string;
  principalArn: string;
  allowedActions: string[];
  deniedActions: string[];
  conditionalGrants: ConditionalGrant[];
  policiesEvaluated: string[];
  evaluatedAt: string;
  isAdmin: boolean;
  blastRadius: number;
}

export interface ConditionalGrant {
  action: string;
  resource: string;
  conditions: IamConditionBlock;
}

export type EscalationType = 'admin' | 'privilege_escalation' | 'lateral_movement';

export interface EscalationPath {
  id: string;
  sourceArn: string;
  targetArn: string;
  path: { from: string; to: string; edgeType: string }[];
  pathLength: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  escalationType: EscalationType;
  conditions: IamConditionBlock;
  detectedAt: string;
}

export interface ServiceActions {
  service: string;
  actions: string[];
}

export interface UnusedPermissions {
  principalArn: string;
  unusedActions: ServiceActions[];
  usedActions: ServiceActions[];
  lastAnalyzed: string;
}

export interface RightsizingRecommendation {
  principalArn: string;
  currentPolicy: ParsedStatement[];
  recommendedPolicy: ParsedStatement[];
  removedActions: string[];
  keptActions: string[];
  riskLevel: 'low' | 'medium' | 'high';
  confidence: number;
}

export interface ConditionEvaluationContext {
  principal?: string;
  sourceIp?: string;
  sourceVpc?: string;
  sourceArn?: string;
  requestTime?: Date;
  encryptionContext?: Record<string, string>;
  s3Prefix?: string;
  userAgent?: string;
  secureTransport?: boolean;
  tokenActions?: string[];
  keyOrigin?: string;
  callerAccount?: string;
  viaService?: string;
}

export type ConditionResult = boolean | 'conditional';

export const ADMIN_ACTIONS = [
  '*',
  '*:*',
  'iam:*',
  'organizations:*',
  'sts:AssumeRole',
  'iam:CreateAccessKey',
  'iam:CreateLoginProfile',
  'iam:UpdateLoginProfile',
  'iam:AttachUserPolicy',
  'iam:AttachRolePolicy',
  'iam:PutUserPolicy',
  'iam:PutRolePolicy',
  'iam:PassRole',
  'iam:AddUserToGroup',
  'iam:CreateRole',
  'iam:CreateUser',
  'iam:CreatePolicy',
  'iam:DeleteRolePolicy',
  'iam:DeleteUserPolicy',
];

export const PRIVILEGE_ESCALATION_ACTIONS = [
  'iam:PassRole',
  'iam:CreateAccessKey',
  'iam:CreateLoginProfile',
  'iam:UpdateLoginProfile',
  'iam:AttachUserPolicy',
  'iam:AttachRolePolicy',
  'iam:PutUserPolicy',
  'iam:PutRolePolicy',
  'iam:AddUserToGroup',
  'iam:CreateRole',
  'iam:CreatePolicy',
  'sts:AssumeRole',
  'lambda:CreateFunction',
  'lambda:UpdateFunctionCode',
  'ec2:RunInstances',
  'cloudformation:CreateStack',
  'cloudformation:UpdateStack',
];