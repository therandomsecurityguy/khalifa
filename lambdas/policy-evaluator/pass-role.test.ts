import { detectPassRoleEscalations, passableAdminRole, passRoleCapability } from './pass-role';

const account = '111122223333';
const ci = `arn:aws:iam::${account}:role/ci-deploy`;
const admin = `arn:aws:iam::${account}:role/LambdaAdmin`;
const lambdaTrust = JSON.stringify({
  Statement: [
    { Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' },
  ],
});

function policy(...statements: object[]): string {
  return JSON.stringify({ Version: '2012-10-17', Statement: statements });
}

const createLambda = {
  Effect: 'Allow',
  Action: ['lambda:CreateFunction', 'lambda:InvokeFunction'],
  Resource: '*',
};

function detect(documents: string[], role = passableAdminRole(admin, '/', lambdaTrust)!) {
  const capability = passRoleCapability(ci, documents);
  return capability ? detectPassRoleEscalations([capability], [role], 'now') : [];
}

describe('PassRole escalation', () => {
  it('finds a principal that can pass an admin role to a Lambda it creates', () => {
    const paths = detect([
      policy({ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }, createLambda),
    ]);
    expect(paths).toEqual([
      expect.objectContaining({
        id: `esc-path:${ci}:${admin}:pass-role`,
        sourceArn: ci,
        targetArn: admin,
        escalationType: 'pass_role',
        riskLevel: 'critical',
        via: ['lambda.amazonaws.com'],
      }),
    ]);
  });

  it('matches PassRole resources against the role ARN with its path', () => {
    const role = passableAdminRole(admin, '/service-role/', lambdaTrust)!;
    expect(role.passArn).toBe(`arn:aws:iam::${account}:role/service-role/LambdaAdmin`);
    const grant = (resource: string) =>
      policy({ Effect: 'Allow', Action: 'iam:PassRole', Resource: resource }, createLambda);
    expect(detect([grant(`arn:aws:iam::${account}:role/service-role/*`)], role)).toHaveLength(1);
    expect(detect([grant(`arn:aws:iam::${account}:role/LambdaAdmin`)], role)).toEqual([]);
  });

  it('needs the compute action as well as PassRole', () => {
    const passOnly = policy({ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' });
    const createOnly = policy({ Effect: 'Allow', Action: 'lambda:CreateFunction', Resource: '*' });
    expect(detect([passOnly])).toEqual([]);
    expect(detect([passOnly, createOnly])).toEqual([]);
  });

  it('respects a Deny on PassRole for the role', () => {
    const paths = detect([
      policy(
        { Effect: 'Allow', Action: 'iam:*', Resource: '*' },
        { Effect: 'Deny', Action: 'iam:PassRole', Resource: admin.replace('LambdaAdmin', '*') },
        createLambda
      ),
    ]);
    expect(paths).toEqual([]);
  });

  it('limits a grant to the services in iam:PassedToService', () => {
    const toService = (service: string) =>
      policy(
        {
          Effect: 'Allow',
          Action: 'iam:PassRole',
          Resource: '*',
          Condition: { StringEquals: { 'iam:PassedToService': service } },
        },
        createLambda
      );
    expect(detect([toService('lambda.amazonaws.com')])).toHaveLength(1);
    expect(detect([toService('ecs-tasks.amazonaws.com')])).toEqual([]);
  });

  it('does not count a grant narrowed by another condition', () => {
    const paths = detect([
      policy(
        {
          Effect: 'Allow',
          Action: 'iam:PassRole',
          Resource: '*',
          Condition: { StringEquals: { 'aws:ResourceTag/team': 'ci' } },
        },
        createLambda
      ),
    ]);
    expect(paths).toEqual([]);
  });

  it('ignores a role the compute service does not trust, and other accounts', () => {
    const ec2Trust = lambdaTrust.replace('lambda.amazonaws.com', 'ec2.amazonaws.com');
    const docs = [policy({ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }, createLambda)];
    expect(detect(docs, passableAdminRole(admin, '/', ec2Trust)!)).toEqual([]);
    const other = passableAdminRole(
      'arn:aws:iam::999988887777:role/LambdaAdmin',
      '/',
      lambdaTrust
    )!;
    expect(detect(docs, other)).toEqual([]);
  });

  it('keeps no role that no compute service can assume', () => {
    const humanTrust = JSON.stringify({
      Statement: [{ Effect: 'Allow', Principal: { AWS: `arn:aws:iam::${account}:root` } }],
    });
    expect(passableAdminRole(admin, '/', humanTrust)).toBeUndefined();
    expect(passableAdminRole(admin, '/', '')).toBeUndefined();
  });

  it('never links a role to itself', () => {
    const capability = passRoleCapability(admin, [
      policy({ Effect: 'Allow', Action: 'iam:PassRole', Resource: '*' }, createLambda),
    ])!;
    const role = passableAdminRole(admin, '/', lambdaTrust)!;
    expect(detectPassRoleEscalations([capability], [role])).toEqual([]);
  });
});
