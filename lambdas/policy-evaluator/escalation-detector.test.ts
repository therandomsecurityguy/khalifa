import { detectEscalationPaths, detectLateralMovement } from './escalation-detector';
import type { TrustEdge, RoleWithPermissions } from './escalation-detector';

describe('detectEscalationPaths', () => {
  it('detects direct trust to admin role', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:root',
        to: 'arn:aws:iam::444455556666:role/AdminRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::444455556666:role/AdminRole', allowedActions: ['*'], isAdmin: true },
    ];

    const paths = detectEscalationPaths(trustEdges, roles);
    expect(paths.length).toBeGreaterThanOrEqual(1);
    expect(paths[0].escalationType).toBe('admin');
    expect(paths[0].riskLevel).toBe('critical');
    expect(paths[0].sourceArn).toBe('arn:aws:iam::111122223333:root');
    expect(paths[0].targetArn).toBe('arn:aws:iam::444455556666:role/AdminRole');
  });

  it('detects privilege escalation via iam:PassRole', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:user/DevUser',
        to: 'arn:aws:iam::444455556666:role/PowerRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::444455556666:role/PowerRole', allowedActions: ['iam:PassRole', 'ec2:RunInstances'], isAdmin: false },
    ];

    const paths = detectEscalationPaths(trustEdges, roles);
    expect(paths.some((p) => p.escalationType === 'privilege_escalation')).toBe(true);
    expect(paths.some((p) => p.riskLevel === 'high')).toBe(true);
  });

  it('detects chained trust paths', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:root',
        to: 'arn:aws:iam::444455556666:role/IntermediateRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
      {
        from: 'arn:aws:iam::444455556666:role/IntermediateRole',
        to: 'arn:aws:iam::555566667777:role/AdminRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::444455556666:role/IntermediateRole', allowedActions: ['sts:AssumeRole'], isAdmin: false },
      { arn: 'arn:aws:iam::555566667777:role/AdminRole', allowedActions: ['*'], isAdmin: true },
    ];

    const paths = detectEscalationPaths(trustEdges, roles, undefined, 3);
    expect(paths.some((p) => p.escalationType === 'admin')).toBe(true);
  });

  it('respects maxHops limit', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:root',
        to: 'arn:aws:iam::222233334444:role/RoleA',
        principalType: 'AWS',
        isCrossAccount: true,
      },
      {
        from: 'arn:aws:iam::222233334444:role/RoleA',
        to: 'arn:aws:iam::333344445555:role/RoleB',
        principalType: 'AWS',
        isCrossAccount: true,
      },
      {
        from: 'arn:aws:iam::333344445555:role/RoleB',
        to: 'arn:aws:iam::444455556666:role/RoleC',
        principalType: 'AWS',
        isCrossAccount: true,
      },
      {
        from: 'arn:aws:iam::444455556666:role/RoleC',
        to: 'arn:aws:iam::555566667777:role/AdminRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::555566667777:role/AdminRole', allowedActions: ['*'], isAdmin: true },
    ];

    const paths2 = detectEscalationPaths(trustEdges, roles, undefined, 2);
    const paths4 = detectEscalationPaths(trustEdges, roles, undefined, 4);
    expect(paths4.length).toBeGreaterThanOrEqual(paths2.length);
  });

  it('filters by source account', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:root',
        to: 'arn:aws:iam::444455556666:role/AdminRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
      {
        from: 'arn:aws:iam::999988887777:root',
        to: 'arn:aws:iam::444455556666:role/AdminRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::444455556666:role/AdminRole', allowedActions: ['*'], isAdmin: true },
    ];

    const paths = detectEscalationPaths(trustEdges, roles, '111122223333');
    expect(paths.every((p) => p.sourceArn.includes('111122223333'))).toBe(true);
  });

  it('deduplicates paths', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:root',
        to: 'arn:aws:iam::444455556666:role/AdminRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::444455556666:role/AdminRole', allowedActions: ['*'], isAdmin: true },
    ];

    const paths = detectEscalationPaths(trustEdges, roles);
    const uniqueKeys = new Set(paths.map((p) => `${p.sourceArn}:${p.targetArn}:${p.escalationType}`));
    expect(uniqueKeys.size).toBe(paths.length);
  });
});

describe('detectLateralMovement', () => {
  it('detects cross-account trust to role with data access', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:root',
        to: 'arn:aws:iam::444455556666:role/DataRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::444455556666:role/DataRole', allowedActions: ['s3:GetObject', 'dynamodb:Query'], isAdmin: false },
    ];

    const paths = detectLateralMovement(trustEdges, roles);
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].escalationType).toBe('lateral_movement');
    expect(paths[0].riskLevel).toBe('medium');
  });

  it('ignores roles without data actions', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:root',
        to: 'arn:aws:iam::444455556666:role/NoDataRole',
        principalType: 'AWS',
        isCrossAccount: true,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::444455556666:role/NoDataRole', allowedActions: ['ec2:DescribeInstances'], isAdmin: false },
    ];

    const paths = detectLateralMovement(trustEdges, roles);
    expect(paths).toHaveLength(0);
  });

  it('ignores same-account trust edges', () => {
    const trustEdges: TrustEdge[] = [
      {
        from: 'arn:aws:iam::111122223333:role/InternalRole',
        to: 'arn:aws:iam::111122223333:role/DataRole',
        principalType: 'AWS',
        isCrossAccount: false,
      },
    ];

    const roles: RoleWithPermissions[] = [
      { arn: 'arn:aws:iam::111122223333:role/DataRole', allowedActions: ['s3:GetObject'], isAdmin: false },
    ];

    const paths = detectLateralMovement(trustEdges, roles);
    expect(paths).toHaveLength(0);
  });
});