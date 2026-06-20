import { resolveEffectivePermissions, checkActionAllowed } from './effect-resolver';
import type { ResolveInput, PermissionBoundary } from './effect-resolver';
import type { EffectivePermission } from './types';

const makePolicy = (statements: { effect: 'Allow' | 'Deny'; action: string | string[]; resource?: string | string[]; condition?: any }[]) => {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: statements.map((s) => ({
      Effect: s.effect,
      Action: s.action,
      Resource: s.resource || '*',
      ...(s.condition ? { Condition: s.condition } : {}),
    })),
  });
};

describe('resolveEffectivePermissions', () => {
  it('resolves a simple Allow policy', () => {
    const input: ResolveInput = {
      principalArn: 'arn:aws:iam::123456:role/TestRole',
      identityPolicies: [
        {
          policyArn: 'arn:aws:iam::123456:policy/TestPolicy',
          policyDocumentJson: makePolicy([{ effect: 'Allow', action: 's3:GetObject' }]),
        },
      ],
    };

    const result = resolveEffectivePermissions(input);
    expect(result.allowedActions).toContain('s3:GetObject');
    expect(result.isAdmin).toBe(false);
    expect(result.policiesEvaluated).toContain('arn:aws:iam::123456:policy/TestPolicy');
  });

  it('explicit Deny wins over Allow', () => {
    const input: ResolveInput = {
      principalArn: 'arn:aws:iam::123456:role/TestRole',
      identityPolicies: [
        {
          policyArn: 'policy-allow',
          policyDocumentJson: makePolicy([{ effect: 'Allow', action: ['s3:GetObject', 's3:PutObject'] }]),
        },
        {
          policyArn: 'policy-deny',
          policyDocumentJson: makePolicy([{ effect: 'Deny', action: 's3:PutObject' }]),
        },
      ],
    };

    const result = resolveEffectivePermissions(input);
    expect(result.allowedActions).toContain('s3:GetObject');
    expect(result.allowedActions).not.toContain('s3:PutObject');
    expect(result.deniedActions).toContain('s3:PutObject');
  });

  it('detects admin when * is allowed', () => {
    const input: ResolveInput = {
      principalArn: 'arn:aws:iam::123456:role/AdminRole',
      identityPolicies: [
        {
          policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
          policyDocumentJson: makePolicy([{ effect: 'Allow', action: '*' }]),
        },
      ],
    };

    const result = resolveEffectivePermissions(input);
    expect(result.isAdmin).toBe(true);
  });

  it('handles conditional grants', () => {
    const input: ResolveInput = {
      principalArn: 'arn:aws:iam::123456:role/ConditionalRole',
      identityPolicies: [
        {
          policyArn: 'policy-conditional',
          policyDocumentJson: makePolicy([{
            effect: 'Allow',
            action: 's3:GetObject',
            condition: { StringEquals: { 'aws:SourceVpc': 'vpc-12345' } },
          }]),
        },
      ],
    };

    const result = resolveEffectivePermissions(input);
    expect(result.conditionalGrants).toHaveLength(1);
    expect(result.conditionalGrants[0].action).toBe('s3:GetObject');
  });

  it('permission boundary scopes wildcard to boundary actions', () => {
    const input: ResolveInput = {
      principalArn: 'arn:aws:iam::123456:role/BoundaryRole',
      identityPolicies: [
        {
          policyArn: 'policy-allow-all',
          policyDocumentJson: makePolicy([{ effect: 'Allow', action: '*' }]),
        },
      ],
      permissionBoundary: {
        policyArn: 'boundary-policy',
        policyDocumentJson: makePolicy([{ effect: 'Allow', action: 's3:GetObject' }]),
      },
    };

    const result = resolveEffectivePermissions(input);
    expect(result.allowedActions).toContain('s3:GetObject');
    expect(result.allowedActions).not.toContain('*');
    expect(result.allowedActions).not.toContain('iam:*');
    expect(result.isAdmin).toBe(false);
  });

  it('handles multiple identity policies', () => {
    const input: ResolveInput = {
      principalArn: 'arn:aws:iam::123456:role/MultiRole',
      identityPolicies: [
        {
          policyArn: 'policy-s3',
          policyDocumentJson: makePolicy([{ effect: 'Allow', action: 's3:GetObject' }]),
        },
        {
          policyArn: 'policy-dynamodb',
          policyDocumentJson: makePolicy([{ effect: 'Allow', action: 'dynamodb:GetItem' }]),
        },
      ],
    };

    const result = resolveEffectivePermissions(input);
    expect(result.allowedActions).toContain('s3:GetObject');
    expect(result.allowedActions).toContain('dynamodb:GetItem');
  });

  it('sets blastRadius to count of allowed actions', () => {
    const input: ResolveInput = {
      principalArn: 'arn:aws:iam::123456:role/TestRole',
      identityPolicies: [
        {
          policyArn: 'policy-multi',
          policyDocumentJson: makePolicy([{ effect: 'Allow', action: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'] }]),
        },
      ],
    };

    const result = resolveEffectivePermissions(input);
    expect(result.blastRadius).toBe(3);
  });

  it('handles invalid JSON gracefully', () => {
    const input: ResolveInput = {
      principalArn: 'arn:aws:iam::123456:role/TestRole',
      identityPolicies: [
        {
          policyArn: 'policy-invalid',
          policyDocumentJson: 'not json',
        },
      ],
    };

    const result = resolveEffectivePermissions(input);
    expect(result.allowedActions).toEqual([]);
    expect(result.policiesEvaluated).not.toContain('policy-invalid');
  });
});

describe('checkActionAllowed', () => {
  const perm: EffectivePermission = {
    id: 'eff-perm:test',
    principalArn: 'arn:aws:iam::123456:role/TestRole',
    allowedActions: ['s3:GetObject', 's3:PutObject'],
    deniedActions: ['iam:*'],
    conditionalGrants: [{
      action: 'kms:Decrypt',
      resource: '*',
      conditions: { StringEquals: { 'aws:SourceVpc': ['vpc-12345'] } },
    }],
    policiesEvaluated: ['policy-1'],
    evaluatedAt: '2024-01-01T00:00:00Z',
    isAdmin: false,
    blastRadius: 2,
  };

  it('allows an explicitly allowed action', () => {
    expect(checkActionAllowed(perm, 's3:GetObject').allowed).toBe(true);
  });

  it('denies an explicitly denied action', () => {
    expect(checkActionAllowed(perm, 'iam:CreateUser').allowed).toBe(false);
    expect(checkActionAllowed(perm, 'iam:CreateUser').reason).toBe('Explicit deny');
  });

  it('denies an action not in allowed or denied (implicit deny)', () => {
    expect(checkActionAllowed(perm, 'ec2:RunInstances').allowed).toBe(false);
    expect(checkActionAllowed(perm, 'ec2:RunInstances').reason).toBe('Implicit deny');
  });

  it('returns conditional for conditional grants without context', () => {
    const result = checkActionAllowed(perm, 'kms:Decrypt');
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('Conditional (no context provided)');
  });

  it('allows conditional grant when conditions are met', () => {
    const result = checkActionAllowed(perm, 'kms:Decrypt', undefined, { sourceVpc: 'vpc-12345' });
    expect(result.allowed).toBe(true);
  });

  it('denies conditional grant when conditions are not met', () => {
    const result = checkActionAllowed(perm, 'kms:Decrypt', undefined, { sourceVpc: 'vpc-99999' });
    expect(result.allowed).toBe(false);
  });
});