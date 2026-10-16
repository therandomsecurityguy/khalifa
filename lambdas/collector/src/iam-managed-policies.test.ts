import { buildAwsManagedPolicyNode, isAwsManagedPolicyArn } from './iam-managed-policies';

describe('isAwsManagedPolicyArn', () => {
  it.each([
    ['arn:aws:iam::aws:policy/AWSSupportAccess', true],
    ['arn:aws:iam::aws:policy/service-role/AWSConfigRole', true],
    ['arn:aws-us-gov:iam::aws:policy/AWSCloudShellFullAccess', true],
    // Customer-managed policies already get a vertex from ListPolicies.
    ['arn:aws:iam::111122223333:policy/custom', false],
    [undefined, false],
  ])('%s -> %s', (arn, want) => {
    expect(isAwsManagedPolicyArn(arn as string | undefined)).toBe(want);
  });
});

describe('buildAwsManagedPolicyNode', () => {
  // The id must be the bare ARN: it is the target of every ATTACHED_TO edge to
  // this policy and the source of the CONTAINS edge to its document. Any other
  // id and those edges are skipped exactly as before.
  it('keys the vertex on the policy ARN so existing edges resolve', () => {
    const arn = 'arn:aws:iam::aws:policy/AWSSupportAccess';

    const node = buildAwsManagedPolicyNode(arn, 'AWSSupportAccess', '111122223333');

    expect(node.id).toBe(arn);
    expect(node.label).toBe('IamPolicy');
    expect(node.properties).toMatchObject({ arn, policy_type: 'aws-managed' });
  });

  it('falls back to the ARN tail when no name is supplied', () => {
    const node = buildAwsManagedPolicyNode(
      'arn:aws:iam::aws:policy/AWSCloudShellFullAccess',
      undefined,
      '111122223333'
    );

    expect(node.properties.id).toBe('AWSCloudShellFullAccess');
  });
});
