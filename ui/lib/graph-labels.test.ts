import { formatNodeLabel, nodeName } from './graph-labels';

describe('graph labels', () => {
  it('humanizes Neptune labels instead of screaming the raw type', () => {
    expect(formatNodeLabel('DataClassificationFinding')).toBe('Secret finding');
    expect(formatNodeLabel('LambdaFunction')).toBe('Lambda');
    expect(formatNodeLabel('Ec2Instance')).toBe('EC2 instance');
    expect(formatNodeLabel('IamRole')).toBe('IAM role');
    expect(formatNodeLabel('S3Bucket')).toBe('S3 bucket');
  });

  it('splits unknown PascalCase labels', () => {
    expect(formatNodeLabel('GuardDutyDetector')).toBe('GuardDuty detector');
    expect(formatNodeLabel('SomeNewVertex')).toBe('Some New Vertex');
  });

  it('reads the display name from properties', () => {
    expect(
      nodeName({
        id: 'finding-secret-lambda-env',
        label: 'DataClassificationFinding',
        properties: { name: 'AWS access key in Lambda environment' },
      })
    ).toBe('AWS access key in Lambda environment');
  });
});
