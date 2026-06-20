import {
  evaluateCondition,
  evaluateConditionBlock,
  KNOWN_CONDITION_KEYS,
} from './condition-evaluator';
import type { ConditionEvaluationContext, IamConditionBlock } from './types';

describe('evaluateCondition', () => {
  const baseContext: ConditionEvaluationContext = {
    sourceVpc: 'vpc-12345',
    sourceIp: '10.0.0.5',
    sourceArn: 'arn:aws:s3:::my-bucket',
    secureTransport: true,
    userAgent: 'aws-cli/2.0',
    s3Prefix: 'logs/',
  };

  it('returns conditional when context value is undefined', () => {
    const result = evaluateCondition('StringEquals', 'aws:SourceVpc', ['vpc-12345'], {});
    expect(result).toBe('conditional');
  });

  describe('StringEquals', () => {
    it('returns true when string matches', () => {
      expect(evaluateCondition('StringEquals', 'aws:SourceVpc', ['vpc-12345'], baseContext)).toBe(
        true
      );
    });

    it('returns false when string does not match', () => {
      expect(evaluateCondition('StringEquals', 'aws:SourceVpc', ['vpc-99999'], baseContext)).toBe(
        false
      );
    });
  });

  describe('StringNotEquals', () => {
    it('returns true when string does not match', () => {
      expect(
        evaluateCondition('StringNotEquals', 'aws:SourceVpc', ['vpc-99999'], baseContext)
      ).toBe(true);
    });

    it('returns false when string matches', () => {
      expect(
        evaluateCondition('StringNotEquals', 'aws:SourceVpc', ['vpc-12345'], baseContext)
      ).toBe(false);
    });
  });

  describe('StringLike', () => {
    it('matches wildcard patterns', () => {
      expect(
        evaluateCondition('StringLike', 'aws:SourceArn', ['arn:aws:s3:::my-*'], baseContext)
      ).toBe(true);
    });

    it('does not match non-matching patterns', () => {
      expect(
        evaluateCondition('StringLike', 'aws:SourceArn', ['arn:aws:s3:::other-*'], baseContext)
      ).toBe(false);
    });
  });

  describe('IpAddress', () => {
    it('matches IP in CIDR range', () => {
      expect(evaluateCondition('IpAddress', 'aws:SourceIp', ['10.0.0.0/16'], baseContext)).toBe(
        true
      );
    });

    it('does not match IP outside CIDR range', () => {
      expect(evaluateCondition('IpAddress', 'aws:SourceIp', ['192.168.0.0/16'], baseContext)).toBe(
        false
      );
    });

    it('matches exact IP', () => {
      expect(evaluateCondition('IpAddress', 'aws:SourceIp', ['10.0.0.5'], baseContext)).toBe(true);
    });
  });

  describe('NotIpAddress', () => {
    it('returns false when IP is in CIDR range', () => {
      expect(evaluateCondition('NotIpAddress', 'aws:SourceIp', ['10.0.0.0/16'], baseContext)).toBe(
        false
      );
    });

    it('returns true when IP is outside CIDR range', () => {
      expect(
        evaluateCondition('NotIpAddress', 'aws:SourceIp', ['192.168.0.0/16'], baseContext)
      ).toBe(true);
    });
  });

  describe('ArnEquals', () => {
    it('matches exact ARN', () => {
      expect(
        evaluateCondition('ArnEquals', 'aws:SourceArn', ['arn:aws:s3:::my-bucket'], baseContext)
      ).toBe(true);
    });

    it('does not match different ARN', () => {
      expect(
        evaluateCondition('ArnEquals', 'aws:SourceArn', ['arn:aws:s3:::other'], baseContext)
      ).toBe(false);
    });
  });

  describe('Bool', () => {
    it('matches boolean true', () => {
      expect(evaluateCondition('Bool', 'aws:SecureTransport', ['true'], baseContext)).toBe(true);
    });

    it('does not match boolean false', () => {
      expect(evaluateCondition('Bool', 'aws:SecureTransport', ['false'], baseContext)).toBe(false);
    });
  });

  describe('NumericEquals', () => {
    it('matches equal numbers', () => {
      const ctx: ConditionEvaluationContext = { ...baseContext };
      (ctx as any).SomeNumber = '42';
      expect(evaluateCondition('NumericEquals', 'kms:SomeNumber', ['42'], ctx)).toBe(true);
    });
  });

  describe('Null', () => {
    it('returns true when key is null and checking for null', () => {
      const result = evaluateCondition('Null', 'aws:NonExistentKey', ['true'], {});
      expect(result).toBe(true);
    });
  });

  describe('Unknown operator', () => {
    it('returns conditional for unknown operators', () => {
      expect(evaluateCondition('UnknownOp', 'aws:SourceVpc', ['vpc-12345'], baseContext)).toBe(
        'conditional'
      );
    });
  });
});

describe('evaluateConditionBlock', () => {
  it('returns true when all conditions are met', () => {
    const block: IamConditionBlock = {
      StringEquals: { 'aws:SourceVpc': ['vpc-12345'] },
    };
    const context: ConditionEvaluationContext = { sourceVpc: 'vpc-12345' };
    expect(evaluateConditionBlock(block, context)).toBe(true);
  });

  it('returns false when any condition fails', () => {
    const block: IamConditionBlock = {
      StringEquals: { 'aws:SourceVpc': ['vpc-99999'] },
    };
    const context: ConditionEvaluationContext = { sourceVpc: 'vpc-12345' };
    expect(evaluateConditionBlock(block, context)).toBe(false);
  });

  it('returns conditional when context value is missing', () => {
    const block: IamConditionBlock = {
      StringEquals: { 'aws:SourceVpc': ['vpc-12345'] },
    };
    expect(evaluateConditionBlock(block, {})).toBe('conditional');
  });

  it('evaluates multiple conditions with AND logic', () => {
    const block: IamConditionBlock = {
      StringEquals: { 'aws:SourceVpc': ['vpc-12345'] },
      IpAddress: { 'aws:SourceIp': ['10.0.0.0/16'] },
    };
    const context: ConditionEvaluationContext = { sourceVpc: 'vpc-12345', sourceIp: '10.0.0.5' };
    expect(evaluateConditionBlock(block, context)).toBe(true);
  });

  it('returns false when one of multiple conditions fails', () => {
    const block: IamConditionBlock = {
      StringEquals: { 'aws:SourceVpc': ['vpc-12345'] },
      IpAddress: { 'aws:SourceIp': ['192.168.0.0/16'] },
    };
    const context: ConditionEvaluationContext = { sourceVpc: 'vpc-12345', sourceIp: '10.0.0.5' };
    expect(evaluateConditionBlock(block, context)).toBe(false);
  });
});

describe('KNOWN_CONDITION_KEYS', () => {
  it('contains aws condition keys', () => {
    expect(KNOWN_CONDITION_KEYS.aws).toContain('aws:SourceVpc');
    expect(KNOWN_CONDITION_KEYS.aws).toContain('aws:SourceIp');
  });

  it('contains s3 condition keys', () => {
    expect(KNOWN_CONDITION_KEYS.s3).toContain('s3:prefix');
  });

  it('contains kms condition keys', () => {
    expect(KNOWN_CONDITION_KEYS.kms).toContain('kms:EncryptionContext');
  });
});
