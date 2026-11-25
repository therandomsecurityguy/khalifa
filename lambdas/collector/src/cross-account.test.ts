import { AI_SERVICE_PRINCIPALS, extractTrustedAiServices } from './cross-account';

const policy = (principal: unknown, effect = 'Allow') =>
  JSON.stringify({
    Version: '2012-10-17',
    Statement: [{ Effect: effect, Principal: principal, Action: 'sts:AssumeRole' }],
  });

describe('extractTrustedAiServices', () => {
  it('finds AI service principals named as a string or a list', () => {
    expect(extractTrustedAiServices(policy({ Service: 'bedrock.amazonaws.com' }))).toEqual([
      'bedrock.amazonaws.com',
    ]);
    expect(
      extractTrustedAiServices(
        policy({ Service: ['sagemaker.amazonaws.com', 'bedrock-agentcore.amazonaws.com'] })
      )
    ).toEqual(['bedrock-agentcore.amazonaws.com', 'sagemaker.amazonaws.com']);
  });

  it('ignores non-AI services, AWS principals, and denied statements', () => {
    expect(extractTrustedAiServices(policy({ Service: 'ec2.amazonaws.com' }))).toEqual([]);
    expect(extractTrustedAiServices(policy({ AWS: 'arn:aws:iam::999999999999:root' }))).toEqual([]);
    expect(
      extractTrustedAiServices(
        JSON.stringify({
          Statement: [
            { Effect: 'Deny', Principal: { Service: 'bedrock.amazonaws.com' } },
            { Effect: 'Allow', Principal: { Service: 'sagemaker.amazonaws.com' } },
          ],
        })
      )
    ).toEqual(['sagemaker.amazonaws.com']);
  });

  it('handles a single-statement object and a repeated principal', () => {
    expect(
      extractTrustedAiServices(
        JSON.stringify({
          Statement: { Effect: 'Allow', Principal: { Service: 'bedrock.amazonaws.com' } },
        })
      )
    ).toEqual(['bedrock.amazonaws.com']);
    expect(
      extractTrustedAiServices(
        policy({ Service: ['bedrock.amazonaws.com', 'bedrock.amazonaws.com'] })
      )
    ).toEqual(['bedrock.amazonaws.com']);
  });

  it('decodes URL-encoded trust documents, as IAM returns them', () => {
    const encoded = encodeURIComponent(policy({ Service: 'bedrock.amazonaws.com' }));
    expect(extractTrustedAiServices(encoded)).toEqual(['bedrock.amazonaws.com']);
  });

  it('returns nothing for a missing trust policy', () => {
    expect(extractTrustedAiServices(undefined)).toEqual([]);
  });

  it('covers exactly the AI services the catalogue documents', () => {
    expect([...AI_SERVICE_PRINCIPALS].sort()).toEqual([
      'bedrock-agentcore.amazonaws.com',
      'bedrock.amazonaws.com',
      'sagemaker.amazonaws.com',
    ]);
  });
});
