import { LambdaClient } from '@aws-sdk/client-lambda';
import type { Classifier } from './classifier';
import { scanLambdaFunctions } from './lambda-sampler';

function client(pages: { Functions?: unknown[]; NextMarker?: string }[]): LambdaClient {
  let page = 0;
  return {
    send: jest.fn(async () => pages[page++] ?? {}),
  } as unknown as LambdaClient;
}

const noopClassifier: Classifier = {
  name: 'noop',
  classify: jest.fn().mockResolvedValue([]),
};

describe('scanLambdaFunctions', () => {
  it('classifies environment variables keyed as NAME=value', async () => {
    const content = jest.fn();
    const classifier: Classifier = {
      name: 'capture',
      classify: jest.fn(async (text: string) => {
        content(text);
        return [{ piiType: 'aws_access_key' as const, count: 1, confidence: 0.95 }];
      }),
    };

    const lambdaClient = client([
      {
        Functions: [
          {
            FunctionArn: 'arn:aws:lambda:us-west-2:111122223333:function:leaky',
            FunctionName: 'leaky',
            Environment: {
              Variables: {
                AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
                REGION: 'us-west-2',
              },
            },
          },
        ],
      },
    ]);

    const results = await scanLambdaFunctions(lambdaClient as LambdaClient, [classifier]);

    expect(results).toHaveLength(1);
    expect(content).toHaveBeenCalledWith(
      'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nREGION=us-west-2'
    );
    expect(results[0].result).toMatchObject({
      piiTypes: ['aws_access_key'],
      secretCount: 0,
      sampleSize: 2,
      classifier: 'capture',
    });
  });

  it('skips functions without environment variables', async () => {
    const lambdaClient = client([
      {
        Functions: [
          { FunctionArn: 'arn:aws:lambda:us-west-2:1:function:clean', FunctionName: 'clean' },
          {
            FunctionArn: 'arn:aws:lambda:us-west-2:1:function:empty',
            FunctionName: 'clean2',
            Environment: { Variables: {} },
          },
        ],
      },
    ]);

    const results = await scanLambdaFunctions(lambdaClient as LambdaClient, [noopClassifier]);

    expect(results).toHaveLength(2);
    for (const result of results) {
      expect(result.result).toBeNull();
    }
    expect(noopClassifier.classify).not.toHaveBeenCalled();
  });

  it('paginates with NextMarker', async () => {
    const send = jest
      .fn()
      .mockResolvedValueOnce({
        Functions: [{ FunctionArn: 'arn:aws:lambda:us-west-2:1:function:a', FunctionName: 'a' }],
        NextMarker: 'page-2',
      })
      .mockResolvedValueOnce({
        Functions: [{ FunctionArn: 'arn:aws:lambda:us-west-2:1:function:b', FunctionName: 'b' }],
      });

    const lambdaClient = { send } as unknown as LambdaClient;
    const results = await scanLambdaFunctions(lambdaClient, [noopClassifier]);

    expect(results).toHaveLength(2);
    expect(send.mock.calls[0][0].input.Marker).toBeUndefined();
    expect(send.mock.calls[1][0].input.Marker).toBe('page-2');
  });

  it('records per-function errors without failing the scan', async () => {
    const classifier: Classifier = {
      name: 'boom',
      classify: jest.fn().mockRejectedValue(new Error('classifier exploded')),
    };
    const lambdaClient = client([
      {
        Functions: [
          {
            FunctionArn: 'arn:aws:lambda:us-west-2:1:function:f',
            FunctionName: 'f',
            Environment: { Variables: { A: '1' } },
          },
        ],
      },
    ]);

    const results = await scanLambdaFunctions(lambdaClient as LambdaClient, [classifier]);

    expect(results).toHaveLength(1);
    expect(results[0].result).toBeNull();
    expect(results[0].error).toBe('classifier exploded');
  });
});
