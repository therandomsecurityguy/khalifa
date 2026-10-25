import { collectLambdaExposure, policyAllowsAnyone } from './lambda-exposure';

const fn = 'arn:aws:lambda:us-west-2:111122223333:function:api';
const policy = (...statements: object[]) => JSON.stringify({ Statement: statements });
const urlStatement = {
  Effect: 'Allow',
  Principal: '*',
  Action: 'lambda:InvokeFunctionUrl',
  Resource: fn,
  Condition: { StringEquals: { 'lambda:FunctionUrlAuthType': 'NONE' } },
};

function named(name: string): Error {
  const error = new Error(name);
  error.name = name;
  return error;
}

// Answers ListFunctionUrlConfigs with `urls` and GetPolicy from `policies`
// (keyed by qualifier, '' for the function itself).
function client(urls: object[], policies: Record<string, string | Error>) {
  const send = jest.fn(async (command: { constructor: { name: string }; input: any }) => {
    if (command.constructor.name === 'ListFunctionUrlConfigsCommand') {
      return { FunctionUrlConfigs: urls };
    }
    const result = policies[command.input.Qualifier ?? ''] ?? named('ResourceNotFoundException');
    if (result instanceof Error) throw result;
    return { Policy: result };
  });
  return { send } as any;
}

describe('policyAllowsAnyone', () => {
  it.each([
    ['the standard public URL statement', [urlStatement], 'lambda:invokefunctionurl', true],
    [
      'AWS: * with lambda:*',
      [{ ...urlStatement, Principal: { AWS: '*' }, Action: 'lambda:*', Condition: undefined }],
      'lambda:invokefunction',
      true,
    ],
    [
      'an Invoke* wildcard',
      [{ ...urlStatement, Action: ['lambda:Invoke*'], Condition: undefined }],
      'lambda:invokefunction',
      true,
    ],
    ['InvokeFunctionUrl only, for direct invoke', [urlStatement], 'lambda:invokefunction', false],
    [
      'a service principal with SourceArn',
      [
        {
          Effect: 'Allow',
          Principal: { Service: 'apigateway.amazonaws.com' },
          Action: 'lambda:InvokeFunction',
        },
      ],
      'lambda:invokefunction',
      false,
    ],
    [
      'anyone limited by SourceAccount',
      [
        {
          ...urlStatement,
          Action: 'lambda:InvokeFunction',
          Condition: { StringEquals: { 'AWS:SourceAccount': '444455556666' } },
        },
      ],
      'lambda:invokefunction',
      false,
    ],
    [
      'anyone limited to the organization',
      [
        {
          ...urlStatement,
          Action: 'lambda:InvokeFunction',
          Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-2pydbopsis' } },
        },
      ],
      'lambda:invokefunction',
      false,
    ],
    [
      'one other account',
      [
        {
          ...urlStatement,
          Principal: { AWS: 'arn:aws:iam::444455556666:root' },
          Condition: undefined,
        },
      ],
      'lambda:invokefunctionurl',
      false,
    ],
    ['a Deny', [{ ...urlStatement, Effect: 'Deny' }], 'lambda:invokefunctionurl', false],
  ])('%s', (_, statements, action, expected) => {
    expect(policyAllowsAnyone(policy(...statements), action)).toBe(expected);
  });

  it('treats a missing or unreadable policy as not public', () => {
    expect(policyAllowsAnyone(undefined, 'lambda:invokefunction')).toBe(false);
    expect(policyAllowsAnyone('not json', 'lambda:invokefunction')).toBe(false);
  });
});

describe('collectLambdaExposure', () => {
  it('flags a URL without auth that anyone may call', async () => {
    await expect(
      collectLambdaExposure(
        client([{ FunctionArn: fn, AuthType: 'NONE' }], { '': policy(urlStatement) }),
        'api'
      )
    ).resolves.toEqual({
      function_url_auth_type: 'NONE',
      function_url_public: true,
      public_invoke_policy: false,
      lambda_exposure_restricted: false,
    });
  });

  it('does not flag an AWS_IAM URL', async () => {
    await expect(
      collectLambdaExposure(
        client([{ FunctionArn: fn, AuthType: 'AWS_IAM' }], { '': policy(urlStatement) }),
        'api'
      )
    ).resolves.toMatchObject({ function_url_auth_type: 'AWS_IAM', function_url_public: false });
  });

  it('reads the alias policy for an alias URL', async () => {
    const lambda = client([{ FunctionArn: `${fn}:live`, AuthType: 'NONE' }], {
      live: policy(urlStatement),
    });
    await expect(collectLambdaExposure(lambda, 'api')).resolves.toMatchObject({
      function_url_public: true,
    });
    expect(lambda.send.mock.calls.map(([c]: any) => c.input.Qualifier)).toContain('live');
  });

  it('treats no URL and no policy as not exposed', async () => {
    await expect(collectLambdaExposure(client([], {}), 'api')).resolves.toEqual({
      function_url_auth_type: undefined,
      function_url_public: false,
      public_invoke_policy: false,
      lambda_exposure_restricted: false,
    });
  });

  it('records a denied read as unknown instead of failing', async () => {
    await expect(
      collectLambdaExposure(client([], { '': named('AccessDeniedException') }), 'api')
    ).resolves.toEqual({ lambda_exposure_restricted: true });
  });

  it('still fails on any other error', async () => {
    await expect(
      collectLambdaExposure(client([], { '': named('TooManyRequestsException') }), 'api')
    ).rejects.toThrow('TooManyRequestsException');
  });
});
