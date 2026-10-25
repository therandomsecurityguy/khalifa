import {
  GetPolicyCommand,
  ListFunctionUrlConfigsCommand,
  type LambdaClient,
} from '@aws-sdk/client-lambda';
import { globMatch } from '../../shared/glob';
import { collectPaginated } from '../../shared/pagination';

export interface LambdaExposure {
  // NONE when any of the function's URLs (unqualified or alias) needs no auth.
  function_url_auth_type?: string;
  function_url_public?: boolean;
  public_invoke_policy?: boolean;
  // The collector role cannot read URLs or the policy (member stack not yet
  // redeployed), so exposure is unknown rather than false.
  lambda_exposure_restricted?: boolean;
}

function asList(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
}

function allowsAnyone(principal: unknown): boolean {
  if (principal === '*') return true;
  if (!principal || typeof principal !== 'object') return false;
  return asList((principal as Record<string, unknown>).AWS).includes('*');
}

// Conditions other than lambda:FunctionUrlAuthType (aws:SourceArn,
// aws:SourceAccount, aws:PrincipalOrgID, ...) narrow who can invoke.
function unconditioned(condition: unknown): boolean {
  if (!condition || typeof condition !== 'object') return true;
  return Object.values(condition as Record<string, unknown>).every(
    (keys) =>
      !!keys &&
      typeof keys === 'object' &&
      Object.keys(keys as Record<string, unknown>).every(
        (key) => key.toLowerCase() === 'lambda:functionurlauthtype'
      )
  );
}

// Whether a function policy lets anyone, with no narrowing condition, call the
// given action ('lambda:invokefunction' or 'lambda:invokefunctionurl').
export function policyAllowsAnyone(policyJson: string | undefined, action: string): boolean {
  if (!policyJson) return false;
  let document: unknown;
  try {
    document = JSON.parse(policyJson);
  } catch {
    return false;
  }
  return asList((document as { Statement?: unknown })?.Statement).some((statement) => {
    const s = statement as Record<string, unknown>;
    return (
      s?.Effect === 'Allow' &&
      allowsAnyone(s.Principal) &&
      asList(s.Action).some(
        (pattern) => typeof pattern === 'string' && globMatch(pattern, action)
      ) &&
      unconditioned(s.Condition)
    );
  });
}

function isDenied(error: unknown): boolean {
  return error instanceof Error && /^AccessDenied/.test(error.name);
}

async function readPolicy(
  client: LambdaClient,
  functionName: string,
  qualifier?: string
): Promise<string | undefined> {
  try {
    const response = await client.send(
      new GetPolicyCommand({ FunctionName: functionName, Qualifier: qualifier })
    );
    return response.Policy;
  } catch (error) {
    if (error instanceof Error && error.name === 'ResourceNotFoundException') return undefined;
    throw error;
  }
}

// Reads a function's URL configs and resource policies. Only the derived flags
// are kept; policy documents are not stored.
export async function collectLambdaExposure(
  client: LambdaClient,
  functionName: string
): Promise<LambdaExposure> {
  try {
    const urls = await collectPaginated(
      (marker) =>
        client.send(
          new ListFunctionUrlConfigsCommand({ FunctionName: functionName, Marker: marker })
        ),
      (page) => page.FunctionUrlConfigs,
      (page) => page.NextMarker
    );
    const policy = await readPolicy(client, functionName);

    let urlPublic = false;
    for (const url of urls) {
      if (url.AuthType !== 'NONE') continue;
      // An alias URL is governed by the alias's own policy.
      const qualifier = url.FunctionArn?.split(':')[7];
      const urlPolicy = qualifier ? await readPolicy(client, functionName, qualifier) : policy;
      if (policyAllowsAnyone(urlPolicy, 'lambda:invokefunctionurl')) urlPublic = true;
    }

    return {
      function_url_auth_type: urls.some((url) => url.AuthType === 'NONE')
        ? 'NONE'
        : urls[0]?.AuthType,
      function_url_public: urlPublic,
      public_invoke_policy: policyAllowsAnyone(policy, 'lambda:invokefunction'),
      lambda_exposure_restricted: false,
    };
  } catch (error) {
    if (isDenied(error)) return { lambda_exposure_restricted: true };
    throw error;
  }
}
