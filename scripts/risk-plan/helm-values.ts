import { load } from 'js-yaml';
import type { RawFinding } from './analyzers';

// Shift-left for Helm values: the values file decides how the chart's API/UI
// reach the network, and the one value that changes that materially is
// ingress. An internet-facing scheme (however the controller spells it in its
// annotations) is the deploy-time precursor of the public-endpoint exposure
// the live rules would flag; a plain ingress is a lesser note because the
// controller's default decides.
export class HelmValuesParseError extends Error {}

export function helmValuesFindings(valuesText: string): RawFinding[] {
  let values: unknown;
  try {
    values = load(valuesText);
  } catch {
    throw new HelmValuesParseError('--helm-values must be a valid YAML values file');
  }
  if (!values || typeof values !== 'object') return [];

  const ingress = (values as { ingress?: unknown }).ingress;
  if (!ingress || typeof ingress !== 'object') return [];
  const block = ingress as { enabled?: unknown; annotations?: unknown };
  if (block.enabled !== true) return [];

  const annotations = JSON.stringify(block.annotations ?? {});
  const internetFacing = annotations.includes('internet-facing');
  if (internetFacing) {
    return [
      {
        ruleId: null,
        fallbackName: 'Internet-Facing Ingress Declared for the API/UI',
        fallbackSeverity: 'high',
        address: 'helm:ingress',
        detail:
          'ingress annotations request an internet-facing load balancer for the API/UI; authentication (Cognito, Access) still applies, but the endpoint becomes reachable from the internet',
        predictedPath: 'Internet → ingress → khalifa-api / khalifa-ui',
      },
    ];
  }
  return [
    {
      ruleId: null,
      fallbackName: 'Ingress Declared for the API/UI',
      fallbackSeverity: 'medium',
      address: 'helm:ingress',
      detail:
        "ingress is enabled; whether it is internet-facing depends on your controller's default — set an explicit private scheme if the API/UI should stay internal",
      predictedPath: 'Ingress → khalifa-api / khalifa-ui',
    },
  ];
}
