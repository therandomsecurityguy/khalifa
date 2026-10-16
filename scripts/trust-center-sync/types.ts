export type PublishableStatus = 'PASS' | 'FAIL';

export interface PublishableRequirement {
  requirement: string;
  title: string;
  section: string;
  status: PublishableStatus;
}

export interface PublishableResponse {
  status: 'OK' | 'STALE' | 'MISSING';
  generatedAt: string | null;
  requirements: PublishableRequirement[];
}

export type TrustControlStatus = 'implemented' | 'partial' | 'planned';
export type TrustFrameworkStatus = 'in-progress' | 'planned';

/**
 * The generated sections of trust.config.json. They match the public
 * Fimil-dev/trust-center Zod schema (src/config/schema.ts) for `frameworks`
 * and `controls`; the hand-edited config keeps everything else.
 */
export interface TrustConfigFragment {
  frameworks: Array<{
    name: string;
    status: TrustFrameworkStatus;
    description: string;
    lastVerified?: string;
  }>;
  controls: Array<{
    domain: string;
    items: Array<{
      title: string;
      description: string;
      status: TrustControlStatus;
    }>;
  }>;
}

export interface BuildMeta {
  generatedAt: string;
  framework: {
    id: 'CIS_AWS_FOUNDATIONS';
    name: string;
    version: string;
  };
  source: {
    endpoint: string;
    recordStatus: 'OK';
    recordGeneratedAt: string | null;
  };
  counts: {
    requirements: number;
    pass: number;
    fail: number;
    domains: number;
  };
  generator: {
    name: 'khalifa-trust-center-sync';
  };
}
