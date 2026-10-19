export type PublishableStatus = 'PASS' | 'FAIL';

export interface PublishableRequirement {
  requirement: string;
  title: string;
  section: string;
  status: PublishableStatus;
}

export type PublishedFramework = 'CIS_AWS_FOUNDATIONS' | 'SOC2' | 'ISO27001';

export interface PublishableMappedRequirement extends PublishableRequirement {
  framework: Exclude<PublishedFramework, 'CIS_AWS_FOUNDATIONS'>;
}

export interface PublishableResponse {
  status: 'OK' | 'STALE' | 'MISSING';
  generatedAt: string | null;
  requirements: PublishableRequirement[];
  mappedFrameworks?: PublishableMappedRequirement[];
  /** Hours after which a record is STALE; absent on older APIs. */
  maxAgeHours?: number;
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
    id: PublishedFramework;
    name: string;
    status: TrustFrameworkStatus;
    description: string;
    lastVerified?: string;
  }>;
  controls: Array<{
    framework: PublishedFramework;
    domain: string;
    items: Array<{
      title: string;
      description: string;
      status: TrustControlStatus;
    }>;
  }>;
  /** Posture transitions since the previous publish, newest first. */
  changelog?: ChangelogEntry[];
}

export interface ChangelogEntry {
  date: string;
  title: string;
  description?: string;
}

/** Machine-readable answer sheet, statuses only. */
export interface Questionnaire {
  generatedAt: string;
  source: 'khalifa-trust-center-sync';
  note: string;
  recordGeneratedAt: string | null;
  maxAgeHours?: number;
  frameworks: Array<{
    id: PublishedFramework;
    name: string;
    requirements: Array<{
      id: string;
      title: string;
      section: string;
      answer: TrustControlStatus;
    }>;
  }>;
}

/** Persisted between publishes (locally and as a public static asset). */
export interface PostureState {
  updatedAt: string;
  posture: Record<string, TrustControlStatus>;
  changelog: ChangelogEntry[];
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
    /** Age of the assessed record at build time, in whole hours. */
    recordAgeHours?: number;
    /** The staleness window the API enforces, as published by the endpoint. */
    maxAgeHours?: number;
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
