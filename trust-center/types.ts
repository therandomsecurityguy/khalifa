/**
 * Static trust-center site configuration (hand-maintained, deployment-owned).
 * The generated posture (frameworks/controls) comes from the sync tool and is
 * merged in at build time; it is never edited here.
 */
export interface SiteConfig {
  company: {
    name: string;
    website?: string;
    securityEmail?: string;
  };
  title?: string;
  description?: string;
  links?: Array<{ label: string; href: string }>;
  theme?: { primary?: string };
  footerNote?: string;
  /**
   * How this deployment monitors itself, rendered in the continuous-monitoring
   * section. staleAfterHours is optional: when set it must match the API's
   * published window, and the build fails on contradiction.
   */
  monitoring?: {
    assessmentCadence?: string;
    publishCadence?: string;
    staleAfterHours?: number;
    /** Optional status/uptime page this deployment links to. */
    statusPageUrl?: string;
  };
  /** What this deployment actually does, one short paragraph each. */
  practices?: string[];
  /** Vendors that process data for this deployment; render "None" when empty. */
  subprocessors?: Array<{
    name: string;
    purpose: string;
    location: string;
    dpaUrl?: string;
  }>;
  subprocessorsLastUpdated?: string;
  /** Public documents (privacy policy, DPA, ...). Request-only entries use requestEmail. */
  documents?: Array<{
    label: string;
    url?: string;
    requestEmail?: string;
  }>;
  faqs?: Array<{ question: string; answer: string }>;
  /** RFC 9116 security.txt emitted into the site when securityEmail is set. */
  securityTxt?: {
    /** Days until Expires (default 180). */
    expiresDays?: number;
    /** Optional Policy URL (e.g. the vulnerability disclosure policy). */
    policyUrl?: string;
  };
}

export type ControlStatus = 'implemented' | 'partial' | 'planned';
export type FrameworkStatus = 'certified' | 'in-progress' | 'planned';

/** The generated sections, as written by scripts/trust-center-sync. */
export interface GeneratedConfig {
  frameworks?: Array<{
    /** Stable framework id; optional for hand-written single-framework configs. */
    id?: string;
    name: string;
    status: FrameworkStatus;
    description?: string;
    lastVerified?: string;
  }>;
  controls?: Array<{
    /** Which framework's requirements these domains belong to. */
    framework?: string;
    domain: string;
    items: Array<{
      title: string;
      description?: string;
      status: ControlStatus;
    }>;
  }>;
  /** Posture transitions recorded by the sync tool, newest first. */
  changelog?: Array<{ date: string; title: string; description?: string }>;
  /** Series directions published by the sync tool while the record is OK. */
  projections?: Array<{
    label: string;
    perDay: number;
    confidence: 'high' | 'medium' | 'low';
    basisDays: number;
    horizonDays: number;
    projectedValue: number;
  }>;
}

export interface BuildMeta {
  generatedAt: string;
  source?: {
    recordStatus?: string;
    recordGeneratedAt?: string | null;
    /** Age of the assessed record at build time, in whole hours. */
    recordAgeHours?: number;
    /** The staleness window the API enforces, as published by the endpoint. */
    maxAgeHours?: number;
  };
}

export type GeneratedFramework = NonNullable<GeneratedConfig['frameworks']>[number];
export type GeneratedControlDomain = NonNullable<GeneratedConfig['controls']>[number];
export type GeneratedControlItem = GeneratedControlDomain['items'][number];
