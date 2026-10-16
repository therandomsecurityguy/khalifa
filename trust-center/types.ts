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
}

export interface BuildMeta {
  generatedAt: string;
  source?: { recordStatus?: string; recordGeneratedAt?: string | null };
}

export type GeneratedFramework = NonNullable<GeneratedConfig['frameworks']>[number];
export type GeneratedControlDomain = NonNullable<GeneratedConfig['controls']>[number];
export type GeneratedControlItem = GeneratedControlDomain['items'][number];
