import { MAPPED_PUBLISHED_FRAMEWORKS, PUBLISHED_FRAMEWORKS } from './types';
import type {
  PublishableMappedRequirement,
  PublishableRequirement,
  PublishableResponse,
  PublishedFramework,
  TrustConfigFragment,
  TrustControlStatus,
} from './types';

export const CIS_NAME = 'CIS AWS Foundations Benchmark v3.0.0';
export const SOC2_NAME = 'SOC 2 Trust Services Criteria';
export const ISO27001_NAME = 'ISO/IEC 27001:2022 Annex A';
export const PCI_DSS_NAME = 'PCI DSS v4.0';
export const NIST_800_53_NAME = 'NIST SP 800-53 Rev. 5';

const MAPPED_FRAMEWORK_META: Record<
  Exclude<PublishedFramework, 'CIS_AWS_FOUNDATIONS'>,
  { name: string; description: string }
> = {
  SOC2: {
    name: SOC2_NAME,
    description:
      'Trust Services Criteria requirements mapped to the controls Khalifa evaluates. Continuous posture, not a certification.',
  },
  ISO27001: {
    name: ISO27001_NAME,
    description:
      'Annex A requirements mapped to the controls Khalifa evaluates. Continuous posture, not a certification.',
  },
  PCI_DSS: {
    name: PCI_DSS_NAME,
    description:
      'PCI DSS v4.0 requirements mapped to the controls Khalifa evaluates. Continuous posture, not a certification.',
  },
  NIST_800_53: {
    name: NIST_800_53_NAME,
    description:
      'NIST SP 800-53 Rev. 5 controls mapped to the controls Khalifa evaluates. Continuous posture, not a certification.',
  },
};

/** Display names keyed by framework id, for changelog and questionnaire text. */
export const FRAMEWORK_NAMES: Record<PublishedFramework, string> = {
  CIS_AWS_FOUNDATIONS: CIS_NAME,
  ...Object.fromEntries(Object.entries(MAPPED_FRAMEWORK_META).map(([id, meta]) => [id, meta.name])),
} as Record<PublishedFramework, string>;

const CONTROL_STATUS: Record<PublishableRequirement['status'], TrustControlStatus> = {
  PASS: 'implemented',
  FAIL: 'partial',
};

// A tripwire on top of the endpoint's server-side whitelist: nothing that can
// identify an account, resource, or piece of evidence may reach the page.
const FORBIDDEN_PATTERNS: RegExp[] = [
  /\b\d{12}\b/,
  /arn:[a-z0-9-]+:/i,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\b(evidence|finding|resourceArn|accountId|principalArn)\b/i,
];

interface RequirementInput {
  framework: PublishedFramework;
  requirement: string;
  title: string;
  section: string;
  status: PublishableRequirement['status'];
}

/**
 * Maps the publishable endpoint onto the trust-center config sections.
 *
 * Statuses only: PASS becomes implemented, FAIL becomes partial. No framework
 * is ever certified; each is in-progress while anything is publishable and
 * planned while it lists nothing yet.
 */
export function buildTrustFragment(response: PublishableResponse): TrustConfigFragment {
  const cis: RequirementInput[] = response.requirements.map((requirement) => ({
    framework: 'CIS_AWS_FOUNDATIONS' as const,
    ...requirement,
  }));
  const mapped: RequirementInput[] = (response.mappedFrameworks ?? []).map(
    (requirement: PublishableMappedRequirement) => ({ ...requirement })
  );
  const all = [...cis, ...mapped];

  const frameworks: TrustConfigFragment['frameworks'] = [
    frameworkEntry('CIS_AWS_FOUNDATIONS', CIS_NAME, cis.length, {
      description:
        'Continuous posture from automated graph evaluation against the AWS configuration. Not a certification.',
      lastVerified: response.generatedAt ?? undefined,
    }),
    ...MAPPED_PUBLISHED_FRAMEWORKS.map((framework) => {
      const count = countFramework(mapped, framework);
      return frameworkEntry(framework, MAPPED_FRAMEWORK_META[framework].name, count, {
        description: MAPPED_FRAMEWORK_META[framework].description,
        lastVerified: count > 0 ? (response.generatedAt ?? undefined) : undefined,
      });
    }),
  ];

  const controls: TrustConfigFragment['controls'] = [];
  for (const framework of PUBLISHED_FRAMEWORKS) {
    const domains = new Map<string, TrustConfigFragment['controls'][number]['items']>();
    for (const requirement of all
      .filter((entry) => entry.framework === framework)
      .sort((a, b) => a.requirement.localeCompare(b.requirement, 'en', { numeric: true }))) {
      const items = domains.get(requirement.section) ?? [];
      items.push({
        title: requirement.title,
        description: `${frameworkName(framework)}; requirement ${requirement.requirement}.`,
        status: CONTROL_STATUS[requirement.status],
      });
      domains.set(requirement.section, items);
    }
    for (const [domain, items] of [...domains.entries()].sort(([a], [b]) =>
      a.localeCompare(b, 'en', { numeric: true })
    )) {
      controls.push({ framework, domain, items });
    }
  }

  const fragment: TrustConfigFragment = { frameworks, controls };
  assertSanitized(fragment);
  return fragment;
}

function frameworkEntry(
  id: PublishedFramework,
  name: string,
  requirementCount: number,
  options: { description: string; lastVerified?: string }
): TrustConfigFragment['frameworks'][number] {
  const entry: TrustConfigFragment['frameworks'][number] = {
    id,
    name,
    status: requirementCount > 0 ? 'in-progress' : 'planned',
    description: options.description,
  };
  if (options.lastVerified) entry.lastVerified = options.lastVerified;
  return entry;
}

function countFramework(
  requirements: RequirementInput[],
  framework: Exclude<PublishedFramework, 'CIS_AWS_FOUNDATIONS'>
): number {
  return requirements.filter((entry) => entry.framework === framework).length;
}

function frameworkName(framework: PublishedFramework): string {
  if (framework === 'CIS_AWS_FOUNDATIONS') return CIS_NAME;
  return MAPPED_FRAMEWORK_META[framework].name;
}

/** Throws when a forbidden identifier survives into the generated sections. */
/** Throws when a forbidden identifier survives into the generated output. */
export function assertSanitizedValue(value: unknown): void {
  const serialized = JSON.stringify(value);
  for (const pattern of FORBIDDEN_PATTERNS) {
    const match = serialized.match(pattern);
    if (match) {
      throw new Error(`generated trust config contains a forbidden value: ${match[0]}`);
    }
  }
}

export function assertSanitized(fragment: TrustConfigFragment): void {
  assertSanitizedValue(fragment);
}
