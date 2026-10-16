import type {
  PublishableRequirement,
  PublishableResponse,
  TrustConfigFragment,
  TrustControlStatus,
} from './types';

export const CIS_NAME = 'CIS AWS Foundations Benchmark v3.0.0';

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

/**
 * Maps the publishable endpoint onto the trust-center config sections.
 *
 * Statuses only: PASS becomes implemented, FAIL becomes partial. The framework
 * is never certified; it is in-progress while anything is publishable and
 * planned while the record is OK but lists nothing yet.
 */
export function buildTrustFragment(response: PublishableResponse): TrustConfigFragment {
  const requirements = [...response.requirements].sort((a, b) =>
    a.requirement.localeCompare(b.requirement, 'en', { numeric: true })
  );

  const domains = new Map<string, TrustConfigFragment['controls'][number]['items']>();
  for (const requirement of requirements) {
    const items = domains.get(requirement.section) ?? [];
    items.push({
      title: requirement.title,
      description: `${CIS_NAME}; requirement ${requirement.requirement}.`,
      status: CONTROL_STATUS[requirement.status],
    });
    domains.set(requirement.section, items);
  }

  const framework: TrustConfigFragment['frameworks'][number] = {
    name: CIS_NAME,
    status: requirements.length > 0 ? 'in-progress' : 'planned',
    description:
      'Continuous posture from automated graph evaluation against the AWS configuration. Not a certification.',
  };
  if (response.generatedAt) framework.lastVerified = response.generatedAt;

  const fragment: TrustConfigFragment = {
    frameworks: [framework],
    controls: [...domains.entries()]
      .sort(([a], [b]) => a.localeCompare(b, 'en', { numeric: true }))
      .map(([domain, items]) => ({ domain, items })),
  };

  assertSanitized(fragment);
  return fragment;
}

/** Throws when a forbidden identifier survives into the generated sections. */
export function assertSanitized(fragment: TrustConfigFragment): void {
  const serialized = JSON.stringify(fragment);
  for (const pattern of FORBIDDEN_PATTERNS) {
    const match = serialized.match(pattern);
    if (match) {
      throw new Error(`generated trust config contains a forbidden value: ${match[0]}`);
    }
  }
}
