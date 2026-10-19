import { CIS_NAME, ISO27001_NAME, SOC2_NAME } from './map';
import { assertSanitizedValue } from './map';
import type {
  PublishedFramework,
  PublishableResponse,
  Questionnaire,
  TrustControlStatus,
} from './types';

const FRAMEWORK_NAMES: Record<PublishedFramework, string> = {
  CIS_AWS_FOUNDATIONS: CIS_NAME,
  SOC2: SOC2_NAME,
  ISO27001: ISO27001_NAME,
};

const ANSWER: Record<'PASS' | 'FAIL', TrustControlStatus> = {
  PASS: 'implemented',
  FAIL: 'partial',
};

/**
 * A machine-readable answer sheet built only from publishable requirements:
 * statuses, ids, titles and sections — no evidence, accounts, or resources.
 * It answers security questionnaires with exactly what the page shows.
 */
export function buildQuestionnaire(
  response: PublishableResponse,
  now: Date = new Date()
): Questionnaire {
  const cis = response.requirements.map((requirement) => ({
    id: requirement.requirement,
    title: requirement.title,
    section: requirement.section,
    answer: ANSWER[requirement.status],
  }));
  const mapped = (response.mappedFrameworks ?? []).map((requirement) => ({
    framework: requirement.framework,
    entry: {
      id: requirement.requirement,
      title: requirement.title,
      section: requirement.section,
      answer: ANSWER[requirement.status],
    },
  }));

  const byRequirement = (
    entries: Array<{ id: string; title: string; section: string; answer: TrustControlStatus }>
  ) => [...entries].sort((a, b) => a.id.localeCompare(b.id, 'en', { numeric: true }));

  const allFrameworks: Questionnaire['frameworks'] = [
    { id: 'CIS_AWS_FOUNDATIONS', name: CIS_NAME, requirements: byRequirement(cis) },
    ...(['SOC2', 'ISO27001'] as const).map((framework) => ({
      id: framework,
      name: FRAMEWORK_NAMES[framework],
      requirements: byRequirement(
        mapped.filter((entry) => entry.framework === framework).map((entry) => entry.entry)
      ),
    })),
  ];
  const frameworks = allFrameworks.filter((framework) => framework.requirements.length > 0);

  const questionnaire: Questionnaire = {
    generatedAt: now.toISOString(),
    source: 'khalifa-trust-center-sync',
    note: 'Automated configuration posture only; not a certification. It contains no account or resource identifiers and no supporting data.',
    recordGeneratedAt: response.generatedAt,
    frameworks,
  };
  if (response.maxAgeHours !== undefined) questionnaire.maxAgeHours = response.maxAgeHours;

  assertSanitizedValue(questionnaire);
  return questionnaire;
}
