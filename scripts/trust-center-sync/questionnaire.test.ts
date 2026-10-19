import { buildQuestionnaire } from './questionnaire';
import type { PublishableResponse } from './types';

const response: PublishableResponse = {
  status: 'OK',
  generatedAt: '2026-10-16T00:00:00.000Z',
  maxAgeHours: 24,
  requirements: [
    { requirement: '2.1', title: 'CloudTrail enabled', section: '3. Logging', status: 'FAIL' },
    { requirement: '1.5', title: 'Root has MFA', section: '1. Identity', status: 'PASS' },
  ],
  mappedFrameworks: [
    {
      framework: 'SOC2',
      requirement: 'CC9.1',
      title: 'Availability is protected',
      section: 'Availability',
      status: 'PASS',
    },
  ],
};

describe('buildQuestionnaire', () => {
  it('maps statuses to answers and sorts requirements numerically', () => {
    const questionnaire = buildQuestionnaire(response, new Date('2026-10-16T12:00:00.000Z'));
    expect(questionnaire.generatedAt).toBe('2026-10-16T12:00:00.000Z');
    expect(questionnaire.maxAgeHours).toBe(24);
    expect(questionnaire.recordGeneratedAt).toBe('2026-10-16T00:00:00.000Z');
    expect(questionnaire.frameworks.map((f) => f.id)).toEqual(['CIS_AWS_FOUNDATIONS', 'SOC2']);

    const cis = questionnaire.frameworks[0];
    expect(cis.requirements.map((r) => r.id)).toEqual(['1.5', '2.1']);
    expect(cis.requirements[0]).toMatchObject({ answer: 'implemented' });
    expect(cis.requirements[1]).toMatchObject({ answer: 'partial' });

    const soc2 = questionnaire.frameworks[1];
    expect(soc2.requirements).toEqual([
      {
        id: 'CC9.1',
        title: 'Availability is protected',
        section: 'Availability',
        answer: 'implemented',
      },
    ]);
  });

  it('omits frameworks with nothing published', () => {
    const questionnaire = buildQuestionnaire({
      status: 'OK',
      generatedAt: null,
      requirements: [],
      mappedFrameworks: [],
    });
    expect(questionnaire.frameworks).toEqual([]);
    expect(questionnaire.maxAgeHours).toBeUndefined();
  });

  it('rejects identifiers that must never reach the answer sheet', () => {
    expect(() =>
      buildQuestionnaire({
        status: 'OK',
        generatedAt: null,
        requirements: [
          { requirement: '1.1', title: 'Account 111122223333', section: '1', status: 'PASS' },
        ],
      })
    ).toThrow('forbidden value');
  });
});
