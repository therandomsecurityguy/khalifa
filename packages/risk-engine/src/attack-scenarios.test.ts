import {
  ATTACK_SCENARIOS,
  getAttackScenario,
  scenarioTechniques,
  stepResources,
  SCENARIO_RESOURCE_CAP,
} from './attack-scenarios';
import { ATTACK_TECHNIQUES } from './attack-techniques';
import { riskRules } from './rules';

describe('scenario curation', () => {
  it('references only catalogue rules and known techniques', () => {
    const ruleIds = new Set(riskRules.map((rule) => rule.id));
    for (const scenario of ATTACK_SCENARIOS) {
      expect(scenario.steps.length).toBeGreaterThan(1);
      for (const step of scenario.steps) {
        expect(ruleIds.has(step.ruleId)).toBe(true);
        expect(step.description.length).toBeGreaterThan(0);
      }
      for (const technique of scenario.techniques) {
        expect(ATTACK_TECHNIQUES[technique]).toBeDefined();
      }
      expect(scenarioTechniques(scenario).length).toBe(scenario.techniques.length);
    }
  });

  it('finds scenarios by id and nothing for an unknown one', () => {
    expect(getAttackScenario('internet-to-admin')?.name).toBe('Internet exposure to admin');
    expect(getAttackScenario('nope')).toBeUndefined();
  });
});

describe('stepResources', () => {
  it('collects distinct vertex ids in path order, capped', () => {
    const paths = [
      {
        vertices: [
          { id: 'a', label: 'Ec2Instance' },
          { id: 'b', label: 'S3Bucket' },
        ],
      },
      {
        vertices: [
          { id: 'a', label: 'Ec2Instance' },
          { id: 'c', label: 'S3Bucket' },
        ],
      },
    ];
    expect(stepResources(paths)).toEqual(['a', 'b', 'c']);
    expect(stepResources(paths, 2)).toEqual(['a', 'b']);
    expect(SCENARIO_RESOURCE_CAP).toBeGreaterThan(0);
  });
});
