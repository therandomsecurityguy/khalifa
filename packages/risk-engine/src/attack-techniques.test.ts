import { ATTACK_TECHNIQUES, RULE_TECHNIQUES, techniquesForRule } from './attack-techniques';
import { riskRules } from './rules';

describe('rule to ATT&CK curation', () => {
  it('maps every rule in the catalogue', () => {
    for (const rule of riskRules) {
      expect(Object.keys(RULE_TECHNIQUES)).toContain(rule.id);
    }
    expect(Object.keys(RULE_TECHNIQUES).sort()).toEqual(riskRules.map((rule) => rule.id).sort());
  });

  it('references only known, well-formed techniques with names and tactics', () => {
    for (const ids of Object.values(RULE_TECHNIQUES)) {
      expect(ids.length).toBeGreaterThan(0);
      for (const id of ids) {
        expect(id).toMatch(/^T\d{4}(\.\d{3})?$/);
        const technique = ATTACK_TECHNIQUES[id];
        expect(technique).toBeDefined();
        expect(technique.name.length).toBeGreaterThan(0);
        expect(technique.tactic.length).toBeGreaterThan(0);
      }
    }
  });

  it('resolves techniques for a rule and nothing for an unknown rule', () => {
    expect(techniquesForRule('RULE-024').map((technique) => technique.id)).toEqual(['T1552.005']);
    expect(techniquesForRule('RULE-999')).toEqual([]);
  });
});
