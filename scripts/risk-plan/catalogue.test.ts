import { riskRules } from '@khalifa/risk-engine';
import { RULE_CATALOGUE } from './catalogue';

// The CLI keeps its own catalogue so it needs no built engine at runtime; this
// pins it to the engine's so a rename or severity change fails CI here.
describe('RULE_CATALOGUE', () => {
  it('matches the engine catalogue', () => {
    for (const [id, entry] of Object.entries(RULE_CATALOGUE)) {
      const rule = riskRules.find((candidate) => candidate.id === id);
      if (!rule) throw new Error(`engine has no ${id}`);
      expect(entry.name).toBe(rule.name);
      expect(entry.severity).toBe(rule.severityHint);
    }
  });
});
