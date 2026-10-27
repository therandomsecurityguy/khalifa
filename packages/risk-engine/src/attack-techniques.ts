// Curated MITRE ATT&CK mapping for the rule catalogue, following the
// framework-citations pattern: a small, reviewed table rather than derivation.
// A test pins it to the catalogue (every rule mapped, every technique known,
// ids well-formed) so drift fails CI.
export interface AttackTechnique {
  id: string;
  name: string;
  tactic: string;
}

// The subset of Enterprise ATT&CK the catalogue's rules speak to.
export const ATTACK_TECHNIQUES: Record<string, AttackTechnique> = {
  T1069: { id: 'T1069', name: 'Permission Groups Discovery', tactic: 'Discovery' },
  T1078: { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access' },
  'T1078.004': {
    id: 'T1078.004',
    name: 'Valid Accounts: Cloud Accounts',
    tactic: 'Privilege Escalation',
  },
  T1098: { id: 'T1098', name: 'Account Manipulation', tactic: 'Persistence' },
  'T1098.001': {
    id: 'T1098.001',
    name: 'Account Manipulation: Additional Cloud Credentials',
    tactic: 'Persistence',
  },
  T1133: { id: 'T1133', name: 'External Remote Services', tactic: 'Initial Access' },
  T1190: {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
  },
  T1199: { id: 'T1199', name: 'Trusted Relationship', tactic: 'Initial Access' },
  T1486: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
  T1496: { id: 'T1496', name: 'Resource Hijacking', tactic: 'Impact' },
  T1530: { id: 'T1530', name: 'Data from Cloud Storage', tactic: 'Collection' },
  T1552: { id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access' },
  'T1552.001': {
    id: 'T1552.001',
    name: 'Unsecured Credentials: Credentials In Files',
    tactic: 'Credential Access',
  },
  'T1552.005': {
    id: 'T1552.005',
    name: 'Unsecured Credentials: Cloud Instance Metadata API',
    tactic: 'Credential Access',
  },
  'T1562.001': {
    id: 'T1562.001',
    name: 'Impair Defenses: Disable or Modify Tools',
    tactic: 'Defense Evasion',
  },
  'T1562.008': {
    id: 'T1562.008',
    name: 'Impair Defenses: Disable Cloud Logs',
    tactic: 'Defense Evasion',
  },
};

// What a finding from each rule can be a step of. Reviewed like
// REVIEWED_MAPPING: the rule's query is the evidence for the attribution.
export const RULE_TECHNIQUES: Record<string, string[]> = {
  'RULE-001': ['T1190', 'T1078.004', 'T1530'],
  'RULE-002': ['T1133'],
  'RULE-003': ['T1190'],
  'RULE-004': ['T1190', 'T1078.004'],
  'RULE-005': ['T1190', 'T1530'],
  'RULE-006': ['T1199', 'T1078.004'],
  'RULE-007': ['T1530'],
  'RULE-008': ['T1190', 'T1530'],
  'RULE-009': ['T1190', 'T1530'],
  'RULE-010': ['T1552', 'T1199'],
  'RULE-011': ['T1530'],
  'RULE-012': ['T1552.001'],
  'RULE-013': ['T1078.004'],
  'RULE-014': ['T1078.004'],
  'RULE-015': ['T1078.004'],
  'RULE-016': ['T1552'],
  'RULE-017': ['T1562.001'],
  'RULE-018': ['T1190'],
  'RULE-019': ['T1133', 'T1190'],
  'RULE-020': ['T1078.004'],
  'RULE-021': ['T1552', 'T1078.004'],
  'RULE-022': ['T1069'],
  'RULE-023': ['T1078.004', 'T1552.001'],
  'RULE-024': ['T1552.005'],
  'RULE-025': ['T1562.001'],
  'RULE-026': ['T1486'],
  'RULE-027': ['T1562.008'],
  'RULE-028': ['T1562.001'],
  'RULE-029': ['T1190', 'T1496'],
  'RULE-030': ['T1078.004', 'T1098'],
  'RULE-031': ['T1078.004', 'T1098.001'],
  'RULE-032': ['T1552', 'T1199'],
  'RULE-033': ['T1552', 'T1199'],
  'RULE-034': ['T1078.004', 'T1098'],
};

export function techniquesForRule(ruleId: string): AttackTechnique[] {
  return (RULE_TECHNIQUES[ruleId] ?? [])
    .map((id) => ATTACK_TECHNIQUES[id])
    .filter((technique): technique is AttackTechnique => Boolean(technique));
}
