import { ATTACK_TECHNIQUES, type AttackTechnique } from './attack-techniques';

// Graph-only adversary emulation: a scenario is a curated chain of existing
// rule queries evaluated against the live graph — no AWS calls, nothing is
// executed. Each step names the rule whose findings would be that step's
// evidence, so a run says "of this chain's steps, these match your graph
// today". It is attribution over what the collectors already see, not a
// red-team execution.
export interface ScenarioStep {
  ruleId: string;
  description: string;
}

export interface AttackScenario {
  id: string;
  name: string;
  description: string;
  techniques: string[];
  steps: ScenarioStep[];
}

export interface ScenarioStepResult {
  ruleId: string;
  description: string;
  /** Matched paths after dedupe, capped for the response. */
  matchedPaths: number;
  /** The distinct resources on the matched paths, capped. */
  resources: string[];
  truncated: boolean;
  error?: string;
}

export interface ScenarioRun {
  scenarioId: string;
  name: string;
  matchedSteps: number;
  totalSteps: number;
  steps: ScenarioStepResult[];
}

export const SCENARIO_MATCH_CAP = 200;
export const SCENARIO_RESOURCE_CAP = 5;

export const ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: 'leaked-credential-to-data',
    name: 'Leaked credential to data access',
    description:
      'A secret read from an unseen source, probing, an escalation, and a reachable crown jewel: the sequence a stolen credential usually follows.',
    techniques: ['T1078.004', 'T1552', 'T1098', 'T1530'],
    steps: [
      { ruleId: 'RULE-021', description: 'Secret read from a previously unseen source IP' },
      { ruleId: 'RULE-022', description: 'AccessDenied probing from the principal' },
      { ruleId: 'RULE-030', description: 'Principal can escalate to admin or escalation role' },
      { ruleId: 'RULE-005', description: 'Crown jewel reachable from the internet' },
    ],
  },
  {
    id: 'internet-to-admin',
    name: 'Internet exposure to admin',
    description:
      'An open entry point, an internet-reachable workload holding an admin role, and the escalation paths it opens.',
    techniques: ['T1133', 'T1190', 'T1078.004', 'T1098'],
    steps: [
      { ruleId: 'RULE-002', description: 'Security group open to the internet on SSH/RDP' },
      { ruleId: 'RULE-019', description: 'EKS API endpoint open to the world' },
      { ruleId: 'RULE-004', description: 'Admin role on an internet-reachable workload' },
      { ruleId: 'RULE-034', description: 'Principal can pass an admin role to compute it creates' },
    ],
  },
  {
    id: 'cicd-to-cloud-takeover',
    name: 'CI/CD to cloud takeover',
    description:
      'Long-lived keys and role-passing around build systems: the chain that turns a pipeline compromise into account-wide access.',
    techniques: ['T1078.004', 'T1098.001', 'T1098'],
    steps: [
      { ruleId: 'RULE-031', description: 'Admin IAM user with an active access key' },
      { ruleId: 'RULE-013', description: 'Active access key older than 90 days' },
      { ruleId: 'RULE-034', description: 'Principal can pass an admin role to compute it creates' },
      { ruleId: 'RULE-030', description: 'Principal can escalate to admin or escalation role' },
    ],
  },
];

export function getAttackScenario(id: string): AttackScenario | undefined {
  return ATTACK_SCENARIOS.find((scenario) => scenario.id === id);
}

export function scenarioTechniques(scenario: AttackScenario): AttackTechnique[] {
  return scenario.techniques
    .map((id) => ATTACK_TECHNIQUES[id])
    .filter((technique): technique is AttackTechnique => Boolean(technique));
}

// The distinct resources a step's matched paths touch, in path order.
export function stepResources(
  paths: Array<{ vertices: Array<{ id: string; label: string }> }>,
  limit: number = SCENARIO_RESOURCE_CAP
): string[] {
  const resources: string[] = [];
  for (const path of paths) {
    for (const vertex of path.vertices) {
      if (resources.length >= limit) return resources;
      if (!resources.includes(vertex.id)) resources.push(vertex.id);
    }
  }
  return resources;
}
