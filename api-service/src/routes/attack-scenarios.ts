import type { Request, Response } from 'express';
import {
  ATTACK_SCENARIOS,
  extractRulePath,
  getAttackScenario,
  getRuleById,
  scenarioTechniques,
  SCENARIO_MATCH_CAP,
  stepResources,
  type AttackScenario,
  type ScenarioStepResult,
} from '@khalifa/risk-engine';
import { getApiNeptuneClient } from '../services/api-dependencies';
import type { AttackScenarioDetail, AttackScenarioRunResponse } from '../types';

const neptuneClient = getApiNeptuneClient();

function describe(scenario: AttackScenario): AttackScenarioDetail {
  return {
    id: scenario.id,
    name: scenario.name,
    description: scenario.description,
    techniques: scenarioTechniques(scenario),
    steps: scenario.steps.map((step) => ({
      ...step,
      ruleName: getRuleById(step.ruleId)?.name ?? step.ruleId,
    })),
  };
}

export async function listAttackScenarios(_req: Request, res: Response): Promise<void> {
  res.json({ scenarios: ATTACK_SCENARIOS.map(describe) });
}

// Graph-only emulation: each step re-runs the rule's query against the live
// graph (bounded and deduped, like the fix simulation) and reports what it
// matched — no AWS calls and nothing is executed. A step that fails (timeout,
// denied read) records its error and the rest still run; only a run where
// every step fails is an error.
export async function runAttackScenario(req: Request, res: Response): Promise<void> {
  const scenario = getAttackScenario(req.params.id);
  if (!scenario) {
    res
      .status(404)
      .json({ code: 'NOT_FOUND', message: `Unknown attack scenario ${req.params.id}` });
    return;
  }

  const steps: ScenarioStepResult[] = [];
  for (const step of scenario.steps) {
    const rule = getRuleById(step.ruleId);
    if (!rule) {
      steps.push({
        ...step,
        matchedPaths: 0,
        resources: [],
        truncated: false,
        error: 'Rule not in the catalogue',
      });
      continue;
    }
    try {
      const rows = await neptuneClient.executeStaticQuery(rule.gremlinQueryTemplate);
      const seen = new Set<string>();
      const paths: Array<{ vertices: Array<{ id: string; label: string }> }> = [];
      for (const row of rows) {
        const path = extractRulePath(row);
        if (path.vertices.length === 0) continue;
        const key = path.vertices.map((vertex) => vertex.id).join('>');
        if (seen.has(key)) continue;
        seen.add(key);
        paths.push(path);
      }
      const truncated = paths.length > SCENARIO_MATCH_CAP;
      const bounded = paths.slice(0, SCENARIO_MATCH_CAP);
      steps.push({
        ...step,
        matchedPaths: bounded.length,
        resources: stepResources(bounded),
        truncated,
      });
    } catch (error) {
      steps.push({
        ...step,
        matchedPaths: 0,
        resources: [],
        truncated: false,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  if (steps.every((step) => step.error)) {
    console.error('Error running attack scenario:', steps[0]?.error);
    res
      .status(500)
      .json({ code: 'INTERNAL_ERROR', message: 'Failed to evaluate the attack scenario' });
    return;
  }

  const body: AttackScenarioRunResponse = {
    scenarioId: scenario.id,
    name: scenario.name,
    matchedSteps: steps.filter((step) => step.matchedPaths > 0).length,
    totalSteps: steps.length,
    steps,
  };
  res.json(body);
}
