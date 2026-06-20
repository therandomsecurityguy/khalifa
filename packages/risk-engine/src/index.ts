import { RiskRuleRunner, resolveStaleIssues } from './runner';
import { getRuleById, riskRules } from './rules';
import { computeRiskScore } from './scoring';
import type { RiskScoreInput } from './types';
import { Issue } from './types';
import {
  ComplianceEngine,
  runScheduledComplianceAssessment,
  DynamoDBEvidenceStore,
  DynamoDBReportStore,
  InMemoryReportStore,
  type GraphClient,
  type ReportStore,
} from './compliance-engine';

export * from './compliance-types';
export { ComplianceEngine, DynamoDBEvidenceStore, DynamoDBReportStore, InMemoryReportStore, runScheduledComplianceAssessment };
export type { GraphClient, ReportStore };

const NEPTUNE_ENDPOINT =
  process.env.NEPTUNE_ENDPOINT || 'wss://neptune-cluster.us-east-1.amazonaws.com:8182/gremlin';
const ISSUES_TABLE = process.env.ISSUES_TABLE || 'SecurityIssues';

async function runSingleRuleExample() {
  console.log('=== Running Single Rule Example ===\n');

  const rule = getRuleById('RULE-001');
  if (!rule) {
    console.error('Rule not found');
    return;
  }

  console.log(`Executing rule: ${rule.name}`);
  console.log(`Gremlin query:\n${rule.gremlinQueryTemplate}\n`);

  const runner = new RiskRuleRunner(NEPTUNE_ENDPOINT);

  try {
    await runner.initialize();
    console.log('Connected to Neptune\n');

    const result = await runner.runRule(rule);

    console.log('Execution Results:');
    console.log(`  Rule ID: ${result.ruleId}`);
    console.log(`  Execution time: ${result.executionTime}ms`);
    console.log(`  Issues created: ${result.issuesCreated}`);
    console.log(`  Issues resolved: ${result.issuesResolved}`);

    if (result.errors && result.errors.length > 0) {
      console.log(`  Errors: ${result.errors.join(', ')}`);
    }
  } catch (error) {
    console.error('Error executing rule:', error);
  } finally {
    await runner.shutdown();
  }
}

async function computeRiskScoreExample() {
  console.log('\n=== Risk Scoring Example ===\n');

  const testInputs: RiskScoreInput[] = [
    {
      cvss: {
        baseScore: 9.8,
        exploitabilitySubScore: 3.9,
        impactSubScore: 5.9,
        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      },
      exploitabilityFlags: { hasExploit: true, hasPublicExploit: true, malwareAvailable: false },
      exposureLevel: 'internet',
      identityBlastRadius: { type: 'admin', scope: 1 },
      dataClassification: 'restricted',
      environment: 'prod',
      isCrownJewel: false,
      attackPathLength: 3,
    },
    {
      exposureLevel: 'internal',
      dataClassification: 'internal',
      environment: 'dev',
      isCrownJewel: false,
    },
    {
      cvss: {
        baseScore: 7.5,
        exploitabilitySubScore: 2.5,
        impactSubScore: 5.9,
        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
      },
      exposureLevel: 'cross-account',
      dataClassification: 'secret',
      environment: 'prod',
      isCrownJewel: true,
      attackPathLength: 2,
    },
  ];

  for (let i = 0; i < testInputs.length; i++) {
    const result = computeRiskScore(testInputs[i]);
    console.log(`Input ${i + 1}:`, JSON.stringify(testInputs[i], null, 2));
    console.log(`Result ${i + 1}:`, JSON.stringify(result, null, 2));
    console.log('');
  }
}

async function resolveStaleIssuesExample() {
  console.log('\n=== Resolve Stale Issues Example ===\n');

  try {
    const resolvedCount = await resolveStaleIssues(NEPTUNE_ENDPOINT);
    console.log(`Resolved ${resolvedCount} stale issues`);
  } catch (error) {
    console.error('Error resolving stale issues:', error);
  }
}

async function demonstratePeriodicRunner() {
  console.log('\n=== Periodic Rule Runner Service ===\n');

  async function runScheduledJob() {
    console.log(`[${new Date().toISOString()}] Starting scheduled risk assessment...`);

    const runner = new RiskRuleRunner(NEPTUNE_ENDPOINT);

    try {
      await runner.initialize();

      const results = await runner.runAllRules();

      let totalIssuesCreated = 0;
      let totalIssuesResolved = 0;

      for (const result of results) {
        totalIssuesCreated += result.issuesCreated;
        totalIssuesResolved += result.issuesResolved;

        console.log(
          `Rule ${result.ruleId}: ${result.issuesCreated} created, ${result.issuesResolved} resolved`
        );
      }

      console.log(`\nTotal: ${totalIssuesCreated} issues created, ${totalIssuesResolved} resolved`);
    } catch (error) {
      console.error('Error in scheduled job:', error);
    } finally {
      await runner.shutdown();
    }
  }

  console.log('Demonstrating periodic runner (one execution):');
  await runScheduledJob();

  console.log('\nTo run periodically, use:');
  console.log('  setInterval(runScheduledJob, 5 * 60 * 1000); // every 5 minutes');
}

async function runComplianceAssessment() {
  console.log('\n=== Compliance Assessment ===\n');

  const gremlin = await import('gremlin');
  const Gremlin = gremlin.default || gremlin;
  const client = new Gremlin.driver.Client(NEPTUNE_ENDPOINT, {
    traversalSource: 'g',
    connectTimeout: 30000,
  });

  const neptuneClient = {
    async executeQuery(query: string) {
      const result = await client.submit(query);
      const items: any[] = [];
      // eslint-disable-next-line no-constant-condition
      while (true) {
        const item = await result.next();
        if (!item) break;
        items.push(item);
      }
      return items;
    },
  };

  const { DynamoDBEvidenceStore } = await import('./compliance-engine');
  const evidenceStore = new DynamoDBEvidenceStore();
  const engine = new ComplianceEngine(neptuneClient, evidenceStore);

  try {
    console.log('Running CIS AWS Foundations assessment...');
    const cisReport = await engine.runAssessment('CIS_AWS_FOUNDATIONS');
    console.log(
      `CIS: ${cisReport.summary.passed}/${cisReport.summary.totalControls} passed, ${cisReport.summary.coveragePercent}% coverage`
    );

    console.log('Running SOC2 assessment...');
    const soc2Report = await engine.runAssessment('SOC2');
    console.log(
      `SOC2: ${soc2Report.summary.passed}/${soc2Report.summary.totalControls} passed, ${soc2Report.summary.coveragePercent}% coverage`
    );

    console.log('Running ISO27001 assessment...');
    const isoReport = await engine.runAssessment('ISO27001');
    console.log(
      `ISO27001: ${isoReport.summary.passed}/${isoReport.summary.totalControls} passed, ${isoReport.summary.coveragePercent}% coverage`
    );
  } catch (error) {
    console.error('Error in compliance assessment:', error);
  } finally {
    await client.close();
  }
}

async function main() {
  console.log('========================================');
  console.log('Risk and Attack-Path Engine');
  console.log('========================================\n');

  console.log(`Configuration:`);
  console.log(`  Neptune: ${NEPTUNE_ENDPOINT}`);
  console.log(`  Issues Table: ${ISSUES_TABLE}`);
  console.log(`  Available Rules: ${riskRules.length}`);
  console.log(`\n`);

  await runSingleRuleExample();
  await computeRiskScoreExample();
  await demonstratePeriodicRunner();

  console.log('\n=== Examples Complete ===');
}

if (require.main === module) {
  main().catch(console.error);
}

export {
  runSingleRuleExample,
  computeRiskScoreExample,
  resolveStaleIssuesExample,
  demonstratePeriodicRunner,
};
