# Contributing to Khalifa

Khalifa is an open-source AWS security graph and risk engine. Contributions are welcome.

## Development Setup

```bash
npm ci --workspaces
npm test
```

## Project Structure

- `lambdas/collector/` — Agentless resource ingestion (EC2, S3, IAM, RDS, etc.)
- `packages/risk-engine/` — Gremlin-based risk rules + compliance evaluators
- `api-service/` — REST API (Express on EKS or Lambda)
- `ui/` — Next.js dashboard
- `cdk/` — AWS CDK infrastructure
- `eks-manifests/` — Kubernetes manifests for EKS deployment

## Adding a New Risk Rule

1. Edit `packages/risk-engine/src/rules.ts`
2. Add a new `RiskRule` entry to `riskRules` array:
   ```typescript
   {
     id: 'RULE-XXX',
     name: '...',
     description: '...',
     severityHint: 'critical' | 'high' | 'medium' | 'low',
     riskFactors: [...baseRiskFactors],
     gremlinQueryTemplate: `
       g.V().has('label', 'Whatever')...
     `,
     ownerTeam: 'your-team',
     enabled: true,
   }
   ```
3. Add a remediation hint in `packages/risk-engine/src/scoring.ts` (`getRemediationHint`)
4. Add a test in `packages/risk-engine/src/rules.test.ts`

## Adding a New Compliance Control

1. Edit `packages/risk-engine/src/compliance-types.ts` to add the control to the framework array (e.g., `CIS_AWS_FOUNDATIONS_V3_CONTROLS`)
2. If automated, add an evaluator in `packages/risk-engine/src/compliance-rules.ts`:
   ```typescript
   {
     controlId: 'X.Y',
     evaluate: async (graphClient) => {
       const result = await graphClient.executeQuery('...');
       return { status: 'PASS' | 'FAIL', evidence: [...], issues: [...] };
     },
   }
   ```
3. Test it: `cd packages/risk-engine && npm test`

## Adding a New Collector Service

1. Add the AWS SDK client to `lambdas/collector/package.json`
2. Import and instantiate in `lambdas/collector/index.ts` (the `createClients` function)
3. Write a `collectXyz()` function in `lambdas/collector/src/`
4. Call it from the handler
5. Update `cdk/lib/khalifa-stack.ts` and `templates/SecurityGraphCollectorRole.yaml` with required IAM permissions

## Code Style

- TypeScript strict mode everywhere
- ESLint + Prettier via root `npm run lint` / `npm run format`
- Run `npm test` before opening a PR

## Pull Request Checklist

- [ ] `npm test` passes
- [ ] `npm run lint` passes
- [ ] New rules/controls have tests
- [ ] CHANGELOG.md updated under "Unreleased"
- [ ] README.md updated if behavior changes