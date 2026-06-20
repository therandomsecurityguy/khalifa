# Changelog

All notable changes to Khalifa.

## [Unreleased] - Phase 0

### Changed
- **Risk engine moved to `packages/risk-engine`** (workspace member named `@khalifa/risk-engine`). Both `api-service` and the rule-runner CronJob now import from this shared package, eliminating the duplicate-types problem.
- **Collector now produces what the rules query for:**
  - Tag ingestion via `ResourceGroupsTaggingAPI` — `env`, `data_classification`, `crown_jewel`, `owner`, `business_unit` propagate to every vertex.
  - Internet-exposure derivation — sets `is_internet_exposed` based on public IP, world-open SGs, internet-facing LBs, public subnets in IGW-attached VPCs.
  - New synthetic `Internet` vertex (id: `arn:aws:khalifa:global:internet`) with `EXPOSES` edges to IGWs and internet-facing LBs.
  - SecurityGroup, SecurityGroupRule, InternetGateway, NATGateway, Subnet, LoadBalancer, EcrRepository, ContainerImage collection.
  - Cross-account trust analysis: ExternalAccount vertices + `TRUSTS` edges for IAM roles.
  - Region parameterized via `process.env.AWS_REGION` throughout (was hardcoded `us-east-1`).
- **API service compliance route rewritten** — was returning hard-coded mock data, now calls the real `ComplianceEngine` against Neptune + DynamoDB.
- **Gremlin queries parameterized** — every user-supplied value (label, ARN, fromSelector, toSelector) now goes through Gremlin bindings. New `validateGremlinSelectors` middleware rejects injection attempts.
- **API service now has JWT verification + RBAC** — every route (except `/health`) requires a valid Cognito bearer token; Viewer/Analyst/Admin role gates enforced.

### Added
- `packages/risk-engine` workspace package
- `packages/risk-engine/src/compliance-engine.ts` — real `DynamoDBEvidenceStore` + `DynamoDBReportStore` + `InMemoryReportStore`
- `lambdas/collector/src/` — modular collectors (tags, network, load-balancers, containers, cross-account, exposure)
- `api-service/src/middleware/auth.ts` — Cognito OIDC JWT verification via `jose`
- `api-service/src/middleware/rbac.ts` — Admin/Analyst/Viewer roles from Cognito groups
- `api-service/src/middleware/gremlin-validator.ts` — query-param allowlist
- `api-service/src/services/compliance-service.ts` — wires Neptune + DynamoDB to ComplianceEngine
- `ComplianceReports` + `ComplianceEvidence` DynamoDB tables (CDK)
- `accountIds: string[]` CDK input on `SecurityGraphIngestionStackProps`
- EKS ConfigMap exposes Cognito + Compliance tables
- Root `jest.config.js` (projects-based) replaces per-package configs
- 34 new tests across collector, api-service middleware, and ComplianceService

### Security
- Fixed Gremlin string-injection vulnerabilities in attack-paths and resources routes
- API endpoints no longer accept unauthenticated requests

### Fixed
- `findAllAttackPaths` was querying `'isInternetExposed'` (property never set) — now correctly queries `'is_internet_exposed'`

## [1.0.0] - Initial release

- Lambda-based collector for 25+ AWS services
- Neptune-backed security graph
- 10 Gremlin-based risk rules
- 124 controls across CIS/SOC2/ISO27001 compliance frameworks
- Next.js UI with issues, attack-paths, compliance pages
- CDK infrastructure for Lambda + EKS deployments