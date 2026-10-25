# Plan: predictive security roadmap

Status: proposed (2026-10-25) — nothing implemented. This is the output of a
repo review, not a committed schedule.
Related: [`ARCHITECTURE.md`](../../ARCHITECTURE.md) (evaluation engines),
[`docs/plans/2026-10-24-parity-port-remaining.md`](2026-10-24-parity-port-remaining.md)
(the G1–G6 parity port this review follows), [`README.md`](../../README.md) §Compliance.

---

## 1. Objective

Khalifa today is a model-based, current-state security tool: it collects an
org-wide AWS graph, derives reachability and permissions, runs 34 rules plus
compliance and CIEM over that graph, triages issues, and publishes posture.
That is exposure management, not prediction.

This plan defines what "predictive" means concretely for this codebase and
sequences the work to get there without weakening the existing guarantees
(evidence-backed findings, fail-closed publication, no identifiers on the
public page).

## 2. Definition: what counts as predictive

Four capabilities, each with an observable exit test. A claim is only
"predictive" if it carries its inputs, a confidence/coverage statement, and can
later be scored against outcomes.

| Capability        | Means                                                              | Exit test                                                              |
| ----------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| Likelihood        | Findings and paths ranked by probability of exploitation, not only static severity | A critical CVE on an exposed workload outranks an exposed workload with no known exploitability, deterministically and explainably |
| Trajectory        | Posture projections (what will be true next week), not just deltas | Open criticals / exposure projected 7–30 days with an explicit confidence tied to coverage freshness |
| Behavior deviation| Per-principal baselines instead of global thresholds               | Principal X's secret reads deviate from its own history, scored, without a fixed IP-window rule |
| Simulation        | What-if before and after change                                    | A Terraform/IAM change is evaluated pre-merge; a remediation shows its path-count/score delta |

## 3. What exists today (the substrate is good)

| Piece                              | Where                                                                 | Predictive-adjacent because                     |
| ---------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------- |
| Config-derived exposure            | Collector `deriveIsInternetExposed`; ARCHITECTURE "Internet exposure derivation" | Reachability is *inferred*, not just observed |
| Attack-path enumeration            | RULE-005, `GET /attack-paths/search`                                  | Model-based pathfinding over the live graph     |
| CIEM escalation paths              | RULE-030/034, `lambdas/policy-evaluator/pass-role.ts`                 | Chains (assume hops, `iam:PassRole`) are computed, not listed |
| CloudTrail usage profile + anomalies | `lambdas/cloudtrail-analyzer/src/anomalies.ts`                      | Fixed-threshold behavioral signals + canaries   |
| Trend persistence                  | `packages/risk-engine/src/posture-trend-store.ts:11-17`               | Six metrics persisted daily; improving/worsening deltas exist |
| Risk scoring                       | `packages/risk-engine/src/scoring.ts:12-54`                           | Deterministic, explainable factor decomposition |
| Compliance reconciliation + freshness | G4: `cis-reconciliation.ts`, `freshCoverage()`                     | Publication discipline and coverage discipline to reuse for confidence |
| Issue lifecycle                    | `statusHistory`, `resolvedAt` in `issue-repository.ts`                | The raw data for MTTR/risk-window models exists |
| Incremental collector              | `lambdas/incremental-collector` (SQS)                                 | Near-real-time graph updates that predictions can trigger on |

## 4. Gaps

Numbered for reference from the roadmap below. Evidence is in this repo.

| #   | Gap                                | Evidence                                                                                         | Consequence                                             |
| --- | ---------------------------------- | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------- |
| G1  | No exploitability data             | `rules.ts:109` RULE-003 disabled — "nothing creates `HAS_CVE` today"; `scoring.ts:38-41` removed CVSS because nothing populated it | Cannot estimate likelihood, only exposure                |
| G2  | No temporal forecasting            | Trend metrics are counts (`posture-trend-store.ts:11-17`); drift = failed controls (`routes/compliance.ts:292-320`) | No projection, no breach/SLO prediction, no MTTR modeling |
| G3  | Paths enumerated, not ranked/simulated | Attack-path search returns paths; `scoring.ts` is a static weighted sum                      | No path likelihood, no what-if remediation deltas, no event-triggered recompute |
| G4  | No behavioral baselining (UEBA)    | Global constants in `anomalies.ts:23-25` (7-day IP window, 30-day baseline margin, 20+ denied)   | Novel-but-real behavior is invisible; noisy behavior is not tuned per principal |
| G5  | No shift-left change prediction    | Detection runs after collection (hourly–4h); no IaC/policy-diff evaluation                       | Weeks of exposure can precede the first finding          |
| G6  | Reachability not observed          | RULE-027 only checks flow logs are enabled; exposure is derived from config                      | Predicted lateral movement is not grounded in traffic    |
| G7  | No threat-intel enrichment         | No IOC/TTP/campaign context anywhere; canaries are the only tripwire                              | Unknown actors and campaigns are indistinguishable from noise |
| G8  | No feedback/calibration loop       | Suppressions/resolutions recorded but no outcome labels, precision/recall, or weight tuning       | A "prediction" cannot later be judged right or wrong     |
| G9  | Freshness does not temper risk     | `freshCoverage()` guards compliance only; `collection_restricted` stubs exist (G2)                | Scores can silently rest on stale or partial data        |
| G10 | No streaming risk triggers         | Incremental collector updates the graph; rules run on schedules                                   | New admin grant + new key does not produce an immediate predicted escalation |

## 5. Roadmap

Each phase is its own branch/PR with the repository's normal gates
(`npm run ci:quality`, CHANGELOG, docs). Phases are independent unless noted.

### P1 — Exploitability layer (highest leverage; unblocks G1)

- Collect Amazon Inspector findings (EC2/ECR/Lambda) into `Vulnerability`
  vertices and `HAS_CVE` edges (the schema is already reserved in
  ARCHITECTURE: "not yet created").
- Enrich with EPSS score and KEV flag, with a fetch/import cadence and a
  bounded age; store the source and retrieval time as evidence.
- Re-add an `exploitability` factor to `scoring.ts` and re-enable RULE-003
  with graph tests; update `REVIEWED_MAPPING` (load-bearing) and the rule
  catalogue counts in README.
- Exit: RULE-003 fires on real data; scores decompose exploitability; the §2
  likelihood exit test holds.

### P2 — Path probability and simulation (G3)

- Likelihood model v1 per path: exposure × privilege/blast radius ×
  exploitability (from P1, optional) × reachability confidence; persist the
  factors with the path so the ranking is explainable.
- Simulation surface: a `what-if` API (or an extension of attack-path search)
  that computes the path-count/score delta of removing one edge — trust,
  statement, exposure — and a "what changes if I fix this" panel on the issue
  page.
- Recompute predicted paths from incremental-collector deltas, so a new admin
  grant or trust produces a predicted escalation within one cycle.
- Exit: every path has a scored likelihood with factors; the top remediation
  for a critical path shows a measured delta; event-triggered recompute works.

### P3 — Trajectory forecasting (G2, G9)

- Extend the trend store with risk-score, exposure-by-type, admin-principal
  and MTTR series; keep daily granularity.
- Explainable forecasting only (EWMA/linear with a documented basis), with
  confidence degraded by `freshCoverage`/`collection_restricted` (reuse G4's
  signals); no black-box model in this phase.
- Per-issue "risk window" from observed resolution times; SLO burn/breach
  prediction for open criticals.
- Surface trajectory (and confidence) on the Trends page and, gated like every
  other claim, in the trust center's monitoring section.
- Exit: 7/30-day projections with confidence bands; stale coverage visibly
  lowers confidence.

### P4 — Behavioral baselines (G4)

- Per-principal CloudTrail baselines: API mix, source IPs/ASNs, time-of-day,
  first-seen services; deviation scoring replaces the fixed thresholds as the
  primary path, with thresholds retained for cold start.
- Joint scoring: deviation × CIEM blast radius (a deviating principal that can
  escalate ranks first).
- Exit: RULE-021/022 are re-expressed as baseline deviations with a
  false-positive harness over historical windows.

### P5 — Shift-left change prediction (G5)

- Reuse `lambdas/policy-evaluator` + `globMatch` to evaluate a Terraform plan
  (`terraform show -json`), an IAM policy diff, or Helm values: which rules
  would fire, which vertices/edges appear, what paths are created.
- A CLI (`npm run risk:plan <plan.json>`) plus an optional CI gate.
- Exit: a plan that adds a world-open security group or an account-root trust
  fails the gate naming the rule and the predicted path.

### P6 — Calibration and feedback (G8)

- Outcome labels: join GuardDuty/Security Hub findings and issue resolution
  history; compute precision/recall per rule; publish a per-rule quality
  dashboard.
- Weight/severity changes only with recorded evidence; auto-ticketing (still
  off for RULE-006/031–034 per the port's §7.2 decision) is enabled per rule
  once measured precision supports it.
- Exit: per-rule precision published; first evidence-based weight change
  merged.

### P7 — Observed reachability and threat intel (G6, G7; later/optional)

- Ingest VPC flow logs (Athena, like the CloudTrail analyzer) into observed
  flow edges; reachability confidence becomes observed ∧ configured.
- Threat-intel enrichment (IOC feeds, TTP mapping) and adversary-emulation
  scenarios evaluated against the graph.
- Exit: lateral-movement predictions cite observed traffic; TI matches change
  ranking, not just labeling.

## 6. Sequencing

| Order | Phase | Depends on                    | Notes                                         |
| ----- | ----- | ----------------------------- | --------------------------------------------- |
| 1     | P1    | —                             | Biggest lever; unblocks likelihood in P2/P6   |
| 2     | P2    | P1 optional (v1 without it)   | Simulation can start on current scoring       |
| 2     | P3    | —                             | Parallel with P2; independent of exploitability |
| 2     | P5    | G2/G5 evaluator work (merged) | Parallel; reuses existing parser/matcher      |
| 3     | P4    | usage cache (exists)          | After P3 so deviation can feed trajectories   |
| 4     | P6    | P1–P4 outputs                 | Needs something to calibrate                  |
| 5     | P7    | P2 (confidence input)         | Cost/volume review first                      |

## 7. Guardrails

- **Predicted ≠ observed**: every predictive surface is labeled and carries
  its factors and confidence; nothing predictive may reach the trust center
  without the same publishable discipline the trust center already enforces.
- **Load-bearing updates are explicit**: enabling RULE-003 or re-expressing
  RULE-021/022 touches `REVIEWED_MAPPING`, the catalogue counts, and
  `CHANGELOG.md` in the PR that does it (AGENTS.md §2.1).
- **No identifier leakage**: TI/threat data and flow logs are internal
  evidence; the sanitization tripwires stay authoritative.
- **Alert fatigue**: likelihood gates ticketing; auto-ticketing stays off
  until P6 measures precision.
- **Cost bounds**: Inspector, flow logs, Athena queries and forecast storage
  get explicit windows/retention (follow the analyzer's partition-bounding
  pattern).

## 8. Open decisions

1. Exploitability source: Amazon Inspector only, or a third-party
   vulnerability/context provider alongside it?
2. EPSS/KEV acquisition: scheduled import (S3/DynamoDB) vs an API call at
   collection time; update cadence and offline behavior.
3. Simulation shape: synchronous request on the issue page vs an async job
   writing results to DynamoDB.
4. Forecasting method and the wording of its confidence (what probability
   means to a human reading the Trends page).
5. Which rules earn auto-ticketing at what measured precision threshold, and
   where that threshold is recorded.
