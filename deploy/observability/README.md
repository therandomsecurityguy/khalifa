# Observability assets

- [`grafana-dashboard.json`](grafana-dashboard.json) — API dashboard for
  Grafana: request rate by status, 5xx ratio, average latency, and top routes.
  Import via Dashboards → New → Import and pick the Prometheus data source
  when prompted (the dashboard carries a `DS_PROMETHEUS` variable for that).

Alert rules deliberately live in the Helm chart
(`prometheusRule.enabled`) rather than here, so they ship and roll back with
the release. The rules cover HTTP traffic (metrics absent, 5xx ratio, average
latency) and posture: reconciliation not OK (15m, critical — the trust center
publishes nothing while it holds), reconciliation older than 36h, and the
domain refresh itself failing (30m). Extra groups can be appended through
`prometheusRule.rules`.

## Domain gauges

The posture values come from `khalifa_open_issues{severity}`,
`khalifa_reconciliation_ok`, `khalifa_reconciliation_status`,
`khalifa_reconciliation_age_seconds`, and `khalifa_domain_metrics_ok` — read
by the API on a **five-minute interval** and cached, because the issue counts
page through open issues and a 30s scrape must not become a query every 30s.
The alerts' `for:` windows are all well above the refresh interval; stale
values are preferable to a gap, and `khalifa_domain_metrics_ok` catches a
refresh that never succeeds.

## Deliberately deferred

Queue and DLQ depth stay out of Prometheus: reading them needs a CloudWatch
call at scrape time. Those failures are covered by the CDK stack's
`security-graph-alarms` topic instead (DLQ not empty, queue stalled,
processor errors).
