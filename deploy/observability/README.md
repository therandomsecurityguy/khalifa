# Observability assets

- [`grafana-dashboard.json`](grafana-dashboard.json) — API dashboard for
  Grafana: request rate by status, 5xx ratio, average latency, and top routes.
  Import via Dashboards → New → Import and pick the Prometheus data source
  when prompted (the dashboard carries a `DS_PROMETHEUS` variable for that).

Alert rules deliberately live in the Helm chart
(`prometheusRule.enabled`) rather than here, so they ship and roll back with
the release. The default group covers API metrics absence, 5xx ratio above 5%,
and average latency above 1s — the thresholds `OPERATIONAL.md` §E already
names. Extra groups can be appended through `prometheusRule.rules`.

## Deliberately deferred

Domain alerts — issue backlog, reconciliation staleness, queue/DLQ depth, rule
execution results — need domain **gauges**, which the API does not expose yet.
Alerting on absent series would page on nothing, so those panels and rules
wait for gauges (a scrape-time DynamoDB read needs a caching design first).
