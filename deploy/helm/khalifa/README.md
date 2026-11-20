# Khalifa Helm chart

Khalifa security platform workloads for Kubernetes: the API and UI, the graph
writer, the collection and analysis CronJobs, compliance and reconciliation,
and the External Secrets wiring for the runtime secret.

## Prerequisites

- The **namespace must already exist** — the chart never creates it
  (`helm install --create-namespace` is not supported).
- **External Secrets Operator** with a `ClusterSecretStore`/`SecretStore`
  reachable from the namespace (the chart renders `SecretStore` +
  `ExternalSecret` per `externalSecrets.*`).
- **IRSA service accounts** created by the Terraform modules; pass their role
  ARNs through `serviceAccounts.*.annotations`.
- **Digest-pinned images only** — the chart schema rejects `repo:tag`
  references (`repo@sha256:<64 hex>`). Build and push with the root
  `Dockerfile` targets, then reference the digests.

The end-to-end walkthrough lives in
[`deploy/terraform/examples/complete/README.md`](../terraform/examples/complete/README.md);
operations and runbooks in [`OPERATIONAL.md`](../../OPERATIONAL.md).

## Install

```bash
kubectl create namespace khalifa   # once
helm upgrade --install khalifa deploy/helm/khalifa \
  --namespace khalifa --values my-values.yaml
```

## Key values

| Area           | Keys                                                                                                           | Notes                                                                        |
| -------------- | -------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Images         | `api.image`, `ui.image`, `*.image` for every job/daemon                                                        | `repo@sha256:…`; never tags                                                  |
| Data plane     | `config.neptuneEndpoint`, `*.Table`, `config.cognito*`                                                         | Endpoint, DynamoDB table names, and the Cognito pool the API verifies        |
| Collection     | `collection.homeAccountId`, `accountIds`, `regions`, `incrementalQueueUrl`, `recomputeQueueUrl`, `concurrency` | Scope of the organization sweep and the event queues                         |
| Schedules      | `organizationCollector.schedule`, `ruleRunner.schedule`, `compliance.schedule`                                 | Cron expressions are deliberately offset; `suspend` gates each               |
| API / UI       | `api.*`, `ui.*`                                                                                                | Replicas, ports, resources, HPA (`autoscaling.enabled`), PDB (`pdb.enabled`) |
| Reconciliation | `reconciliation.securityHubRoleArn`, `minAgreementDays`, `publishAllowlist`, `trustCenterSyncClientId`         | Nothing publishes until all are set (see OPERATIONAL.md § J.1)               |
| Monitoring     | `api.serviceMonitor.enabled`, `.labels`, `.interval`                                                           | Prometheus Operator scrape of `/metrics`                                     |
| Exposure       | `ingress.*`                                                                                                    | Off by default; `internet-facing` requires explicit operator approval        |
| Guardrails     | `networkPolicies.*`, `serviceAccounts.*`, `topologySpread`                                                     | Default-deny egress patterns, IRSA annotations, spread constraints           |

The full reference is [`values.yaml`](values.yaml) and the validated schema
[`values.schema.json`](values.schema.json) (enforced at install time).

## Verify

```bash
kubectl -n khalifa get pods
kubectl -n khalifa get externalsecret
kubectl -n khalifa port-forward svc/khalifa-api 8080:80
curl -sf http://localhost:8080/livez && curl -sf http://localhost:8080/readyz
```

`readyz` fails closed until the data plane is reachable; it names the missing
configuration, which is the fastest way to catch a botched values file.
