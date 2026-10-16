# Khalifa EKS Helm wrapper

This module installs its version-matched Khalifa chart as a fresh release. The caller configures the Helm provider and passes the target namespace and environment values.

The module creates only one `helm_release`. It does not create or discover EKS clusters, namespaces, OIDC providers, IAM roles, service accounts outside the chart, or AWS data stores.

```hcl
module "khalifa" {
  source = "../../deploy/terraform/khalifa-eks"

  providers = {
    helm = helm
  }

  namespace  = "existing-namespace"
  values     = yamldecode(file("${path.module}/khalifa-values.yaml"))
}
```

The target namespace must exist before Terraform applies this module. Helm operations are atomic, wait for readiness, and clean up a failed installation.

## Inputs

| Name | Required | Description |
| --- | --- | --- |
| `namespace` | yes | Existing Kubernetes namespace |
| `values` | yes | Caller-owned chart values |
| `release_name` | no | Helm release name; defaults to `khalifa` |
| `timeout_seconds` | no | Helm operation timeout; defaults to 600 seconds |

## Output

`release` contains only the release name, namespace, and status.
