# Complete EKS example

End-to-end wiring of the three Khalifa modules against an existing EKS cluster:

- [`khalifa-registry`](../../khalifa-registry) — immutable ECR repositories and the GitHub OIDC publish role for release images
- [`khalifa-data`](../../khalifa-data) — CMK, Neptune Serverless, DynamoDB tables, SQS/SNS, Cognito, Secrets Manager, IRSA roles, optional Athena over organization CloudTrail
- [`khalifa-eks`](../../khalifa-eks) — the Helm release (API, UI, converter/rule-runner workloads, collectors, graph-writer, compliance, analyzer, DSPM)

This example also creates the IRSA role the External Secrets controller uses to read the `khalifa-runtime` secret (`COLLECTOR_EXTERNAL_ID`, `GRAPH_WRITER_TOKEN`) so no runtime credential ever lands in Helm values or Terraform state.

## Prerequisites

- Terraform 1.7+, AWS CLI credentials for the target account, `kubectl`
- An existing EKS cluster with a managed node group (or equivalent) and its IAM OIDC provider
- The [External Secrets operator](https://external-secrets.io) installed in the cluster (it renders the `SecretStore`/`ExternalSecret` the chart creates)
- Docker with `buildx` to build the release images
- For `ingress.enabled` in the chart: the [AWS Load Balancer Controller](https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html) and a TLS certificate setup you own

## 1. Configure

```bash
cd deploy/terraform/examples/complete
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars
```

The `oidc_provider_arn` comes from the cluster's issuer:

```bash
aws eks describe-cluster --name "$CLUSTER" --query 'cluster.identity.oidc.issuer' --output text
aws iam list-open-id-connect-providers   # match the issuer path
```

## 2. Create the AWS resources and ECR repositories

```bash
terraform init
terraform apply -var install_chart=false
```

This creates ECR repositories, the data plane, and the IRSA roles. The Helm release is skipped so images can be pushed first.

Create the namespace (the chart intentionally does not create it):

```bash
kubectl create namespace khalifa
```

## 3. Build and push the images

```bash
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
REGISTRY="$ACCOUNT.dkr.ecr.$REGION.amazonaws.com"

aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY"

# from the repository root, where the multi-stage Dockerfile lives
docker buildx build --platform linux/amd64 --target api         -t "$REGISTRY/example-khalifa-api:$IMAGE_TAG"         --push .
docker buildx build --platform linux/amd64 --target ui          -t "$REGISTRY/example-khalifa-ui:$IMAGE_TAG"          --push .
docker buildx build --platform linux/amd64 --target rule-runner -t "$REGISTRY/example-khalifa-rule-runner:$IMAGE_TAG" --push .
```

`terraform output -json image_references` prints the exact references the chart expects. `scripts/smoke-containers.sh` shows the same build targets for local smoke testing.

## 4. Install the release

```bash
terraform apply
```

Then create your first user (Cognito groups `khalifa-admin`, `khalifa-analyst`, `khalifa-viewer` already exist):

```bash
POOL="$(terraform output -json cognito | jq -r .user_pool_id)"

aws cognito-idp admin-create-user --user-pool-id "$POOL" --username you@example.com
aws cognito-idp admin-add-user-to-group --user-pool-id "$POOL" --username you@example.com --group-name khalifa-admin
```

With `ingress` configured in `extra_chart_values`, point DNS and TLS at the ALB the controller provisions. Without ingress, reach the API through `kubectl port-forward`:

```bash
kubectl port-forward -n khalifa svc/khalifa-api 8080:80
curl http://localhost:8080/livez
```

## Member accounts

Collection assumes `SecurityGraphCollectorRole` in each member account. Deploy [`templates/SecurityGraphCollectorRole.yaml`](../../../../templates/SecurityGraphCollectorRole.yaml) into every account (or as a StackSet with [`SecurityGraphCollectorStackSet.yaml`](../../../../templates/SecurityGraphCollectorStackSet.yaml)) using the hub IRSA role ARNs as `TrustedPrincipalArn`/`AdditionalTrustedPrincipalArn` and the ExternalId from `khalifa/runtime`:

```bash
aws secretsmanager get-secret-value --secret-id "$(terraform output -raw runtime_secret_name)" \
  --query SecretString --output text | jq .
```

`scripts/deploy-collector-role.sh` automates the per-account deployment.

## Teardown

`terraform destroy` is intentionally blocked by safety features: DynamoDB tables have deletion protection, and the CMK/tables/Neptune use `RETAIN`. Disable deletion protection and empty/destroy retained resources explicitly if you really want to remove everything.

## Notes

- Runtime credentials stay in Secrets Manager; only the External Secrets IRSA role can read them.
- `install_chart = false` is also useful for re-running Terraform while the cluster or Helm is unavailable.
- No state or chart value contains account IDs beyond what the modules already publish as outputs.
