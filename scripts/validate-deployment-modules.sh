#!/usr/bin/env bash

set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
chart="${CHART_DIR:-$root/deploy/helm/khalifa}"
values="${HELM_VALUES_FILE:-$root/deploy/testdata/eks-deployment-values.yaml}"
eks_module="${TERRAFORM_DIR:-$root/deploy/terraform/khalifa-eks}"
registry_module="${REGISTRY_TERRAFORM_DIR:-$root/deploy/terraform/khalifa-registry}"
data_module="${DATA_TERRAFORM_DIR:-$root/deploy/terraform/khalifa-data}"
examples_module="${EXAMPLES_TERRAFORM_DIR:-$root/deploy/terraform/examples/complete}"
timeout_seconds="${COMMAND_TIMEOUT_SECONDS:-180}"
init_timeout_seconds="${TERRAFORM_INIT_TIMEOUT_SECONDS:-300}"

fail() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for command in helm terraform kubeconform; do need "$command"; done
timeout_bin="$(command -v timeout || command -v gtimeout || true)"
[[ -n "$timeout_bin" ]] || fail "Required command not found: timeout (or gtimeout)"
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || fail "COMMAND_TIMEOUT_SECONDS must be a positive integer"
[[ "$init_timeout_seconds" =~ ^[1-9][0-9]*$ ]] || fail "TERRAFORM_INIT_TIMEOUT_SECONDS must be a positive integer"
[[ -f "$chart/Chart.yaml" ]] || fail "Helm chart not found: $chart"
[[ -f "$values" ]] || fail "Helm values not found: $values"
for module in "$eks_module" "$registry_module" "$data_module" "$examples_module"; do
  [[ -d "$module" ]] || fail "Terraform module not found: $module"
done

tmp="$(mktemp -d "${TMPDIR:-/tmp}/khalifa-validate.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT
run() {
  local seconds=$1
  shift
  "$timeout_bin" "${seconds}s" "$@" || fail "Command failed or timed out: $*"
}

echo "==> Helm lint and template"
run "$timeout_seconds" helm lint "$chart" --strict --values "$values"
run "$timeout_seconds" helm template validation "$chart" --namespace security-graph --values "$values" >"$tmp/rendered.yaml"

eso_values="$root/deploy/testdata/eks-deployment-values-eso.yaml"
echo "==> Helm lint and template (External Secrets runtime secret)"
run "$timeout_seconds" helm lint "$chart" --strict --values "$values" --values "$eso_values"
run "$timeout_seconds" helm template validation "$chart" --namespace security-graph --values "$values" --values "$eso_values" >"$tmp/rendered-eso.yaml"
grep -q 'name: khalifa-runtime' "$tmp/rendered-eso.yaml" || fail "ESO values must mount khalifa-runtime"
if grep -E 'name: validation-khalifa-(collector|graph-writer-token)$' "$tmp/rendered-eso.yaml"; then
  fail "ESO values must not render helm-owned collection secrets"
fi
if grep -E 'COLLECTOR_EXTERNAL_ID:|GRAPH_WRITER_TOKEN:' "$tmp/rendered-eso.yaml"; then
  fail "ESO values must not render secret material"
fi

echo "==> Unresolved placeholder checks"
unresolved='\{\{|\}\}|\$\{[^}]+\}'
sentinel='(^|[^[:alnum:]_])(REPLACE([_-]?ME)?|CHANGE([_-]?ME)?|TODO|PLACEHOLDER([_-]?ARN)?)([^[:alnum:]_]|$)|<[A-Za-z][A-Za-z0-9_-]*>'
! grep -EnH "$unresolved" "$tmp/rendered.yaml" "$tmp/rendered-eso.yaml" || fail "Rendered manifest contains unresolved template syntax"
! grep -EinH "$sentinel" "$tmp/rendered.yaml" "$tmp/rendered-eso.yaml" "$values" "$eso_values" || fail "Helm output or values contain placeholder tokens"
! grep -ERinH --include='*.tf' "$sentinel" "$eks_module" "$registry_module" "$data_module" "$examples_module" || fail "Terraform source contains placeholder tokens"

echo "==> Kubernetes schema validation"
run "$timeout_seconds" kubeconform -strict -summary -ignore-missing-schemas "$tmp/rendered.yaml" "$tmp/rendered-eso.yaml"

echo "==> Terraform formatting, init, and validation"
run "$timeout_seconds" terraform fmt -check -recursive "$root/deploy"
cp -R "$root/deploy" "$tmp/deploy"
run "$init_timeout_seconds" env TF_IN_AUTOMATION=1 terraform -chdir="$tmp/deploy/terraform/khalifa-eks" init -backend=false -input=false -no-color
run "$timeout_seconds" env TF_IN_AUTOMATION=1 terraform -chdir="$tmp/deploy/terraform/khalifa-eks" validate -no-color
run "$init_timeout_seconds" env TF_IN_AUTOMATION=1 terraform -chdir="$tmp/deploy/terraform/khalifa-registry" init -backend=false -input=false -no-color
run "$timeout_seconds" env TF_IN_AUTOMATION=1 terraform -chdir="$tmp/deploy/terraform/khalifa-registry" validate -no-color
run "$timeout_seconds" env TF_IN_AUTOMATION=1 terraform -chdir="$tmp/deploy/terraform/khalifa-registry" test -no-color
run "$init_timeout_seconds" env TF_IN_AUTOMATION=1 terraform -chdir="$tmp/deploy/terraform/khalifa-data" init -backend=false -input=false -no-color
run "$timeout_seconds" env TF_IN_AUTOMATION=1 terraform -chdir="$tmp/deploy/terraform/khalifa-data" validate -no-color
run "$timeout_seconds" env TF_IN_AUTOMATION=1 terraform -chdir="$tmp/deploy/terraform/khalifa-data" test -no-color

echo "Deployment modules validation passed."
