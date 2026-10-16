#!/usr/bin/env bash

set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
chart="${CHART_DIR:-$root/deploy/helm/khalifa}"
values="${HELM_VALUES_FILE:-$root/deploy/testdata/eks-deployment-values.yaml}"
cluster="${KIND_CLUSTER_NAME:-khalifa-smoke-$$-$RANDOM}"
release="${HELM_RELEASE_NAME:-smoke}"
namespace="${HELM_NAMESPACE:-security-graph}"
timeout_seconds="${COMMAND_TIMEOUT_SECONDS:-180}"

fail() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"; }

for command in kind kubectl helm; do need "$command"; done
timeout_bin="$(command -v timeout || command -v gtimeout || true)"
[[ -n "$timeout_bin" ]] || fail "Required command not found: timeout (or gtimeout)"
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || fail "COMMAND_TIMEOUT_SECONDS must be a positive integer"
[[ -f "$chart/Chart.yaml" ]] || fail "Helm chart not found: $chart"
[[ -f "$values" ]] || fail "Helm values not found: $values"
[[ ${#cluster} -le 63 && "$cluster" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || fail "Invalid kind cluster name: $cluster"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/khalifa-smoke.XXXXXX")"
kubeconfig="$tmp/kubeconfig"
cleanup_cluster=false
cleanup() {
  local code=$?
  trap - EXIT
  if [[ "$cleanup_cluster" == true ]]; then
    "$timeout_bin" "${timeout_seconds}s" kind delete cluster --name "$cluster" >/dev/null 2>&1 || echo "WARNING: Failed to delete kind cluster $cluster" >&2
  fi
  rm -rf -- "$tmp"
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
run() {
  local seconds=$1
  shift
  "$timeout_bin" "${seconds}s" "$@" || fail "Command failed or timed out: $*"
}
revision() {
  run "$timeout_seconds" helm status "$release" -n "$namespace" --kubeconfig "$kubeconfig" | awk '$1 == "REVISION:" {print $2}'
}
assert_revision() { [[ "$(revision)" == "$1" ]] || fail "Expected Helm revision $1"; }

existing="$(run "$timeout_seconds" kind get clusters)"
! grep -Fxq "$cluster" <<<"$existing" || fail "Refusing to reuse existing kind cluster: $cluster"

echo "==> Create kind cluster"
cleanup_cluster=true
run "$timeout_seconds" kind create cluster --name "$cluster" --kubeconfig "$kubeconfig" --wait 120s

common=(--namespace "$namespace" --kubeconfig "$kubeconfig")
overrides=(--set externalSecrets.enabled=false --set-json 'config.issueSinks=[]' --set api.serviceMonitor.enabled=false --set ingress.enabled=false)

echo "==> Install"
run "$timeout_seconds" helm install "$release" "$chart" "${common[@]}" --create-namespace --values "$values" "${overrides[@]}" --timeout 2m
assert_revision 1
run "$timeout_seconds" kubectl --kubeconfig "$kubeconfig" -n "$namespace" --request-timeout=30s get deployment/"$release-khalifa-api" deployment/"$release-khalifa-ui" deployment/"$release-khalifa-incremental" deployment/"$release-khalifa-graph-writer" cronjob/"$release-khalifa-rule-runner" cronjob/"$release-khalifa-org-collector" cronjob/"$release-khalifa-compliance" cronjob/"$release-khalifa-cloudtrail-analyzer" cronjob/"$release-khalifa-dspm-scanner" cronjob/"$release-khalifa-policy-evaluator" cronjob/"$release-khalifa-least-privilege-sweep" service/"$release-khalifa-graph-writer" >/dev/null

echo "==> Upgrade"
run "$timeout_seconds" helm upgrade "$release" "$chart" "${common[@]}" --values "$values" "${overrides[@]}" --set-string api.podAnnotations.khalifa-smoke-phase=upgrade --timeout 2m
assert_revision 2

echo "==> Rollback"
run "$timeout_seconds" helm rollback "$release" 1 "${common[@]}" --timeout 2m
assert_revision 3

echo "==> Uninstall"
run "$timeout_seconds" helm uninstall "$release" "${common[@]}" --wait --timeout 2m
releases="$(run "$timeout_seconds" helm list --short "${common[@]}")"
! grep -Fxq "$release" <<<"$releases" || fail "Release still exists after uninstall: $release"
leftovers="$(run "$timeout_seconds" kubectl --kubeconfig "$kubeconfig" -n "$namespace" --request-timeout=30s get deployment/"$release-khalifa-api" deployment/"$release-khalifa-ui" deployment/"$release-khalifa-incremental" deployment/"$release-khalifa-graph-writer" cronjob/"$release-khalifa-rule-runner" cronjob/"$release-khalifa-org-collector" cronjob/"$release-khalifa-compliance" cronjob/"$release-khalifa-cloudtrail-analyzer" cronjob/"$release-khalifa-dspm-scanner" cronjob/"$release-khalifa-policy-evaluator" cronjob/"$release-khalifa-least-privilege-sweep" --ignore-not-found -o name)"
[[ -z "$leftovers" ]] || fail "Workloads remain after uninstall: $leftovers"

echo "==> Delete kind cluster"
run "$timeout_seconds" kind delete cluster --name "$cluster"
cleanup_cluster=false
echo "Helm lifecycle smoke test passed."
