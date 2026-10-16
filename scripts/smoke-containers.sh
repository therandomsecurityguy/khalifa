#!/usr/bin/env bash

set -euo pipefail

run_id=$$
api_container="khalifa-api-smoke-$run_id"
ui_container="khalifa-ui-smoke-$run_id"
runtime_container="khalifa-runtime-smoke-$run_id"

cleanup() {
  docker rm -f "$api_container" "$ui_container" "$runtime_container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

get_host_port() {
  docker port "$1" "$2/tcp" | sed 's/.*://'
}

wait_for_http() {
  local container=$1
  local port=$2
  local path=$3
  local host_port

  host_port=$(get_host_port "$container" "$port")
  for _ in $(seq 1 30); do
    if curl --fail --silent "http://127.0.0.1:$host_port$path" >/dev/null; then
      return
    fi
    sleep 1
  done

  docker logs "$container"
  return 1
}

wait_for_health() {
  local container=$1
  local status

  for _ in $(seq 1 30); do
    status=$(docker inspect --format '{{.State.Health.Status}}' "$container")
    if [[ "$status" == "healthy" ]]; then
      return
    fi
    if [[ "$status" == "unhealthy" ]]; then
      docker logs "$container"
      return 1
    fi
    sleep 1
  done

  docker logs "$container"
  return 1
}

if [[ $# -gt 0 ]]; then
  targets=("$1")
else
  targets=(api ui rule-runner)
fi

for target in "${targets[@]}"; do
  docker build --target "$target" --tag "khalifa-$target:smoke" .
  test "$(docker image inspect --format '{{.Config.User}}' "khalifa-$target:smoke")" = "65532"
done

if [[ " ${targets[*]} " == *" api "* ]]; then
  docker run --detach --name "$api_container" --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true --health-interval 1s --health-start-period 1s --publish 127.0.0.1::8080 khalifa-api:smoke >/dev/null
  wait_for_http "$api_container" 8080 /livez
  wait_for_health "$api_container"
  api_port=$(get_host_port "$api_container" 8080)
  test "$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:$api_port/readyz")" = "503"
  docker stop --time 10 "$api_container" >/dev/null
  test "$(docker inspect --format '{{.State.ExitCode}}' "$api_container")" = "0"
fi

if [[ " ${targets[*]} " == *" ui "* ]]; then
  docker run --detach --name "$ui_container" --read-only --tmpfs /tmp --tmpfs /app/ui/.next/cache:uid=65532,gid=65532 --cap-drop ALL --security-opt no-new-privileges:true --health-interval 1s --health-start-period 1s --publish 127.0.0.1::3000 khalifa-ui:smoke >/dev/null
  wait_for_http "$ui_container" 3000 /healthz
  wait_for_health "$ui_container"
  docker stop --time 10 "$ui_container" >/dev/null
  [[ "$(docker inspect --format '{{.State.ExitCode}}' "$ui_container")" =~ ^(0|143)$ ]]
fi

if [[ " ${targets[*]} " == *" rule-runner "* ]]; then
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true khalifa-rule-runner:smoke --help >/dev/null
  if docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true khalifa-rule-runner:smoke >/dev/null 2>&1; then
    echo "Rule runner succeeded without NEPTUNE_ENDPOINT" >&2
    exit 1
  fi
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -e NEPTUNE_ENDPOINT=cluster.us-east-1.neptune.amazonaws.com khalifa-rule-runner:smoke risk --check >/dev/null
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -e NEPTUNE_ENDPOINT=cluster.us-east-1.neptune.amazonaws.com -e COMPLIANCE_EVIDENCE_TABLE=ComplianceEvidence -e COMPLIANCE_REPORTS_TABLE=ComplianceReports khalifa-rule-runner:smoke compliance --check >/dev/null
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -e AWS_REGION=us-east-1 -e COLLECTION_ACCOUNT_IDS=111122223333 -e COLLECTION_REGIONS=us-east-1 -e HOME_ACCOUNT_ID=111122223333 -e COLLECTOR_EXTERNAL_ID=container-smoke-external-id -e GRAPH_WRITER_URL=http://graph-writer:8080 -e GRAPH_WRITER_TOKEN=container-smoke-token khalifa-rule-runner:smoke organization-collector --check >/dev/null
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -e AWS_REGION=us-east-1 -e ATHENA_DATABASE=cloudtrail_database -e ATHENA_WORKGROUP=cloudtrail_workgroup -e ATHENA_RESULTS_S3_LOCATION="$(printf 's3:%s' '//example.invalid/athena-results')" -e ACCESS_ANALYZER_TABLE=AccessAnalyzerCache khalifa-rule-runner:smoke cloudtrail-analyzer --check >/dev/null
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -e AWS_REGION=us-east-1 -e GRAPH_WRITER_URL=http://graph-writer:8080 -e GRAPH_WRITER_TOKEN=container-smoke-token khalifa-rule-runner:smoke dspm-scanner --check >/dev/null
  docker run --rm --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -e AWS_REGION=us-east-1 -e COLLECTION_ACCOUNT_IDS=111122223333 -e COLLECTION_REGIONS=us-east-1 -e HOME_ACCOUNT_ID=111122223333 -e COLLECTOR_EXTERNAL_ID=container-smoke-external-id -e GRAPH_WRITER_URL=http://graph-writer:8080 -e GRAPH_WRITER_TOKEN=container-smoke-token -e SQS_QUEUE_URL=https://sqs.us-west-2.amazonaws.com/111122223333/incremental.fifo khalifa-rule-runner:smoke incremental-collector --check >/dev/null
  docker run --detach --name "$runtime_container" --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true -e AWS_REGION=us-east-1 -e NEPTUNE_ENDPOINT=cluster.us-east-1.neptune.amazonaws.com -e GRAPH_WRITER_PORT=8080 -e GRAPH_WRITER_TOKEN=container-smoke-token --publish 127.0.0.1::8080 khalifa-rule-runner:smoke graph-writer >/dev/null
  wait_for_http "$runtime_container" 8080 /readyz
  docker stop --time 10 "$runtime_container" >/dev/null
  test "$(docker inspect --format '{{.State.ExitCode}}' "$runtime_container")" = "0"
fi

echo "Validated container targets: ${targets[*]}"
