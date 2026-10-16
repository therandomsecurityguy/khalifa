#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
artifact_dir="$repo_root/artifacts/lambdas"
temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT

mkdir -p "$artifact_dir"

bundles=(
  "cloudtrail-analyzer:lambdas/cloudtrail-analyzer/dist"
  "collector:lambdas/collector/dist"
  "dspm-scanner:lambdas/dspm-scanner/dist"
  "graph-writer:lambdas/graph-writer/dist"
  "incremental-collector:lambdas/incremental-collector/dist"
  "least-privilege-sweep:lambdas/least-privilege-sweep/dist"
  "list-accounts:lambdas/list-accounts/dist"
  "policy-evaluator:lambdas/policy-evaluator/dist"
  "risk-engine:packages/risk-engine/dist/lambda"
)

for bundle in "${bundles[@]}"; do
  name=${bundle%%:*}
  relative_dir=${bundle#*:}
  bundle_dir="$repo_root/$relative_dir"

  if [[ ! -f "$bundle_dir/index.js" ]]; then
    echo "Missing Lambda handler bundle: $bundle_dir/index.js" >&2
    exit 1
  fi

  files=(index.js)
  if [[ -f "$bundle_dir/index.js.map" ]]; then
    files+=(index.js.map)
  fi

  stage_dir="$temp_dir/$name"
  mkdir -p "$stage_dir"
  for file in "${files[@]}"; do
    cp "$bundle_dir/$file" "$stage_dir/$file"
  done
  TZ=UTC touch -t 198001010000 "$stage_dir"/*
  (cd "$stage_dir" && TZ=UTC zip -q -X "$temp_dir/$name.zip" "${files[@]}")
  mv -f "$temp_dir/$name.zip" "$artifact_dir/$name.zip"
done

(cd "$artifact_dir" && shasum -a 256 ./*.zip > SHA256SUMS)
