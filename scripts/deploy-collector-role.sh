#!/usr/bin/env bash
# Update the SecurityGraphCollectorRole stack in member accounts from
# templates/SecurityGraphCollectorRole.yaml and verify the attached policy.
#
# Each profile must already have the stack (ExternalId and trusted principals are
# reused from it). Profiles without a cached SSO token get a browser login.
#
# Usage: scripts/deploy-collector-role.sh [--region REGION] [--stack-name NAME] [--verify-only] PROFILE...
# REGION defaults to AWS_REGION (or us-east-1 when unset).
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEMPLATE="$ROOT/templates/SecurityGraphCollectorRole.yaml"
STACK_NAME=SecurityGraphCollectorRole
ROLE_NAME=SecurityGraphCollectorRole
REGION=${AWS_REGION:-us-east-1}
VERIFY_ONLY=false

usage() {
  sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 64
}

while [ $# -gt 0 ]; do
  case $1 in
    --region) REGION=$2; shift 2 ;;
    --stack-name) STACK_NAME=$2; shift 2 ;;
    --verify-only) VERIFY_ONLY=true; shift ;;
    -h | --help) usage ;;
    --*) echo "Unknown option: $1" >&2; usage ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || usage

expected_actions() {
  LC_ALL=C sed -nE 's/^[[:space:]]+- ([a-z0-9-]+:[A-Za-z*]+)[[:space:]]*$/\1/p' "$TEMPLATE" | LC_ALL=C sort -u
}

# Prints the account ID; opens the SSO login only when the cached token is unusable.
ensure_session() {
  local profile=$1
  if ! aws sts get-caller-identity --profile "$profile" --query Account --output text 2>/dev/null; then
    aws sso login --profile "$profile" >&2
    aws sts get-caller-identity --profile "$profile" --query Account --output text
  fi
}

deploy() {
  local profile=$1
  aws cloudformation describe-stacks --profile "$profile" --region "$REGION" \
    --stack-name "$STACK_NAME" --query 'Stacks[0].StackStatus' --output text >&2
  aws cloudformation deploy --profile "$profile" --region "$REGION" \
    --stack-name "$STACK_NAME" --template-file "$TEMPLATE" \
    --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset >&2
}

# Prints "OK <policy name>" or the action-level difference from the template.
verify() {
  local profile=$1 policy_arn version actions
  policy_arn=$(aws iam list-attached-role-policies --profile "$profile" --role-name "$ROLE_NAME" \
    --query "AttachedPolicies[?contains(PolicyName, 'CollectionPolicy')].PolicyArn | [0]" --output text)
  if [ -z "$policy_arn" ] || [ "$policy_arn" = None ]; then
    echo "no CollectionPolicy attached to $ROLE_NAME"
    return 1
  fi
  version=$(aws iam get-policy --profile "$profile" --policy-arn "$policy_arn" \
    --query Policy.DefaultVersionId --output text)
  actions=$(aws iam get-policy-version --profile "$profile" --policy-arn "$policy_arn" \
    --version-id "$version" --query 'PolicyVersion.Document.Statement[].Action[]' --output text |
    tr '\t' '\n' | LC_ALL=C sort -u)
  if diff <(expected_actions) <(printf '%s\n' "$actions") >/dev/null; then
    echo "OK ${policy_arn##*/}"
  else
    echo "DIFFERS ${policy_arn##*/}: missing [$(LC_ALL=C comm -23 <(expected_actions) <(printf '%s\n' "$actions") | paste -sd, -)] extra [$(LC_ALL=C comm -13 <(expected_actions) <(printf '%s\n' "$actions") | paste -sd, -)]"
    return 1
  fi
}

failures=0
summary=()
for profile in "$@"; do
  echo "== $profile" >&2
  if ! account=$(ensure_session "$profile"); then
    summary+=("$profile	-	LOGIN FAILED")
    failures=$((failures + 1))
    continue
  fi
  if [ "$VERIFY_ONLY" = false ] && ! deploy "$profile"; then
    summary+=("$profile	$account	DEPLOY FAILED")
    failures=$((failures + 1))
    continue
  fi
  if result=$(verify "$profile"); then
    summary+=("$profile	$account	$result")
  else
    summary+=("$profile	$account	$result")
    failures=$((failures + 1))
  fi
done

printf '\n%s\n' "PROFILE	ACCOUNT	RESULT"
printf '%s\n' "${summary[@]}"
[ "$failures" -eq 0 ]
