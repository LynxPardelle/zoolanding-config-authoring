#!/usr/bin/env bash
set -euo pipefail

: "${STACK_NAME:?STACK_NAME is required}"

status="$(aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].StackStatus' \
  --output text \
  --no-cli-pager)"
case "$status" in
  CREATE_COMPLETE|UPDATE_COMPLETE) ;;
  *)
    echo "stack_status_invalid"
    exit 1
    ;;
esac

mapfile -t functions < <(aws cloudformation list-stack-resources \
  --stack-name "$STACK_NAME" \
  --query "StackResourceSummaries[?ResourceType=='AWS::Lambda::Function'].PhysicalResourceId" \
  --output text \
  --no-cli-pager | tr '\t' '\n' | sed '/^$/d')
if [[ "${#functions[@]}" -eq 0 ]]; then
  echo "stack_lambda_inventory_empty"
  exit 1
fi
for function_name in "${functions[@]}"; do
  read -r state update_status < <(aws lambda get-function-configuration \
    --function-name "$function_name" \
    --query '[State,LastUpdateStatus]' \
    --output text \
    --no-cli-pager)
  if [[ "$state" != "Active" || "$update_status" != "Successful" ]]; then
    echo "lambda_runtime_not_ready"
    exit 1
  fi
done
echo "post_deploy_smoke_ok"

