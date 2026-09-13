#!/usr/bin/env bash
set -euo pipefail

: "${STACK_NAME:?STACK_NAME is required}"
: "${CHANGE_SET_NAME:?CHANGE_SET_NAME is required}"
: "${RELEASE_SHA:?RELEASE_SHA is required}"
: "${ARTIFACTS_BUCKET:?ARTIFACTS_BUCKET is required}"
: "${PARAMETER_FILE:?PARAMETER_FILE is required}"
: "${EXPECTED_PARAMETER_FILE:?EXPECTED_PARAMETER_FILE is required}"
: "${REQUIRED_PARAMETER_FILE:?REQUIRED_PARAMETER_FILE is required}"
: "${AWS_REGION:?AWS_REGION is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"

if [[ ! "$RELEASE_SHA" =~ ^[a-f0-9]{40}$ ]]; then
  echo "release_sha_invalid"
  exit 1
fi
test -f "$PARAMETER_FILE"
test -f "$EXPECTED_PARAMETER_FILE"
test -f "$REQUIRED_PARAMETER_FILE"
test -f .aws-sam/build/template.yaml
reviewer_path="${REVIEWER_PATH:-.aws-sam/build/release-tools/review_test_change_set.py}"
test -f "$reviewer_path"

packaged="$RUNNER_TEMP/packaged-template.yaml"
description="$RUNNER_TEMP/reviewed-change-set.json"
lookup_error="$RUNNER_TEMP/stack-lookup.err"
prefix_root="${ARTIFACT_PREFIX_ROOT:-test-releases}"
if [[ ! "$prefix_root" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$ || "$prefix_root" == *".."* ]]; then
  echo "artifact_prefix_root_invalid"
  exit 1
fi
prefix="$prefix_root/${RELEASE_SHA}/${GITHUB_RUN_ID}/${GITHUB_RUN_ATTEMPT}"

sam package \
  --template-file .aws-sam/build/template.yaml \
  --s3-bucket "$ARTIFACTS_BUCKET" \
  --s3-prefix "$prefix/artifacts" \
  --output-template-file "$packaged" \
  --region "$AWS_REGION"

template_key="$prefix/packaged-template.yaml"
aws s3 cp "$packaged" "s3://$ARTIFACTS_BUCKET/$template_key" \
  --sse AES256 \
  --only-show-errors
template_url="https://s3.$AWS_REGION.amazonaws.com/$ARTIFACTS_BUCKET/$template_key"

set +e
aws cloudformation describe-stacks \
  --stack-name "$STACK_NAME" \
  --query 'Stacks[0].StackId' \
  --output text \
  --no-cli-pager > /dev/null 2> "$lookup_error"
lookup_status=$?
set -e
if [[ "$lookup_status" -eq 0 ]]; then
  change_set_type="UPDATE"
elif grep -Fq "does not exist" "$lookup_error"; then
  change_set_type="CREATE"
else
  echo "stack_lookup_failed"
  exit 1
fi

create_args=(
  cloudformation create-change-set
  --stack-name "$STACK_NAME"
  --change-set-name "$CHANGE_SET_NAME"
  --change-set-type "$change_set_type"
  --client-token "github-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${RELEASE_SHA}"
  --description "GitHub ${GITHUB_REPOSITORY}@${RELEASE_SHA}"
  --template-url "$template_url"
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM
  --parameters "file://$PARAMETER_FILE"
  --query Id
  --output text
  --no-cli-pager
)
if [[ "$change_set_type" == "CREATE" ]]; then
  create_args+=(--on-stack-failure DO_NOTHING)
fi
change_set_arn="$(aws "${create_args[@]}")"

set +e
aws cloudformation wait change-set-create-complete \
  --stack-name "$STACK_NAME" \
  --change-set-name "$change_set_arn"
wait_status=$?
set -e
aws cloudformation describe-change-set \
  --stack-name "$STACK_NAME" \
  --change-set-name "$change_set_arn" \
  --include-property-values \
  --output json \
  --no-cli-pager > "$description"

review_args=(
  python3 "$reviewer_path"
  "$description"
  --expected-stack-name "$STACK_NAME"
  --expected-change-set-name "$CHANGE_SET_NAME"
  --expected-change-set-arn "$change_set_arn"
  --expected-change-set-type "$change_set_type"
)
while IFS= read -r item; do
  [[ -z "$item" ]] || review_args+=(--expected-parameter "$item")
done < "$EXPECTED_PARAMETER_FILE"
while IFS= read -r item; do
  [[ -z "$item" ]] || review_args+=(--required-parameter "$item")
done < "$REQUIRED_PARAMETER_FILE"

decision="$("${review_args[@]}")"
if [[ "$decision" == "noop" ]]; then
  aws cloudformation delete-change-set \
    --stack-name "$STACK_NAME" \
    --change-set-name "$change_set_arn" \
    --no-cli-pager
  echo "change_set_noop"
  exit 0
fi
test "$decision" = "execute"
test "$wait_status" -eq 0
aws cloudformation execute-change-set \
  --stack-name "$STACK_NAME" \
  --change-set-name "$change_set_arn" \
  --client-request-token "execute-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${RELEASE_SHA}" \
  --no-cli-pager
if [[ "$change_set_type" == "CREATE" ]]; then
  aws cloudformation wait stack-create-complete --stack-name "$STACK_NAME"
else
  aws cloudformation wait stack-update-complete --stack-name "$STACK_NAME"
fi
